"""边界条件回归测试：python -m unittest discover -s tests -v。"""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import wsp
from wsa import http
from wsa.alerting import Alerter
from wsa.analysis import AnalysisOptions, Analyzer
from wsa.filescan import FileScanner
from wsa.logs import FileTailer, WebLogMonitor
from wsa.models import Alert, Severity
from wsa.winmon import IisLogMonitor


def alert(flow="client"):
    return Alert(1, Severity.HIGH, "test", "test", "TEST-1", 70, flow, "test")


class TailerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "access.log"
        self.path.write_bytes(b"")
        self.tailer = FileTailer(str(self.path), from_beginning=True)

    def append(self, data):
        with self.path.open("ab") as fh:
            fh.write(data)

    def test_partial_line_waits_for_newline(self):
        self.append(b"first")
        self.assertEqual(self.tailer.read_lines()[0], [])
        self.append(b" second\n")
        self.assertEqual(self.tailer.read_lines()[0], ["first second"])
        self.assertEqual(self.tailer.read_lines()[0], [])

    def test_utf8_split_between_polls(self):
        data = "中文\r\n".encode()
        self.append(data[:2])
        self.assertEqual(self.tailer.read_lines()[0], [])
        self.append(data[2:])
        self.assertEqual(self.tailer.read_lines()[0], ["中文"])

    def test_offline_final_line_without_newline(self):
        self.append(b"last")
        self.assertEqual(self.tailer.read_lines(flush_partial=True)[0], ["last"])
        self.assertEqual(self.tailer.read_lines(flush_partial=True)[0], [])

    def test_truncate_discards_old_partial(self):
        self.append(b"old partial")
        self.tailer.read_lines()
        self.path.write_bytes(b"new\n")
        self.assertEqual(self.tailer.read_lines()[0], ["new"])

    def test_rotation_discards_old_partial(self):
        self.append(b"old partial")
        self.tailer.read_lines()
        self.path.rename(self.path.with_suffix(".old"))
        self.path.write_bytes(b"new\n")
        self.assertEqual(self.tailer.read_lines()[0], ["new"])

    def test_long_line_has_bounded_pending_and_recovers(self):
        self.tailer.max_line_bytes = 8
        self.append(b"a" * 100000)
        lines, notes = self.tailer.read_lines()
        self.assertEqual(lines, [])
        self.assertEqual(len(self.tailer._pending), 8)
        self.assertTrue(notes)
        self.append(b"\nok\n")
        self.assertEqual(self.tailer.read_lines()[0], ["a" * 8, "ok"])

    def test_default_skips_existing_history(self):
        self.append(b"old\n")
        tailer = FileTailer(str(self.path))
        self.assertEqual(tailer.read_lines()[0], [])
        self.append(b"new\n")
        self.assertEqual(tailer.read_lines()[0], ["new"])


class HttpTests(unittest.TestCase):
    def request(self, body):
        return b"POST /a HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n" + body

    def test_chunked_pipeline_keeps_next_request(self):
        first = self.request(b"3\r\nabc\r\n0\r\n\r\n")
        next_req = b"GET /next HTTP/1.1\r\nHost: x\r\n\r\n"
        req, used = http.parse_request(first + next_req)
        self.assertEqual(req.body, b"abc")
        self.assertEqual(used, len(first))
        self.assertEqual(http.parse_request((first + next_req)[used:])[0].target, "/next")

    def test_chunked_pipeline_keeps_next_response(self):
        first = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
        second = b"HTTP/1.1 204 No Content\r\n\r\n"
        resp, used = http.parse_response(first + second)
        self.assertTrue(resp.body_complete)
        self.assertEqual(used, len(first))
        self.assertEqual(http.parse_response(second)[0].status, 204)

    def test_chunked_waits_for_final_empty_line(self):
        self.assertEqual(http.parse_request(self.request(b"0\r\n")), (None, 0))

    def test_chunk_extensions_and_trailers(self):
        first = self.request(b"3;ext=yes\r\nabc\r\n0\r\nX-End: yes\r\n\r\n")
        req, used = http.parse_request(first + b"GET / HTTP/1.1\r\n\r\n")
        self.assertEqual(req.body, b"abc")
        self.assertEqual(used, len(first))

    def test_chunked_body_limit_keeps_next_request(self):
        first = self.request(b"8\r\n12345678\r\n0\r\n\r\n")
        with patch.object(http, "MAX_BODY", 4):
            req, used = http.parse_request(first + b"GET / HTTP/1.1\r\n\r\n")
        self.assertEqual(req.body, b"1234")
        self.assertEqual(used, len(first))

    def test_negative_and_missing_chunk_delimiter_rejected(self):
        for body in (b"-1\r\na\r\n0\r\n\r\n", b"1\r\na0\r\n\r\n"):
            with self.subTest(body=body):
                self.assertEqual(http.parse_request(self.request(body)), (None, 0))

    def test_response_negative_length_does_not_consume_next_message(self):
        first = b"HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n"
        resp, used = http.parse_response(first + b"HTTP/1.1 204 OK\r\n\r\n")
        self.assertEqual(used, len(first))
        self.assertEqual(resp.body, b"")
        self.assertFalse(resp.body_complete)

    def test_body_collection_limit_preserves_message_boundary(self):
        with patch.object(http, "MAX_BODY", 4):
            for parser, head in ((http.parse_request, b"POST / HTTP/1.1"),
                                 (http.parse_response, b"HTTP/1.1 200 OK")):
                message = head + b"\r\nContent-Length: 8\r\n\r\n12345678"
                result, used = parser(message + b"next")
                self.assertEqual(result.body, b"1234")
                self.assertEqual(used, len(message))

    def test_complete_oversized_headers_rejected(self):
        with patch.object(http, "MAX_HEAD", 32):
            for parser, head in ((http.parse_request, b"GET / HTTP/1.1"),
                                 (http.parse_response, b"HTTP/1.1 200 OK")):
                message = head + b"\r\nX: " + b"a" * 64 + b"\r\n\r\n"
                self.assertEqual(parser(message), (None, len(message)))

    def test_multipart_preserves_boundary_case_and_value_suffix(self):
        body = (b'--AaB03x\r\nContent-Disposition: form-data; name="data"\r\n\r\n'
                b'value--\r\n\r\n--AaB03x--\r\n')
        params = http.parse_params("POST", "/", {"content-type":
            'multipart/form-data; boundary="AaB03x"'}, body)
        self.assertEqual(params, {"data": "value--\r\n"})


class AlertTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_daily_files_roll_over_while_running(self):
        with patch("wsa.alerting.time.strftime", return_value="20261014"):
            alerter = Alerter(self.tmp.name, syslog=False, dedupe_seconds=0)
            alerter.emit(alert())
        with patch("wsa.alerting.time.strftime", return_value="20261015"):
            alerter.emit(alert())
            alerter.log("INFO", "new day")
        for day in ("20261014", "20261015"):
            self.assertEqual(len((Path(self.tmp.name) / f"alerts-{day}.jsonl").read_text(encoding="utf-8").splitlines()), 1)
        self.assertTrue((Path(self.tmp.name) / "watch-20261015.log").exists())

    def test_history_limit_keeps_lifetime_counts_and_disk_records(self):
        alerter = Alerter(self.tmp.name, syslog=False, dedupe_seconds=0, max_history=2)
        for i in range(5):
            alerter.emit(alert(str(i)))
        self.assertEqual([a.flow for a in alerter.alerts], ["3", "4"])
        self.assertEqual(alerter.counts[Severity.HIGH], 5)
        self.assertIn("告警总数 5", alerter.summary())
        with open(alerter.jsonl_path, encoding="utf-8") as fh:
            self.assertEqual(len(fh.readlines()), 5)

    def test_dedupe_expiry_and_cleanup_at_exact_boundary(self):
        alerter = Alerter(self.tmp.name, syslog=False, save_jsonl=False, dedupe_seconds=10)
        with patch("wsa.alerting.time.monotonic", side_effect=[0, 1, 10, 11]):
            alerter.emit(alert("a"))
            alerter.emit(alert("b"))
            alerter.emit(alert("a"))
            alerter.emit(alert("b"))
        self.assertEqual(len(alerter.alerts), 4)
        self.assertEqual(len(alerter._seen), 2)

    def test_duplicates_still_suppressed(self):
        alerter = Alerter(self.tmp.name, syslog=False, save_jsonl=False, dedupe_seconds=10)
        with patch("wsa.alerting.time.monotonic", side_effect=[10, 11]):
            alerter.emit(alert())
            alerter.emit(alert())
        self.assertEqual(alerter.suppressed, 1)
        self.assertEqual(len(alerter.alerts), 1)


class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "web"
        self.root.mkdir()
        self.analyzer = Analyzer(options=AnalysisOptions(try_decrypt=False))
        self.alerter = Alerter(str(Path(self.tmp.name) / "logs"), syslog=False, dedupe_seconds=0)
        self.scanner = FileScanner(self.alerter.emit, self.alerter.log, self.analyzer.rules,
            [str(self.root)], [".php"], str(Path(self.tmp.name) / "state"))

    def test_file_hash_present_in_persisted_alert(self):
        code = b'<?php eval($_POST["x"]); ?>'
        (self.root / "bad.php").write_bytes(code)
        self.scanner.scan()
        with open(self.alerter.jsonl_path, encoding="utf-8") as fh:
            records = [json.loads(line) for line in fh]
        record = next(a for a in records if a["rule_id"] == "DEF-031")
        self.assertIn(hashlib.sha256(code).hexdigest(), record["response"])

    def test_new_script_content_scanned_once(self):
        self.scanner.update_baseline()
        (self.root / "bad.php").write_text('<?php eval($_POST["x"]); ?>')
        with patch.object(self.scanner, "scan_content", wraps=self.scanner.scan_content) as scan:
            self.scanner.scan()
        self.assertEqual(scan.call_count, 1)

    def test_failed_baseline_save_does_not_mark_success(self):
        (self.root / "index.php").write_text("<?php echo 1; ?>")
        with patch("wsa.filescan.os.replace", side_effect=OSError("disk full")):
            result = self.scanner.update_baseline()
        self.assertFalse(result.baseline_created)
        self.assertTrue(self.scanner.baseline_missing)
        self.assertEqual(self.scanner.baseline, {})

    def test_failed_first_scan_save_is_retried_next_scan(self):
        with patch("wsa.filescan.os.replace", side_effect=OSError("disk full")):
            result = self.scanner.scan()
        self.assertFalse(result.baseline_created)
        self.assertTrue(self.scanner.baseline_missing)
        self.assertTrue(self.scanner.scan().baseline_created)

    def test_alert_uses_old_baseline_when_updating(self):
        path = self.root / "index.php"
        path.write_text("old")
        self.scanner.update_baseline()
        path.write_text("changed")
        self.scanner.scan(update_baseline=True)
        record = next(a for a in self.alerter.alerts if a.rule_id == "DEF-034")
        self.assertIn("3 -> 7", record.evidence)


class IisTests(unittest.TestCase):
    HEADER = "#Fields: date time c-ip cs-method cs-uri-stem sc-status cs(User-Agent)\n"
    ROW = "2026-10-14 12:00:00 192.0.2.1 GET /index.aspx 200 Mozilla/5.0\n"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "u_ex261014.log"
        self.path.write_text(self.HEADER + self.ROW, encoding="utf-8")
        self.monitor = IisLogMonitor(lambda a: None, lambda *args: None,
            Analyzer(options=AnalysisOptions(try_decrypt=False)),
            [{"path": self.tmp.name}])

    def test_live_start_loads_header_and_only_analyzes_new_rows(self):
        self.monitor.poll_once()
        self.assertEqual(self.monitor.entries_total, 0)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(self.ROW)
        self.monitor.poll_once()
        self.assertEqual(self.monitor.entries_total, 1)
        self.assertEqual(self.monitor.parse_fail, 0)

    def test_new_daily_file_is_read_from_beginning(self):
        self.monitor.poll_once()
        (Path(self.tmp.name) / "u_ex261015.log").write_text(self.HEADER + self.ROW, encoding="utf-8")
        self.monitor.poll_once()
        self.assertEqual(self.monitor.entries_total, 1)

    def test_rotation_refreshes_changed_field_order(self):
        self.monitor.poll_once()
        self.path.rename(self.path.with_suffix(".old"))
        self.path.write_text("#Fields: date time cs-method c-ip cs-uri-stem sc-status\n"
                             "2026-10-14 12:01:00 GET 192.0.2.1 /home.aspx 200\n")
        self.monitor.poll_once()
        self.assertEqual(self.monitor.entries_total, 1)
        self.assertEqual(self.monitor.parse_fail, 0)


class CliTests(unittest.TestCase):
    def test_explicit_config_forms_override_platform_default(self):
        with patch.object(wsp, "DEFAULT_CONFIG_PATH", "default.json"):
            for args in (["--config=custom.json", "rules"], ["-ccustom.json", "rules"],
                         ["-c", "custom.json", "rules"], ["--config", "custom.json", "rules"]):
                self.assertEqual(wsp._prepare_argv(args), args)

    def test_platform_default_is_injected_when_missing(self):
        with patch.object(wsp, "DEFAULT_CONFIG_PATH", "default.json"):
            self.assertEqual(wsp._prepare_argv(["rules"]), ["--config", "default.json", "rules"])

    def test_offline_monitor_handles_unterminated_final_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "access.log"
            path.write_text('192.0.2.1 - - [14/Oct/2026:12:00:00 +0800] '
                            '"GET / HTTP/1.1" 200 1 "-" "Mozilla/5.0"')
            monitor = WebLogMonitor(lambda a: None, lambda *args: None,
                Analyzer(options=AnalysisOptions(try_decrypt=False)),
                [{"path": str(path)}], from_beginning=True, final_lines=True)
            self.assertEqual(monitor.poll_once(), 1)
            self.assertEqual(monitor.entries_total, 1)
            self.assertEqual(monitor.poll_once(), 0)


class ReviewFixTests(unittest.TestCase):
    def test_scanner_skips_fifo_and_symlink(self):
        import os
        if not hasattr(os, "mkfifo"):
            self.skipTest("no fifo")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "web"; root.mkdir()
            outside = Path(tmp) / "secret.php"; outside.write_text('<?php eval($_POST["x"]); ?>')
            os.mkfifo(root / "pipe.php")
            os.symlink(outside, root / "link.php")
            alerter = Alerter(str(Path(tmp) / "logs"), syslog=False, dedupe_seconds=0)
            sc = FileScanner(alerter.emit, alerter.log, Analyzer(options=AnalysisOptions(try_decrypt=False)).rules,
                             [str(root)], [".php"], str(Path(tmp) / "state"))
            sc.scan()  # 不应阻塞在 FIFO 上
            self.assertEqual(sc.scan_content(str(root / "pipe.php")), [])
            self.assertEqual(sc.scan_content(str(root / "link.php")), [])

    def test_pcapng_power_of_two_tsresol(self):
        from wsa.pcap import PcapReader
        self.assertAlmostEqual(PcapReader._ng_ts(0, 1 << 20, -20), 1.0)

    def test_eventlog_name_injection_rejected(self):
        from wsa.winmon import EventLogMonitor
        with tempfile.TemporaryDirectory() as tmp:
            m = EventLogMonitor(lambda a: None, lambda l, m: None, [], log_name="Security; calc", state_dir=tmp)
            ok, reason = m.check_available()
            self.assertFalse(ok)
            self.assertIn("非法", reason)


if __name__ == "__main__":
    unittest.main()
