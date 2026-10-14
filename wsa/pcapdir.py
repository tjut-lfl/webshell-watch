"""
pcap 目录监视：把落在这个目录里的抓包文件自动分析掉。

适用场景：服务器上用 tcpdump/pktmon 做定点抓包取证，
把输出写到该目录（例如 /var/lib/webshell-watch/pcap），
本监控会自动分析新文件并按同一套规则告警，不需要人工触发。
"""

from __future__ import annotations

import os
import time
from typing import Callable, Dict, Tuple

from .capture import FlowTable
from .pcap import ParseStats, PcapReader, sniff_files

PCAP_SOURCE = "PCAP文件"
EXTENSIONS = (".pcap", ".pcapng", ".cap", ".dmp")


class PcapDirMonitor:
    def __init__(
        self,
        alert_fn: Callable[[Alert], None],
        log_fn: Callable[[str, str], None],
        analyzer,
        directory: str,
        settle_seconds: float = 3.0,
    ):
        self.alert_fn = alert_fn
        self.log = log_fn
        self.analyzer = analyzer
        self.directory = directory
        self.settle_seconds = settle_seconds
        self._seen: Dict[str, Tuple[float, int]] = {}
        self.files_done = 0
        self.alerts_emitted = 0
        os.makedirs(directory, exist_ok=True)

    def scan_once(self) -> int:
        files, _ = sniff_files([self.directory])
        now = time.time()
        processed = 0
        for path in files:
            try:
                st = os.stat(path)
            except OSError:
                continue
            key = (st.st_mtime, st.st_size)
            if self._seen.get(path) == key:
                continue
            if now - st.st_mtime < self.settle_seconds:
                continue      # 文件可能还在写入
            self._seen[path] = key
            self.analyze_file(path)
            processed += 1
        return processed

    def analyze_file(self, path: str) -> int:
        stats = ParseStats()
        table = FlowTable(source=PCAP_SOURCE)
        t0 = time.time()
        try:
            with PcapReader(path, stats) as reader:
                for pkt in reader.packets():
                    table.feed(pkt)
        except OSError as exc:
            self.log("ERROR", f"读取 {path} 失败：{exc}")
            return 0
        flows = table.finish()
        count = 0
        for flow in flows:
            found = self.analyzer.analyze_flow(flow)
            if found:
                for a in found:
                    a.source = PCAP_SOURCE
                    self.alert_fn(a)
                count += len(found)
        self.files_done += 1
        self.alerts_emitted += count
        self.log(
            "INFO",
            f"已分析抓包 {os.path.basename(path)}：帧 {stats.total_frames}，会话 {len(flows)}，"
            f"告警 {count}，用时 {time.time() - t0:.2f}s",
        )
        for p in stats.pitfalls:
            self.log("WARN", f"[{p.kind}] {p.message}")
        return count

    def summary(self) -> str:
        return f"PCAP 目录监视：已分析 {self.files_done} 个文件，告警 {self.alerts_emitted}"
