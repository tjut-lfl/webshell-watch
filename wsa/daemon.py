"""
守护进程：把各监控器编排起来，是 `webshell-watch start` 的实际执行体。

监控器与调度周期：
    Web 访问日志   2 秒      主力数据源（服务器侧明文可见）
    认证日志       5 秒      持久化与提权行为
    文件巡检       可配置     发现新增/修改的马文件（默认 300 秒）
    抓包(可选)     实时       仅明文 HTTP 与 TLS 指纹
    pcap 目录(可选) 10 秒     离线抓包文件自动分析

设计取舍：
    * 单进程多线程，事件驱动 + 轮询结合；日志用增量 tail，不做全量重读；
    * 所有监控器共享同一个检测引擎与告警出口，因此「工具特征」与「防守行为特征」
      会在同一套打分体系里叠加，避免两套规则互相看不见；
    * 任一监控器异常不会拖垮进程：捕获异常、记日志、下一轮继续。
"""

from __future__ import annotations

import os
import platform
import signal
import threading
import time
from dataclasses import dataclass
from typing import Dict, List

from .alerting import Alerter
from .analysis import Analyzer
from .authmon import AuthMonitor
from .config import WatchConfig
from .filescan import FileScanner
from .logs import WebLogMonitor
from .models import Alert
from .pcapdir import PcapDirMonitor
from .rules import build_rule_set


def cfg_host(cfg: WatchConfig) -> str:
    return cfg.hostname


def _platform_name() -> str:
    """人类可读的平台名，用于启动日志与自检输出。"""
    system = platform.system()
    if system == "Windows":
        release = platform.release() or ""
        return f"Windows {release}".strip()
    if system == "Linux":
        try:
            with open("/etc/os-release", "r", encoding="utf-8") as fh:
                for line in fh:
                    if line.startswith("PRETTY_NAME="):
                        return line.split("=", 1)[1].strip().strip('"')
        except OSError:
            pass
        return "Linux"
    return system or "未知平台"


@dataclass
class MonitorStat:
    name: str
    interval: float
    last_run: float = 0.0
    runs: int = 0
    errors: int = 0
    last_error: str = ""
    detail: str = ""


class WatchDaemon:
    """防守端守护进程。"""

    def __init__(self, cfg: WatchConfig):
        self.cfg = cfg
        self.alerter = Alerter(
            log_dir=cfg.log_dir,
            save_jsonl=bool(cfg.section("output").get("save_jsonl", True)),
            syslog=bool(cfg.section("output").get("syslog", True)),
            syslog_facility=str(cfg.section("output").get("syslog_facility", "local0")),
            console=bool(cfg.section("output").get("console", False)),
            color=bool(cfg.section("output").get("color", True)),
            verbose=bool(cfg.section("output").get("verbose", True)),
            hostname=cfg.hostname,
            dedupe_seconds=int(cfg.section("notify").get("dedupe_seconds", 300)),
            webhook=cfg.section("webhook"),
            state_dir=cfg.state_dir,
            max_history=int(cfg.section("output").get("max_history", 5000)),
        )
        rules, notes = build_rule_set(cfg.rule_dir)
        self.analyzer = Analyzer(
            rule_dir=cfg.rule_dir,
            options=cfg.analysis_options(),
            disabled_rules=cfg.disabled_rules(),
            enabled_tools=cfg.enabled_tools(),
        )
        for note in notes:
            self.alerter.log("INFO", note)

        self.monitors: Dict[str, object] = {}
        self.stats: Dict[str, MonitorStat] = {}
        self._stop = threading.Event()
        self._threads: List[threading.Thread] = []
        self.started_at = time.time()

    # ------------------------------------------------------------------
    def log(self, level: str, message: str) -> None:
        self.alerter.log(level, message)

    def emit(self, alert: Alert) -> None:
        self.alerter.emit(alert)

    # ------------------------------------------------------------------
    # 启动
    # ------------------------------------------------------------------
    def start(self) -> int:
        cfg = self.cfg
        self.log("INFO", "=" * 72)
        self.log("INFO", f"WebShell 防守监控启动（主机 {cfg.hostname}，规则 {len(self.analyzer.rules)} 条）")
        self.log("INFO", f"告警输出：{', '.join(f'{k}={v}' for k, v in self.alerter.paths.items())}")
        self._banner()

        # 1) Web 访问日志
        wl = cfg.section("weblog")
        if wl.get("enabled", True):
            mon = WebLogMonitor(
                alert_fn=self.emit,
                log_fn=self.log,
                analyzer=self.analyzer,
                sources=wl.get("sources") or [],
                max_line_bytes=int(wl.get("max_line_bytes", 262144)),
                from_beginning=bool(wl.get("from_beginning", False)),
            )
            self.monitors["weblog"] = mon
            self._add_thread("weblog", 2.0, mon.poll_once)

        # 2) 认证日志
        al = cfg.section("authlog")
        if al.get("enabled", True):
            mon = AuthMonitor(
                alert_fn=self.emit,
                log_fn=self.log,
                analyzer_rules=self.analyzer.rules,
                sources=al.get("sources") or [],
                from_beginning=bool(al.get("from_beginning", False)),
                fail_window=int(al.get("fail_window", 300)),
                fail_threshold=int(al.get("fail_threshold", 10)),
                trusted_ips=al.get("trusted_ips") or (),
            )
            self.monitors["authlog"] = mon
            self._add_thread("authlog", 5.0, mon.poll_once)

        # 3) 文件巡检
        fs = cfg.section("filescan")
        if fs.get("enabled", True):
            scanner = FileScanner(
                alert_fn=self.emit,
                log_fn=self.log,
                rules=self.analyzer.rules,
                webroots=fs.get("webroots") or [],
                script_extensions=fs.get("script_extensions") or [],
                state_dir=cfg.state_dir,
                exclude_dirs=fs.get("exclude_dirs") or [],
                max_file_bytes=int(fs.get("max_file_bytes", 2097152)),
                follow_symlinks=bool(fs.get("follow_symlinks", False)),
            )
            self.monitors["filescan"] = scanner
            self._add_thread("filescan", float(fs.get("interval", 300)), self._run_filescan, first_delay=1.0)

        # 4) 抓包（默认关闭）
        sn = cfg.section("sniff")
        if sn.get("enabled", False):
            from .packetmon import PacketMonitor

            mon = PacketMonitor(
                analyzer=self.analyzer,
                alert_fn=self.emit,
                log_fn=self.log,
                interface=str(sn.get("interface", "any")),
                idle_flush=float(sn.get("idle_flush", 20.0)),
                max_flows=int(sn.get("max_flows", 20000)),
            )
            ok, msg = mon.start()
            self.log("INFO" if ok else "ERROR", msg)
            if ok:
                self.monitors["sniff"] = mon
                self.stats["sniff"] = MonitorStat(name="抓包(明文HTTP)", interval=0.0)

        # 5) pcap 目录监视
        pc = cfg.section("pcap")
        if pc.get("enabled", False):
            mon = PcapDirMonitor(
                alert_fn=self.emit,
                log_fn=self.log,
                analyzer=self.analyzer,
                directory=str(pc.get("watch_dir", cfg.state_dir + "/pcap")),
                settle_seconds=float(pc.get("settle_seconds", 3)),
            )
            self.monitors["pcap"] = mon
            self._add_thread("pcap", float(pc.get("interval", 10)), mon.scan_once)

        # ------------------------------------------------------------------
        # Windows 专属监控（仅在 Windows 上启用；配置与 Linux 版共用一份）
        # ------------------------------------------------------------------
        self._start_windows_monitors(cfg)

        if not self.monitors:
            self.log("ERROR", "没有任何监控器被启用，请检查配置")
            return 1

        # 状态汇总线程
        self._add_thread(
            "status",
            float(cfg.section("runtime").get("status_interval", 60)),
            self._status_tick,
            record=False,
        )

        self._install_signals()
        self.log("INFO", f"已启动 {len([k for k in self.monitors])} 个监控器，进入监视状态")
        # 主线程等待退出信号
        try:
            while not self._stop.wait(1.0):
                pass
        except KeyboardInterrupt:
            self.log("INFO", "收到中断信号")
        return self.stop()

    def _banner(self) -> None:
        active = []
        if self.cfg.section("weblog").get("enabled", True):
            active.append("Web日志")
        if self.cfg.section("authlog").get("enabled", True):
            active.append("认证日志")
        if self.cfg.section("filescan").get("enabled", True):
            active.append("文件巡检")
        if self.cfg.section("sniff").get("enabled", False):
            active.append("抓包")
        if self.cfg.section("pcap").get("enabled", False):
            active.append("PCAP目录")
        if os.name == "nt":
            if self.cfg.section("iislog").get("enabled", True):
                active.append("IIS日志")
            if self.cfg.section("winevent").get("enabled", True):
                active.append("Windows事件日志")
            if self.cfg.section("windrop").get("enabled", True):
                active.append("Windows落地目录")
        self.log("INFO", f"运行平台：{_platform_name()}；启用的监控：{'、'.join(active) or '无'}")

    # ------------------------------------------------------------------
    # Windows 专属监控
    # ------------------------------------------------------------------
    def _start_windows_monitors(self, cfg: WatchConfig) -> None:
        if os.name != "nt":
            # 非 Windows 平台上，把 Windows 专属配置段静默跳过，
            # 配置里留着这些段落不会影响 Linux 运行。
            return
        from .winmon import EventLogMonitor, IisLogMonitor, WindowsDropScanner

        iis = cfg.section("iislog")
        if iis.get("enabled", True):
            mon = IisLogMonitor(
                alert_fn=self.emit,
                log_fn=self.log,
                analyzer=self.analyzer,
                sources=iis.get("sources") or [],
                from_beginning=bool(iis.get("from_beginning", False)),
                max_line_bytes=int(iis.get("max_line_bytes", 262144)),
            )
            self.monitors["iislog"] = mon
            self._add_thread("iislog", 3.0, mon.poll_once)

        we = cfg.section("winevent")
        if we.get("enabled", True):
            mon = EventLogMonitor(
                alert_fn=self.emit,
                log_fn=self.log,
                rules=self.analyzer.rules,
                log_name=str(we.get("log_name", "Security")),
                event_ids=we.get("event_ids") or (),
                max_events=int(we.get("max_events", 200)),
                state_dir=cfg.state_dir,
                fail_window=int(we.get("fail_window", 300)),
                fail_threshold=int(we.get("fail_threshold", 10)),
                trusted_ips=we.get("trusted_ips") or (),
                use_whoami_filter=bool(we.get("use_whoami_filter", True)),
            )
            ok, reason = mon.check_available()
            self.log("INFO" if ok else "WARN", f"Windows 事件日志监控：{'可用' if ok else reason}")
            self.monitors["winevent"] = mon
            if ok:
                self._add_thread("winevent", 10.0, mon.poll_once)
            else:
                self.stats["winevent"] = MonitorStat(name="Windows事件日志", interval=10.0)
                self.stats["winevent"].last_error = reason

        wd = cfg.section("windrop")
        if wd.get("enabled", True):
            mon = WindowsDropScanner(
                alert_fn=self.emit,
                log_fn=self.log,
                rules=self.analyzer.rules,
                directories=wd.get("directories") or (),
                lookback_days=float(wd.get("lookback_days", 7)),
                max_files=int(wd.get("max_files", 20000)),
                state_dir=cfg.state_dir,
            )
            self.monitors["windrop"] = mon
            self._add_thread("windrop", 600.0, mon.scan_once, first_delay=5.0)

    # ------------------------------------------------------------------
    def _add_thread(self, name: str, interval: float, fn, record: bool = True, first_delay: float = 0.0) -> None:
        if record:
            self.stats[name] = MonitorStat(name=name, interval=interval)
        th = threading.Thread(
            target=self._loop, args=(name, interval, fn, record, first_delay),
            name=f"mon-{name}", daemon=True,
        )
        th.start()
        self._threads.append(th)

    def _loop(self, name: str, interval: float, fn, record: bool, first_delay: float) -> None:
        if first_delay:
            time.sleep(first_delay)
        while not self._stop.is_set():
            t0 = time.time()
            try:
                fn()
                if record:
                    self.stats[name].runs += 1
                    self.stats[name].last_error = ""
            except Exception as exc:  # 单个监控器异常不应终止整个进程
                if record:
                    self.stats[name].errors += 1
                    self.stats[name].last_error = f"{type(exc).__name__}: {exc}"
                self.log("ERROR", f"监控器 {name} 执行出错：{type(exc).__name__}: {exc}")
            if record:
                self.stats[name].last_run = t0
            elapsed = time.time() - t0
            wait = max(0.2, interval - elapsed)
            if self._stop.wait(wait):
                return

    def _run_filescan(self) -> None:
        scanner: FileScanner = self.monitors["filescan"]  # type: ignore[assignment]
        result = scanner.scan()
        self.stats["filescan"].detail = result.summary()

    # ------------------------------------------------------------------
    def _status_tick(self) -> None:
        uptime = int(time.time() - self.started_at)
        parts = [f"运行 {uptime // 3600}h{(uptime % 3600) // 60}m"]
        for name, st in self.stats.items():
            if name == "status":
                continue
            if st.errors:
                parts.append(f"{st.name}:{st.runs}次/错误{st.errors}")
            else:
                parts.append(f"{st.name}:{st.runs}次")
        if "weblog" in self.monitors:
            mon: WebLogMonitor = self.monitors["weblog"]  # type: ignore[assignment]
            parts.append(f"日志{mon.entries_total}行/带体{mon.body_seen}行")
        if "filescan" in self.monitors:
            scanner: FileScanner = self.monitors["filescan"]  # type: ignore[assignment]
            parts.append(f"基线{'已建' if not scanner.baseline_missing else '未建'}")
        self.log("INFO", "状态：" + "；".join(parts) + f"；{self.alerter.summary()}")

    # ------------------------------------------------------------------
    def _install_signals(self) -> None:
        def handler(signum, _frame):
            self.log("INFO", f"收到信号 {signum}，准备退出")
            self._stop.set()

        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                signal.signal(sig, handler)
            except (ValueError, OSError):
                pass

    # ------------------------------------------------------------------
    # 单次运行（用于部署后验证、cron 巡检，或集成测试）
    # ------------------------------------------------------------------
    def run_once(self) -> int:
        """把所有监控器各跑一轮，打印汇总后退出。"""
        self.log("INFO", f"单次巡检模式（主机 {cfg_host(self.cfg)}，规则 {len(self.analyzer.rules)} 条）")
        results: List[str] = []

        wl = self.cfg.section("weblog")
        if wl.get("enabled", True):
            mon = WebLogMonitor(
                alert_fn=self.emit,
                log_fn=self.log,
                analyzer=self.analyzer,
                sources=wl.get("sources") or [],
                max_line_bytes=int(wl.get("max_line_bytes", 262144)),
                from_beginning=True,   # 单次巡检默认回扫整个文件，否则看不到已有内容
            )
            self.monitors["weblog"] = mon
            rounds = 0
            while mon.poll_once() > 0 and rounds < 200:
                rounds += 1
            results.append(mon.summary())

        al = self.cfg.section("authlog")
        if al.get("enabled", True):
            mon = AuthMonitor(
                alert_fn=self.emit,
                log_fn=self.log,
                analyzer_rules=self.analyzer.rules,
                sources=al.get("sources") or [],
                from_beginning=True,
                fail_window=int(al.get("fail_window", 300)),
                fail_threshold=int(al.get("fail_threshold", 10)),
                trusted_ips=al.get("trusted_ips") or (),
            )
            self.monitors["authlog"] = mon
            rounds = 0
            while mon.poll_once() > 0 and rounds < 200:
                rounds += 1
            results.append(mon.summary())

        fs = self.cfg.section("filescan")
        if fs.get("enabled", True):
            scanner = FileScanner(
                alert_fn=self.emit,
                log_fn=self.log,
                rules=self.analyzer.rules,
                webroots=fs.get("webroots") or [],
                script_extensions=fs.get("script_extensions") or [],
                state_dir=self.cfg.state_dir,
                exclude_dirs=fs.get("exclude_dirs") or [],
                max_file_bytes=int(fs.get("max_file_bytes", 2097152)),
                follow_symlinks=bool(fs.get("follow_symlinks", False)),
            )
            self.monitors["filescan"] = scanner
            results.append(scanner.scan().summary())

        pc = self.cfg.section("pcap")
        if pc.get("enabled", False):
            mon = PcapDirMonitor(
                alert_fn=self.emit,
                log_fn=self.log,
                analyzer=self.analyzer,
                directory=str(pc.get("watch_dir", self.cfg.state_dir + "/pcap")),
                settle_seconds=0.0,     # 单次模式不等待写入完成
            )
            self.monitors["pcap"] = mon
            mon.scan_once()
            results.append(mon.summary())

        # Windows 专属监控也跑一轮
        if os.name == "nt":
            from .winmon import EventLogMonitor, IisLogMonitor, WindowsDropScanner

            iis = self.cfg.section("iislog")
            if iis.get("enabled", True):
                mon = IisLogMonitor(
                    alert_fn=self.emit,
                    log_fn=self.log,
                    analyzer=self.analyzer,
                    sources=iis.get("sources") or [],
                    from_beginning=True,
                    max_line_bytes=int(iis.get("max_line_bytes", 262144)),
                )
                self.monitors["iislog"] = mon
                rounds = 0
                while mon.poll_once() > 0 and rounds < 200:
                    rounds += 1
                results.append(mon.summary())

            we = self.cfg.section("winevent")
            if we.get("enabled", True):
                mon = EventLogMonitor(
                    alert_fn=self.emit,
                    log_fn=self.log,
                    rules=self.analyzer.rules,
                    log_name=str(we.get("log_name", "Security")),
                    event_ids=we.get("event_ids") or (),
                    max_events=int(we.get("max_events", 200)),
                    state_dir=self.cfg.state_dir,
                    fail_window=int(we.get("fail_window", 300)),
                    fail_threshold=int(we.get("fail_threshold", 10)),
                    trusted_ips=we.get("trusted_ips") or (),
                    use_whoami_filter=bool(we.get("use_whoami_filter", True)),
                )
                self.monitors["winevent"] = mon
                ok, reason = mon.check_available()
                if ok:
                    mon.poll_once()
                else:
                    self.log("WARN", f"Windows 事件日志监控不可用：{reason}")
                results.append(mon.summary())

            wd = self.cfg.section("windrop")
            if wd.get("enabled", True):
                mon = WindowsDropScanner(
                    alert_fn=self.emit,
                    log_fn=self.log,
                    rules=self.analyzer.rules,
                    directories=wd.get("directories") or (),
                    lookback_days=float(wd.get("lookback_days", 7)),
                    max_files=int(wd.get("max_files", 20000)),
                    state_dir=self.cfg.state_dir,
                )
                self.monitors["windrop"] = mon
                mon.scan_once()
                results.append(mon.summary())

        if self.cfg.section("sniff").get("enabled", False):
            self.log("INFO", "单次巡检模式不启用抓包（抓包需要持续运行）")

        self.log("INFO", "单次巡检完成")
        for line in results:
            self.log("INFO", line)
        self.log("INFO", self.alerter.summary())
        for name, path in self.alerter.paths.items():
            self.log("INFO", f"{name}: {path}")
        return 0

    def stop(self) -> int:
        self._stop.set()
        self.log("INFO", "正在停止监控器…")
        # 停止主动型监控器
        for key in ("sniff", "pcap"):
            mon = self.monitors.get(key)
            if mon is not None and hasattr(mon, "stop"):
                try:
                    mon.stop()
                except Exception:
                    pass
        for th in self._threads:
            th.join(timeout=3)
        self.log("INFO", "监控已停止")
        self.log("INFO", self.alerter.summary())
        for name, path in self.alerter.paths.items():
            self.log("INFO", f"{name}: {path}")
        return 0
