"""
防守端告警输出。

四个出口，可按需开启：
    * JSONL 文件：结构化，便于长期留存与 SIEM 采集
    * syslog    ：直接进系统日志，接入现有日志平台
    * webhook   ：钉钉/企业微信/Slack/通用 JSON POST
    * console   ：前台运行时的彩色输出

另外提供去重：同一条规则对同一个来源在窗口期内只报一次，
避免高频 webshell 通信把日志刷爆。
"""

from __future__ import annotations

import json
import os
import socket
import threading
import time
import urllib.error
import urllib.request
from collections import OrderedDict
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

from .models import Alert, Severity

RESET = "\033[0m"
SEV_COLOR = {
    Severity.INFO: "",
    Severity.LOW: "\033[36m",
    Severity.MEDIUM: "\033[33m",
    Severity.HIGH: "\033[31m",
    Severity.CRITICAL: "\033[1;41;37m",
}


@dataclass
class LogRecord:
    ts: float
    level: str
    message: str

    @property
    def time_str(self) -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.ts))


class Alerter:
    """告警分发中心。"""

    def __init__(
        self,
        log_dir: str = "/var/log/webshell-watch",
        save_jsonl: bool = True,
        syslog: bool = True,
        syslog_facility: str = "local0",
        console: bool = False,
        color: bool = True,
        verbose: bool = True,
        hostname: str = "",
        dedupe_seconds: int = 300,
        webhook: Optional[Dict] = None,
        state_dir: str = "/var/lib/webshell-watch",
        max_history: int = 0,
    ):
        self.log_dir = log_dir
        self.save_jsonl = save_jsonl
        self.use_syslog = syslog
        self.console = console
        self.color = color
        self.verbose = verbose
        self.hostname = hostname or self._hostname()
        self.dedupe_seconds = int(dedupe_seconds or 0)
        self.webhook = webhook or {}
        self.state_dir = state_dir
        self.max_history = max(0, int(max_history))
        self.alerts: List[Alert] = []
        self.counts: Dict[str, int] = {}
        self._tool_counts: Dict[str, int] = {}
        self._seen: "OrderedDict[Tuple[str, str, str], float]" = OrderedDict()
        self._lock = threading.Lock()
        self._subscribers: List[Callable[[Alert], None]] = []
        self._log_subscribers: List[Callable[[LogRecord], None]] = []
        self._log_buffer: List[LogRecord] = []
        self.suppressed = 0

        day = time.strftime("%Y%m%d")
        self._day = day
        self.jsonl_path = os.path.join(log_dir, f"alerts-{day}.jsonl")
        self.text_path = os.path.join(log_dir, f"alerts-{day}.log")
        self.run_path = os.path.join(log_dir, f"watch-{day}.log")
        # 只在确实要写文件时才创建目录（例如 `wsp check` 这类只读场景不产生副作用）
        if save_jsonl:
            try:
                os.makedirs(log_dir, exist_ok=True)
            except OSError:
                pass

        self._syslog = None
        if self.use_syslog:
            try:
                import syslog as _syslog

                _syslog.openlog("webshell-watch", _syslog.LOG_PID, self._facility(syslog_facility))
                self._syslog = _syslog
            except (ImportError, OSError):
                self._syslog = None

    # ------------------------------------------------------------------
    def _refresh_paths(self) -> None:
        """长时间运行时按写入当天切换文件，在持锁状态下调用。"""
        day = time.strftime("%Y%m%d")
        if day != self._day:
            self._day = day
            self.jsonl_path = os.path.join(self.log_dir, f"alerts-{day}.jsonl")
            self.text_path = os.path.join(self.log_dir, f"alerts-{day}.log")
            self.run_path = os.path.join(self.log_dir, f"watch-{day}.log")

    @staticmethod
    def _hostname() -> str:
        try:
            return socket.gethostname()
        except OSError:
            return "unknown"

    @staticmethod
    def _facility(name: str) -> int:
        try:
            import syslog as _syslog

            return getattr(_syslog, f"LOG_{name.upper()}", _syslog.LOG_LOCAL0)
        except Exception:
            return 0

    def subscribe(self, fn: Callable[[Alert], None]) -> None:
        self._subscribers.append(fn)

    def subscribe_log(self, fn: Callable[[LogRecord], None]) -> None:
        self._log_subscribers.append(fn)

    # ------------------------------------------------------------------
    # 告警
    # ------------------------------------------------------------------
    def emit(self, alert: Alert) -> None:
        # 补齐主机信息，便于多机集中收集
        if not alert.host:
            alert.host = self.hostname
        with self._lock:
            self._refresh_paths()
            if self._is_duplicate(alert):
                self.suppressed += 1
                return
            self.alerts.append(alert)
            if self.max_history and len(self.alerts) > self.max_history:
                del self.alerts[:len(self.alerts) - self.max_history]
            self.counts[alert.severity] = self.counts.get(alert.severity, 0) + 1
            self._tool_counts[alert.tool] = self._tool_counts.get(alert.tool, 0) + 1
            if self.save_jsonl:
                self._write_jsonl(alert)
                self._write_text(alert)
            if self._syslog is not None:
                self._write_syslog(alert)
            if self.console and self.verbose:
                self._print(alert)
        for fn in list(self._subscribers):
            try:
                fn(alert)
            except Exception:
                pass
        self._maybe_webhook(alert)

    def emit_many(self, alerts) -> int:
        n = 0
        for a in alerts:
            self.emit(a)
            n += 1
        return n

    def _is_duplicate(self, alert: Alert) -> bool:
        """
        去重键 = (首个规则、判定类型、来源)。

        为什么不直接用完整 rule_id 列表：引擎会把同一会话命中的多条规则
        聚合成一条告警，rule_id 形如 "ANT-020,ANT-001,ANT-090…"，
        不同的规则组合会被当成不同的键，导致同一类攻击在多个会话里重复刷屏。
        这里改取「首个（分值最高）规则」作为身份标识。
        """
        if self.dedupe_seconds <= 0:
            return False
        first_rule = (alert.rule_id or "").split(",")[0].strip()
        key = (first_rule, alert.tool, alert.flow)
        now = time.monotonic()
        last = self._seen.get(key)
        # 清理过期项，避免无限增长
        while self._seen:
            k, t = next(iter(self._seen.items()))
            if now - t >= self.dedupe_seconds:
                self._seen.popitem(last=False)
            else:
                break
        if last is not None and now - last < self.dedupe_seconds:
            return True
        self._seen[key] = now
        self._seen.move_to_end(key)
        return False

    # -- 输出实现 ---------------------------------------------------------
    def _payload(self, alert: Alert) -> Dict:
        d = alert.to_dict()
        d["host"] = self.hostname
        return d

    def _write_jsonl(self, alert: Alert) -> None:
        try:
            with open(self.jsonl_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(self._payload(alert), ensure_ascii=False) + "\n")
        except OSError:
            pass

    def _write_text(self, alert: Alert) -> None:
        try:
            with open(self.text_path, "a", encoding="utf-8") as fh:
                fh.write(alert.one_line() + "\n")
                if alert.evidence:
                    fh.write(f"    证据: {alert.evidence}\n")
                if alert.advice:
                    fh.write(f"    建议: {alert.advice}\n")
        except OSError:
            pass

    def _write_syslog(self, alert: Alert) -> None:
        try:
            import syslog as _syslog

            level = {
                Severity.CRITICAL: _syslog.LOG_CRIT,
                Severity.HIGH: _syslog.LOG_ERR,
                Severity.MEDIUM: _syslog.LOG_WARNING,
                Severity.LOW: _syslog.LOG_NOTICE,
            }.get(alert.severity, _syslog.LOG_INFO)
            self._syslog.syslog(
                level,
                f"[{alert.severity}] [{alert.tool}] {alert.title} | 规则={alert.rule_id} "
                f"分值={alert.score} | 来源={alert.flow} | 证据={alert.evidence[:200]}",
            )
        except Exception:
            pass

    def _print(self, alert: Alert) -> None:
        prefix = SEV_COLOR.get(alert.severity, "") if self.color else ""
        suffix = RESET if prefix else ""
        print(f"{prefix}{alert.one_line()}{suffix}", flush=True)
        if alert.evidence:
            print(f"        证据: {alert.evidence[:300]}", flush=True)
        if alert.advice:
            print(f"        建议: {alert.advice[:220]}", flush=True)

    # -- webhook ----------------------------------------------------------
    def _maybe_webhook(self, alert: Alert) -> None:
        cfg = self.webhook
        if not cfg.get("enabled") or not cfg.get("url"):
            return
        if Severity.rank(alert.severity) < Severity.rank(str(cfg.get("min_severity", "HIGH"))):
            return
        threading.Thread(
            target=self._post_webhook, args=(alert,), name="webhook", daemon=True
        ).start()

    def _post_webhook(self, alert: Alert) -> None:
        cfg = self.webhook
        fmt = str(cfg.get("format", "generic")).lower()
        text = (
            f"[{alert.severity}] {alert.host} 发现 {alert.tool} 流量特征\n"
            f"规则：{alert.rule_id}（{alert.score} 分）\n"
            f"来源：{alert.flow}\n"
            f"标题：{alert.title}\n"
            f"证据：{alert.evidence[:300]}\n"
            f"建议：{alert.advice[:200]}"
        )
        if fmt == "dingtalk":
            body = {"msgtype": "text", "text": {"content": f"WebShell告警\n{text}"}}
        elif fmt == "wecom":
            body = {"msgtype": "text", "text": {"content": f"WebShell告警\n{text}"}}
        elif fmt == "slack":
            body = {"text": text}
        else:
            body = self._payload(alert)
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        headers = {"Content-Type": "application/json; charset=utf-8"}
        headers.update({str(k): str(v) for k, v in (cfg.get("headers") or {}).items()})
        req = urllib.request.Request(str(cfg["url"]), data=data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=float(cfg.get("timeout", 5))) as resp:
                resp.read(512)
        except (urllib.error.URLError, OSError, ValueError) as exc:
            self.log("WARN", f"webhook 推送失败：{exc}")

    # ------------------------------------------------------------------
    # 运行日志
    # ------------------------------------------------------------------
    def log(self, level: str, message: str) -> None:
        rec = LogRecord(time.time(), level, message)
        with self._lock:
            self._refresh_paths()
            self._log_buffer.append(rec)
            if len(self._log_buffer) > 5000:
                del self._log_buffer[:1000]
            try:
                with open(self.run_path, "a", encoding="utf-8") as fh:
                    fh.write(f"{rec.time_str} [{level}] {message}\n")
            except OSError:
                pass
            if self._syslog is not None:
                try:
                    import syslog as _syslog

                    lvl = {"ERROR": _syslog.LOG_ERR, "WARN": _syslog.LOG_WARNING}.get(
                        level, _syslog.LOG_INFO
                    )
                    self._syslog.syslog(lvl, f"[{level}] {message}")
                except Exception:
                    pass
            if self.console:
                color = ""
                if self.color and level in ("WARN", "ERROR"):
                    color = "\033[33m" if level == "WARN" else "\033[31m"
                print(f"{color}{rec.time_str} [{level}] {message}{RESET if color else ''}", flush=True)
        for fn in list(self._log_subscribers):
            try:
                fn(rec)
            except Exception:
                pass

    # ------------------------------------------------------------------
    def summary(self) -> str:
        parts = [f"告警总数 {sum(self.counts.values())}"]
        for sev in reversed(Severity.ORDER):
            if self.counts.get(sev):
                parts.append(f"{Severity.cn(sev)} {self.counts[sev]}")
        if self.suppressed:
            parts.append(f"去重抑制 {self.suppressed}")
        by_tool = self._tool_counts
        if by_tool:
            top = sorted(by_tool.items(), key=lambda x: -x[1])[:6]
            parts.append("按类型：" + "、".join(f"{k} {v}" for k, v in top))
        return "；".join(parts)

    def export(self, path: str) -> str:
        with open(path, "w", encoding="utf-8") as fh:
            for a in self.alerts:
                fh.write(json.dumps(self._payload(a), ensure_ascii=False) + "\n")
        return path

    @property
    def paths(self) -> Dict[str, str]:
        return {
            "告警JSONL": self.jsonl_path,
            "告警摘要": self.text_path,
            "运行日志": self.run_path,
        }
