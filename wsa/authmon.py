"""
认证日志监控（/var/log/auth.log、/var/log/secure）。

为什么防守 webshell 需要看认证日志：
    webshell 只是入口，攻击者接下来几乎必然做三件事 ——
    写 SSH 公钥做持久化、提权（sudo/SUID）、创建后门账号。
    这些动作全部落在认证日志里，而且 webshell 的流量特征可以被魔改绕过，
    认证日志里的行为证据却很难抹掉。

监控项：
    * SSH 密码爆破（同源 IP 窗口内多次失败）以及爆破成功（后面紧跟成功登录）
    * SSH 认证成功（用于与运维白名单比对）
    * sudo / su 提权成功
    * 创建用户、修改密码
    * sshd 为未知密钥放行（可能被写入 authorized_keys）
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from .models import Alert, Severity, Rule

AUTH_SOURCE = "认证日志"

# ---------------------------------------------------------------------------
# 日志模式
# ---------------------------------------------------------------------------
#: 兼容 syslog 传统格式与 Ubuntu 24.04 的 ISO 时间格式
_TS_PATTERNS = [
    re.compile(r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2}) (?P<hms>\d{2}:\d{2}:\d{2})"),
    re.compile(r"^(?P<iso>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2})?)"),
]

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

EVENT_PATTERNS: List[Tuple[str, str, str]] = [
    # (事件名, 正则, 说明)
    ("ssh_fail", r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)", "SSH 密码认证失败"),
    ("ssh_fail", r"Failed publickey for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)", "SSH 公钥认证失败"),
    ("ssh_fail", r"Invalid user (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)", "SSH 无效用户名尝试"),
    ("ssh_fail", r"authentication failure;.*?rhost=(?P<ip>\S+).*?user=(?P<user>\S+)", "PAM 认证失败"),
    ("ssh_ok", r"Accepted (?:password|publickey|keyboard-interactive/pam) for (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)", "SSH 认证成功"),
    ("ssh_ok", r"Accepted publickey for (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)", "SSH 公钥登录成功"),
    ("privilege_event", r"sudo:\s+(?P<user>\S+) : .*?COMMAND=(?P<cmd>.+)$", "sudo 执行命令"),
    ("privilege_event", r"pam_unix\(sudo:session\): session opened for user (?P<target>\S+) by (?P<user>\S+)", "sudo 会话开启"),
    ("privilege_event", r"su(?:\[|:).*?session opened for user (?P<target>\S+)", "su 切换用户"),
    ("privilege_event", r"useradd(?:\[|:).*?new user: name=(?P<user>[^,]+)", "新建用户"),
    ("privilege_event", r"usermod(?:\[|:| )", "修改用户"),
    ("privilege_event", r"passwd(?:\[|:).*?password changed for (?P<user>\S+)", "修改密码"),
    # 注意：SSH 密钥登录本身不是提权，这条关键词只用于「用户把公钥写进授权文件」的场景，
    # 不能包含裸的 "Accepted ... for user from ip"，否则每次登录都会误报提权。
    ("privilege_event", r"authorized_keys|AuthorizedKeysFile.*updated", "SSH 授权公钥被写入"),
]

_COMPILED = [(name, re.compile(pattern, re.IGNORECASE), note) for name, pattern, note in EVENT_PATTERNS]


@dataclass
class AuthEvent:
    ts: float
    event: str
    note: str
    ip: str = ""
    user: str = ""
    detail: str = ""
    raw: str = ""


def parse_ts(line: str, now: Optional[float] = None) -> float:
    """解析 syslog 或 ISO 时间戳；两者都失败则用当前时间。"""
    now = now if now is not None else time.time()
    for pat in _TS_PATTERNS:
        m = pat.match(line)
        if not m:
            continue
        gd = m.groupdict()
        try:
            if gd.get("iso"):
                text = gd["iso"].replace("Z", "+00:00")
                import datetime

                dt = datetime.datetime.fromisoformat(text)
                return dt.timestamp()
            mon = _MONTHS.get(gd["mon"], 1)
            day = int(gd["day"])
            hh, mm, ss = (int(x) for x in gd["hms"].split(":"))
            lt = time.localtime(now)
            year = lt.tm_year
            # 跨年（12 月日志在 1 月被读到）时回退一年
            if mon == 12 and lt.tm_mon == 1:
                year -= 1
            return time.mktime((year, mon, day, hh, mm, ss, 0, 0, -1))
        except (ValueError, OverflowError):
            return now
    return now


def parse_line(line: str) -> List[AuthEvent]:
    """解析一行认证日志，可能产生多个事件（例如同时含失败与成功）。"""
    line = line.rstrip("\r\n")
    if not line or len(line) > 8192:
        return []
    ts = parse_ts(line)
    events: List[AuthEvent] = []
    for name, pattern, note in _COMPILED:
        m = pattern.search(line)
        if not m:
            continue
        gd = m.groupdict()
        events.append(
            AuthEvent(
                ts=ts,
                event=name,
                note=note,
                ip=(gd.get("ip") or "").strip(),
                user=(gd.get("user") or gd.get("target") or "").strip(),
                detail=(gd.get("cmd") or "").strip(),
                raw=line[:600],
            )
        )
    return events


# ---------------------------------------------------------------------------
# 爆破统计
# ---------------------------------------------------------------------------
class BruteTracker:
    """按来源 IP 统计失败次数，超阈值触发一次告警并进入冷却。"""

    def __init__(self, window: int = 300, threshold: int = 10, cooldown: int = 600):
        self.window = window
        self.threshold = threshold
        self.cooldown = cooldown
        self._fails: Dict[str, List[float]] = {}
        self._fired: Dict[str, float] = {}
        self._users: Dict[str, set] = {}

    def add_fail(self, ip: str, user: str, ts: float) -> Optional[Tuple[int, List[str]]]:
        if not ip:
            return None
        hits = self._fails.setdefault(ip, [])
        hits.append(ts)
        cutoff = ts - self.window
        while hits and hits[0] < cutoff:
            hits.pop(0)
        users = self._users.setdefault(ip, set())
        if user:
            users.add(user)
        if len(hits) >= self.threshold and ts - self._fired.get(ip, 0) > self.cooldown:
            self._fired[ip] = ts
            return len(hits), sorted(users)[:12]
        return None

    def failures(self, ip: str) -> int:
        return len(self._fails.get(ip, []))


# ---------------------------------------------------------------------------
# 监控主体
# ---------------------------------------------------------------------------
class AuthMonitor:
    def __init__(
        self,
        alert_fn: Callable[[Alert], None],
        log_fn: Callable[[str, str], None],
        analyzer_rules: Sequence[Rule],
        sources: Sequence[Dict],
        from_beginning: bool = False,
        fail_window: int = 300,
        fail_threshold: int = 10,
        trusted_ips: Sequence[str] = (),
    ):
        from .logs import FileTailer

        self.alert_fn = alert_fn
        self.log = log_fn
        self.rules = {r.id: r for r in analyzer_rules}
        self.trusted_ips = set(trusted_ips or ())
        self.tailers: List[Tuple[Dict, "FileTailer"]] = []
        for src in sources:
            path = str(src.get("path", ""))
            if path:
                self.tailers.append((src, FileTailer(path, from_beginning=from_beginning)))
        self.tracker = BruteTracker(window=fail_window, threshold=fail_threshold)
        self.events_total = 0
        self.recent: List[AuthEvent] = []
        #: 记录已经报过的成功登录原始行，避免同一行被多个模式命中而重复告警
        self.last_ok: Dict[Tuple[str, str], str] = {}

    def poll_once(self) -> int:
        processed = 0
        for src, tailer in self.tailers:
            lines, notes = tailer.read_lines()
            for n in notes:
                self.log("WARN", n)
            for line in lines:
                for ev in parse_line(line):
                    processed += 1
                    self.events_total += 1
                    self.recent.append(ev)
                    if len(self.recent) > 2000:
                        del self.recent[:500]
                    self._handle(ev, src)
        return processed

    # ------------------------------------------------------------------
    def _handle(self, ev: AuthEvent, src: Dict) -> None:
        source = f"{AUTH_SOURCE}({src.get('name', '')})"
        if ev.event == "ssh_fail":
            got = self.tracker.add_fail(ev.ip, ev.user, ev.ts)
            if got:
                count, users = got
                rule = self.rules.get("DEF-040")
                if rule:
                    self._emit(
                        rule,
                        source,
                        f"来源 {ev.ip} 在 {self.tracker.window} 秒内认证失败 {count} 次；"
                        f"尝试过的用户名：{'、'.join(users) or '未知'}；最后一条：{ev.raw[:180]}",
                        flow=f"{ev.ip} -> SSH",
                    )
            return

        if ev.event == "ssh_ok":
            rule = self.rules.get("DEF-041")
            if not rule:
                return
            if self.last_ok.get((ev.ip, ev.user)) == ev.raw:
                return      # 同一条日志行可能被多个模式命中，避免重复告警
            self.last_ok[(ev.ip, ev.user)] = ev.raw
            trusted = ev.ip in self.trusted_ips
            fails = self.tracker.failures(ev.ip)
            extra = ""
            if trusted:
                extra = "（来源在配置的信任列表内，可忽略）"
            elif fails:
                extra = f"（该来源此前已有 {fails} 次失败记录，高度可疑）"
            self._emit(
                rule,
                source,
                f"用户 {ev.user or '未知'} 从 {ev.ip} 登录成功{extra}；原始日志：{ev.raw[:180]}",
                flow=f"{ev.ip} -> {ev.user or 'SSH'}",
                score_bonus=25 if (fails and not trusted) else 0,
            )
            return

        if ev.event == "privilege_event":
            # sudo 的常规运维操作也会命中，因此只给低分；
            # 但如果同一时间附近有 webshell 告警，运维可据此串联研判。
            if self.trusted_ips and ev.ip and ev.ip in self.trusted_ips:
                return
            rule = self.rules.get("DEF-042")
            if rule:
                detail = f"{ev.note}：{ev.raw[:220]}"
                if ev.detail:
                    detail += f"（命令：{ev.detail[:160]}）"
                self._emit(rule, source, detail, flow=f"本地/{ev.user or 'unknown'}")

    def _emit(self, rule: Rule, source: str, evidence: str, flow: str, score_bonus: int = 0) -> None:
        score = rule.score + score_bonus
        self.alert_fn(
            Alert(
                ts=time.time(),
                severity=Severity.from_score(score),
                tool=rule.tool,
                title=rule.title,
                rule_id=rule.id,
                score=score,
                flow=flow,
                source=source,
                evidence=evidence,
                advice=rule.advice,
                tags=rule.tags,
            )
        )

    def summary(self) -> str:
        return f"认证监控：共处理 {self.events_total} 个事件"
