r"""
Web 访问日志监控（防守端的主力数据源）。

为什么以日志为主：服务器上的 HTTPS 流量是密文，抓包看不到内容；
而 Web 服务器是在 TLS 解密之后处理的请求，访问日志天然记录了明文 URL、
User-Agent、状态码，配置后还能记录 POST 请求体。
因此「日志监控」是本工具在服务器上发现 webshell 调用最可靠的手段。

支持的日志格式（在配置里用 format 指定）：
    nginx_combined_body     主推荐：$request + 之后的请求体字段
    apache_combined_body    同结构（Apache 用 %r 与自定义 body 变量）
    nginx_combined          标准 combined，无请求体
    自定义                  用正则 + 命名组，见 README

日志轮转处理：记录文件的 inode 与偏移量，检测到 inode 变化（logrotate）
或文件变小（被截断）时自动从头读取，不会漏事件、也不会重复读。
"""

from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from .analysis import Analyzer
from .models import Alert, Flow, FlowKey, HttpTransaction, Rule, Severity
from .rules import KIND_LOG, KIND_STAT
from .utils import looks_base64, printable_ratio, shannon_entropy

#: 日志来源标记
LOG_SOURCE = "Web日志"

#: 视为「脚本文件」的扩展名（用于行为统计与路径判断）
SCRIPT_EXT_RE = re.compile(
    r"\.(?:php\d?|phtml|phar|jspx?|jspf|asp|aspx|ashx|asmx|cgi|pl|py|sh)\b", re.IGNORECASE
)


# ---------------------------------------------------------------------------
# 日志行解析
# ---------------------------------------------------------------------------
@dataclass
class LogEntry:
    """一条已解析的访问日志。"""

    ts: float
    client_ip: str
    method: str
    path: str
    protocol: str = "HTTP/1.1"
    status: int = 0
    bytes_sent: int = 0
    referer: str = ""
    user_agent: str = ""
    body: str = ""
    host: str = ""
    format_name: str = ""
    raw: str = ""
    truncated: bool = False

    @property
    def is_script(self) -> bool:
        return bool(SCRIPT_EXT_RE.search(self.path.split("?", 1)[0]))

    @property
    def url(self) -> str:
        base = f"http://{self.host}" if self.host else "http://localhost"
        return f"{base}{self.path}"

    def to_transaction(self, max_body: int = 65536) -> HttpTransaction:
        """把日志条目还原成 HttpTransaction，复用同一套检测规则。"""
        body = self.body.encode("utf-8", "ignore")[:max_body]
        head = [
            f"{self.method} {self.path} {self.protocol}",
            f"Host: {self.host or 'localhost'}",
        ]
        if self.user_agent:
            head.append(f"User-Agent: {self.user_agent}")
        if self.referer:
            head.append(f"Referer: {self.referer}")
        if body:
            head.append("Content-Type: application/x-www-form-urlencoded")
            head.append(f"Content-Length: {len(body)}")
        head.append("")
        head.append("")
        txn = HttpTransaction(index=0, ts=self.ts)
        txn.method = self.method
        txn.path = self.path
        txn.host = self.host or "localhost"
        txn.url = self.url
        txn.status = self.status
        txn.raw_head = "\r\n".join(head[:-2]).encode("utf-8", "ignore") + b"\r\n\r\n"
        txn.headers = {
            "host": txn.host,
            "user-agent": self.user_agent,
            "referer": self.referer,
        }
        raw_pairs: List[Tuple[str, str]] = []
        if self.user_agent:
            raw_pairs.append(("User-Agent", self.user_agent))
        if self.referer:
            raw_pairs.append(("Referer", self.referer))
        raw_pairs.append(("X-Log-Source", self.format_name or "log"))
        txn.raw_headers = raw_pairs
        txn.body = body
        resp = f"HTTP/1.1 {self.status} \r\nContent-Length: {self.bytes_sent}\r\n\r\n"
        txn.resp_head = resp.encode("latin-1", "ignore")
        txn.resp_body = b""
        txn.note = f"来自 {self.format_name or '日志'}"
        return txn


#: 各格式的解析正则（顺序即优先级）
_FORMATS: List[Tuple[str, re.Pattern]] = [
    # nginx: log_format ... '$remote_addr - $remote_user [$time_local] "$request" '
    #                        '$status $body_bytes_sent "$http_referer" "$http_user_agent" $request_body';
    (
        "nginx_combined_body",
        re.compile(
            r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] '
            r'"(?P<req>[^"]*)" (?P<status>\d{3}) (?P<bytes>\d+|-) '
            r'"(?P<referer>[^"]*)" "(?P<ua>[^"]*)" ?(?P<body>.*)$'
        ),
    ),
    # 标准 combined（无请求体）
    (
        "nginx_combined",
        re.compile(
            r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] '
            r'"(?P<req>[^"]*)" (?P<status>\d{3}) (?P<bytes>\d+|-) '
            r'"(?P<referer>[^"]*)" "(?P<ua>[^"]*)"\s*$'
        ),
    ),
    # Apache 自定义：%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i" [body] [Host]
    (
        "apache_combined_body",
        re.compile(
            r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] '
            r'"(?P<req>[^"]*)" (?P<status>\d{3}) (?P<bytes>\d+|-) '
            r'"(?P<referer>[^"]*)" "(?P<ua>[^"]*)" ?(?P<body>.*)$'
        ),
    ),
]

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def parse_ts(text: str, now: float = 0.0) -> float:
    """
    解析 nginx/apache 的时间格式：18/Oct/2026:13:55:36 +0800。

    时区处理说明：日志里写的是服务器本地时间 + 显式偏移量，
    因此正确做法是把「日 时:分:秒」当作 UTC 求秒数（calendar.timegm），
    再减去偏移量得到绝对时间。
    直接用 time.mktime 会按运行机器的本地时区解释，导致时间显示偏移若干小时。
    """
    import calendar

    text = text.strip()
    m = re.match(r"(\d{1,2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})", text)
    if not m:
        return now or time.time()
    day, mon, year, hh, mm, ss = m.groups()
    try:
        base = calendar.timegm(
            (int(year), _MONTHS.get(mon, 1), int(day), int(hh), int(mm), int(ss), 0, 0, 0)
        )
    except (ValueError, OverflowError):
        return now or time.time()
    tz = re.search(r"([+-])(\d{2})(\d{2})\s*$", text)
    if tz:
        sign = 1 if tz.group(1) == "+" else -1
        offset = sign * (int(tz.group(2)) * 3600 + int(tz.group(3)) * 60)
        base -= offset
    return float(base)


def unescape_log(text: str) -> str:
    r"""
    还原日志中的转义序列。

    nginx 默认把不可打印字符与引号写成 \xNN / \" 的形式，
    POST 请求体里常有这类字符，不还原会导致特征匹配失败。
    """
    if "\\" not in text:
        return text
    out = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "\\" and i + 1 < n:
            nxt = text[i + 1]
            if nxt == "x" and i + 3 < n:
                hexs = text[i + 2 : i + 4]
                try:
                    out.append(chr(int(hexs, 16)))
                    i += 4
                    continue
                except ValueError:
                    pass
            if nxt == '"':
                out.append('"')
                i += 2
                continue
            if nxt == "\\":
                out.append("\\")
                i += 2
                continue
            if nxt == "n":
                out.append("\n")
                i += 2
                continue
            if nxt == "r":
                out.append("\r")
                i += 2
                continue
            if nxt == "t":
                out.append("\t")
                i += 2
                continue
        out.append(ch)
        i += 1
    return "".join(out)


def decode_body(text: str) -> str:
    """
    还原日志里记录的请求体。

    处理两件事：
      1. nginx 会把不可打印字符与引号写成 \\xNN / \\" 的形式；
      2. 表单请求体在日志里仍是 URL 编码（%3D、+），需要解码才能匹配明文特征
         （例如蚁剑的载荷在日志里是 base64 后再 %3D 的形式）。
    只在检测到百分号或加号时才做 URL 解码，避免破坏正常的文本内容。
    """
    text = unescape_log(text)
    if "%" not in text:
        return text
    try:
        # 注意用 unquote 而不是 unquote_plus：Base64 里的 "+" 是有效字符，
        # 用 unquote_plus 会把它变成空格从而破坏密文。
        from urllib.parse import unquote

        return unquote(text)
    except Exception:
        return text


def parse_line(line: str, format_hint: str = "", max_body: int = 262144) -> Optional[LogEntry]:
    """解析一行访问日志，失败返回 None。"""
    line = line.rstrip("\r\n")
    if not line:
        return None
    if len(line) > max_body:
        line = line[:max_body]

    candidates = _FORMATS
    if format_hint:
        candidates = [f for f in _FORMATS if f[0] == format_hint] or _FORMATS

    for name, pattern in candidates:
        m = pattern.match(line)
        if not m:
            continue
        gd = m.groupdict()
        req = gd.get("req") or "-"
        parts = req.split(" ")
        if len(parts) >= 3:
            method, path, protocol = parts[0], parts[1], parts[2]
        elif len(parts) == 2:
            method, path, protocol = parts[0], parts[1], "HTTP/1.1"
        else:
            method, path, protocol = req, "/", ""
        body = ""
        raw_body = gd.get("body")
        if raw_body:
            body = decode_body(raw_body.strip())
        try:
            status = int(gd.get("status") or 0)
        except ValueError:
            status = 0
        try:
            nbytes = int(gd.get("bytes") or 0)
        except ValueError:
            nbytes = 0

        # 主机名：部分日志在请求体之后追加了 Host 字段
        host = ""
        host_field = gd.get("vhost") or gd.get("host")
        if host_field:
            host = host_field.strip()

        return LogEntry(
            ts=parse_ts(gd.get("ts") or ""),
            client_ip=gd.get("ip") or "",
            method=method.upper(),
            path=path,
            protocol=protocol or "HTTP/1.1",
            status=status,
            bytes_sent=nbytes,
            referer=(gd.get("referer") or "").strip(),
            user_agent=(gd.get("ua") or "").strip(),
            body=body,
            host=host,
            format_name=name,
            raw=line,
            truncated=len(line) >= max_body,
        )
    return None


# ---------------------------------------------------------------------------
# 文件跟踪（处理 logrotate 与截断）
# ---------------------------------------------------------------------------
@dataclass
class TailState:
    path: str
    inode: int = -1
    offset: int = 0
    first_read: bool = True
    missing_reported: bool = False


class FileTailer:
    """按行读取日志文件，自动处理轮转与截断。"""

    def __init__(self, path: str, from_beginning: bool = False,
                 max_line_bytes: int = 262144):
        self.path = path
        self.from_beginning = from_beginning
        self.state = TailState(path=path)
        self.rotations = 0
        self.max_line_bytes = max(1, int(max_line_bytes))
        self._pending = b""
        self._truncated = False

    def read_lines(self, flush_partial: bool = False) -> Tuple[List[str], List[str]]:
        """返回 (新增行, 提示信息)。"""
        notes: List[str] = []
        lines: List[str] = []
        try:
            # fstat 与读取使用同一个句柄，避免 stat 后发生轮转导致偏移错位。
            fh = open(self.path, "rb")
        except FileNotFoundError:
            if not self.state.missing_reported:
                notes.append(f"日志文件不存在：{self.path}")
                self.state.missing_reported = True
            return lines, notes
        except PermissionError:
            notes.append(f"无权读取日志文件：{self.path}（请用 root 或加入 adm/systemd-journal 组）")
            self.state.missing_reported = True
            return lines, notes
        except OSError as exc:
            notes.append(f"读取 {self.path} 失败：{exc}")
            return lines, notes

        try:
            with fh:
                st = os.fstat(fh.fileno())
                inode = st.st_ino
                if self.state.inode != inode:
                    rotated = self.state.inode != -1
                    if rotated:
                        notes.append(f"{self.path} 发生日志轮转（inode 变化），已跟随新文件")
                        self.rotations += 1
                    self.state.inode = inode
                    self.state.offset = 0 if (self.from_beginning or rotated) else st.st_size
                    self._pending = b""
                    self._truncated = False
                elif st.st_size < self.state.offset:
                    notes.append(f"{self.path} 被截断，已从文件开头继续")
                    self.state.offset = 0
                    self._pending = b""
                    self._truncated = False
                    self.rotations += 1
                self.state.first_read = False
                self.state.missing_reported = False
                fh.seek(self.state.offset)
                # 限制每次读取及未完成行的缓存；UTF-8 完整行收到后才解码。
                remaining = max(0, st.st_size - self.state.offset)
                while remaining:
                    raw = fh.readline(min(65536, remaining))
                    if not raw:
                        break
                    remaining -= len(raw)
                    room = self.max_line_bytes - len(self._pending)
                    self._pending += raw[:room]
                    if len(raw) > room and not self._truncated:
                        notes.append(f"{self.path} 单行超过 {self.max_line_bytes} 字节，已截断")
                        self._truncated = True
                    if raw.endswith(b"\n"):
                        text = self._pending.rstrip(b"\r\n").decode("utf-8", "replace")
                        if text.strip():
                            lines.append(text)
                        self._pending = b""
                        self._truncated = False
                self.state.offset = fh.tell()
                if flush_partial and self._pending:
                    text = self._pending.rstrip(b"\r\n").decode("utf-8", "replace")
                    if text.strip():
                        lines.append(text)
                    self._pending = b""
                    self._truncated = False
        except (OSError, PermissionError) as exc:
            notes.append(f"读取 {self.path} 失败：{exc}")
            return lines, notes

        return lines, notes


# ---------------------------------------------------------------------------
# 防守规则求值
# ---------------------------------------------------------------------------
@dataclass
class LogRuleContext:
    """日志规则的求值上下文。"""

    entry: LogEntry
    stats: Dict[str, object] = field(default_factory=dict)


def eval_log_rule(rule: Rule, ctx: LogRuleContext) -> Optional[Tuple[int, str]]:
    """求值一条 log 类型规则，返回 (分值, 证据) 或 None。"""
    meta = rule.meta or {}
    e = ctx.entry

    if "require_method" in meta and e.method not in meta["require_method"]:
        return None
    if "require_status" in meta and e.status not in meta["require_status"]:
        return None
    if "require_path_ext" in meta:
        base = e.path.split("?", 1)[0].lower()
        exts = [str(x).lower() for x in meta["require_path_ext"]]
        if not any(base.endswith(ext) for ext in exts):
            return None
    if "require_body_min" in meta and len(e.body) < int(meta["require_body_min"]):
        return None
    if "require_missing_header" in meta:
        for name in meta["require_missing_header"]:
            if name.lower() == "referer" and e.referer and e.referer != "-":
                return None
            if name.lower() == "user-agent" and e.user_agent and e.user_agent != "-":
                return None
    if "require_path_regex" in meta:
        try:
            if not re.search(str(meta["require_path_regex"]), e.path, re.IGNORECASE):
                return None
        except re.error:
            return None
    if "require_ua_regex" in meta:
        ua = e.user_agent or ""
        try:
            m = re.search(str(meta["require_ua_regex"]), ua, re.IGNORECASE)
        except re.error:
            m = None
        if not m:
            return None
        return rule.score, f"User-Agent 命中「{m.group(0)}」: {ua[:120]}"
    if "require_regex" in meta:
        blob = " ".join([e.path, e.body, e.user_agent, e.referer])
        try:
            m = re.search(str(meta["require_regex"]), blob, re.IGNORECASE)
        except re.error:
            m = None
        if not m:
            return None
        return rule.score, f"请求内容命中「{m.group(0)[:80]}」（{e.method} {e.path[:120]}）"

    # 组合条件（DEF-001 / DEF-002）
    reasons: List[str] = []
    if meta.get("require_single_param"):
        pairs = [p for p in e.body.split("&") if "=" in p]
        if len(pairs) != 1:
            return None
        reasons.append("单参数")
    if meta.get("require_body_base64ish"):
        value = e.body.split("=", 1)[-1]
        if not (looks_base64(value, 32) or printable_ratio(value.encode("utf-8", "ignore")) > 0.9):
            return None
        reasons.append(f"编码载荷 {len(value)} 字符（熵 {shannon_entropy(value.encode('utf-8', 'ignore')):.2f}）")
    if "require_path_ext" in meta:
        reasons.append(e.path.split("?", 1)[0][-12:])
    if "require_missing_header" in meta:
        reasons.append("无 Referer")
    if "require_body_min" in meta:
        reasons.append(f"体长 {len(e.body)}")
    if e.status:
        reasons.append(f"状态 {e.status}")
    if not reasons:
        return None
    return rule.score, "、".join(reasons)


# ---------------------------------------------------------------------------
# 监控主体
# ---------------------------------------------------------------------------
class ScriptStats:
    """脚本访问的行为统计（用于 DEF-020 / DEF-021）。"""

    def __init__(self, window: int = 60, threshold: int = 30):
        self.window = window
        self.threshold = threshold
        self._by_ip: Dict[str, List[float]] = {}
        self._by_path: Dict[str, Dict[str, float]] = {}
        self._fired_ip: Dict[str, float] = {}
        self._fired_path: Dict[str, float] = {}

    def add(self, ip: str, path: str, ts: float) -> Dict[str, object]:
        """记录一次脚本访问，返回本行触发的统计信号。"""
        out: Dict[str, object] = {}
        script_path = path.split("?", 1)[0]
        window = self.window

        hits = self._by_ip.setdefault(ip, [])
        hits.append(ts)
        cutoff = ts - window
        while hits and hits[0] < cutoff:
            hits.pop(0)
        if len(hits) >= self.threshold and ts - self._fired_ip.get(ip, 0) > window:
            self._fired_ip[ip] = ts
            out["same_ip_to_script"] = len(hits)

        ips = self._by_path.setdefault(script_path, {})
        ips[ip] = ts
        for k, v in list(ips.items()):
            if ts - v > max(window, 300):
                ips.pop(k, None)
        if len(ips) >= 8 and ts - self._fired_path.get(script_path, 0) > 300:
            self._fired_path[script_path] = ts
            out["script_multi_ip"] = len(ips)
        return out


class WebLogMonitor:
    """
    访问日志监控器。

    在线（守护进程）与离线（`wsp analyze-log`）共用同一实现：
    在线时由调度器周期调用 poll_once()，离线时循环调用直到文件读完。
    """

    def __init__(
        self,
        alert_fn: Callable[[Alert], None],
        log_fn: Callable[[str, str], None],
        analyzer: Analyzer,
        sources: Sequence[Dict],
        max_line_bytes: int = 262144,
        from_beginning: bool = False,
        stats_window: int = 60,
        stats_threshold: int = 30,
        final_lines: bool = False,
    ):
        self.alert_fn = alert_fn
        self.log = log_fn
        self.analyzer = analyzer
        self.max_line_bytes = max_line_bytes
        self.final_lines = final_lines
        self.sources = list(sources)
        self.tailers: List[Tuple[Dict, FileTailer]] = []
        self.stats = ScriptStats(window=stats_window, threshold=stats_threshold)
        for src in self.sources:
            path = str(src.get("path", ""))
            if not path:
                continue
            self.tailers.append((src, FileTailer(path, from_beginning=from_beginning,
                                               max_line_bytes=max_line_bytes)))
        self.defense_rules = [r for r in analyzer.rules if r.kind in (KIND_LOG, KIND_STAT)]
        self.lines_total = 0
        self.entries_total = 0
        self.parse_fail = 0
        self.body_seen = 0
        self._body_checked = False

    # ------------------------------------------------------------------
    def poll_once(self) -> int:
        """读取一轮新增日志，返回处理的行数。"""
        processed = 0
        for src, tailer in self.tailers:
            lines, notes = tailer.read_lines(flush_partial=self.final_lines)
            for n in notes:
                self.log("WARN", n)
            hint = str(src.get("format", "")) if src.get("format") else ""
            for line in lines:
                processed += 1
                self.lines_total += 1
                entry = parse_line(line, format_hint=hint, max_body=self.max_line_bytes)
                if entry is None:
                    self.parse_fail += 1
                    continue
                if entry.body:
                    self.body_seen += 1
                self._handle_entry(entry, src)
        self._check_body_logging()
        return processed

    # ------------------------------------------------------------------
    def _handle_entry(self, entry: LogEntry, src: Dict) -> None:
        self.entries_total += 1
        # 来源标识：日志场景没有真实端口，用「来源IP -> 主机/路径」更直观
        where = f"{entry.host}/" if entry.host else ""
        flow_label = f"{entry.client_ip} -> {where}{entry.path.split('?', 1)[0][:70]}"

        # 1) 行为统计
        stat_signals: Dict[str, object] = {}
        if entry.is_script:
            stat_signals = self.stats.add(entry.client_ip, entry.path, entry.ts or time.time())

        # 2) 防守规则
        ctx = LogRuleContext(entry=entry, stats=stat_signals)
        findings: List[Tuple[Rule, int, str]] = []
        for rule in self.defense_rules:
            if rule.kind == KIND_STAT:
                key = str((rule.meta or {}).get("counter", ""))
                if key in stat_signals:
                    findings.append(
                        (rule, rule.score, f"{key} = {stat_signals[key]}（阈值 {rule.meta.get('threshold')}）")
                    )
                continue
            got = eval_log_rule(rule, ctx)
            if got:
                findings.append((rule, got[0], got[1]))

        # 3) 攻击工具特征（复用同一套规则引擎）
        engine_alerts = self._analyze_entry(entry, flow_label)

        # 4) 输出
        for rule, score, evidence in findings:
            self.alert_fn(
                Alert(
                    ts=entry.ts or time.time(),
                    severity=Severity.from_score(score),
                    tool=rule.tool,
                    title=rule.title,
                    rule_id=rule.id,
                    score=score,
                    flow=flow_label,
                    source=f"{LOG_SOURCE}({src.get('name', '')})",
                    evidence=evidence,
                    request=self._render(entry),
                    advice=rule.advice,
                    tags=rule.tags,
                )
            )
        for a in engine_alerts:
            self.alert_fn(a)

    def _analyze_entry(self, entry: LogEntry, flow_label: str) -> List[Alert]:
        txn = entry.to_transaction(max_body=self.max_line_bytes)
        key = FlowKey(entry.client_ip or "0.0.0.0", 0, entry.host or "localhost",
                     443 if entry.path.startswith("https") else 80)
        flow = Flow(key=key, source=LOG_SOURCE)
        flow.transactions = [txn]
        flow.first_ts = txn.ts
        flow.last_ts = txn.ts
        flow.c2s_bytes = len(txn.body)
        alerts = self.analyzer.analyze_flow(flow)
        for a in alerts:
            a.source = LOG_SOURCE
            # 用可读的「来源IP -> 主机+路径」替代 FlowKey 的 "ip:0 -> host:80"，
            # 因为日志场景没有真实端口，显示端口反而误导。
            a.flow = flow_label
        return alerts

    @staticmethod
    def _render(entry: LogEntry) -> str:
        lines = [
            f"{entry.method} {entry.path} {entry.protocol}",
            f"Host: {entry.host or '-'}",
            f"来源IP: {entry.client_ip}",
            f"User-Agent: {entry.user_agent or '-'}",
            f"Referer: {entry.referer or '-'}",
            f"状态码: {entry.status}  响应字节: {entry.bytes_sent}",
        ]
        if entry.body:
            lines.append("")
            lines.append("[请求体]")
            lines.append(entry.body[:1500])
        return "\n".join(lines)

    # ------------------------------------------------------------------
    def _check_body_logging(self) -> None:
        """
        检查日志里是否真的记录了请求体。

        这是防守能力的关键前提：没有请求体，冰蝎/哥斯拉这类加密马的
        载荷完全看不到，只能靠 URL/UA/状态码，检测能力大幅下降。
        """
        if self._body_checked or self.entries_total < 50:
            return
        self._body_checked = True
        if self.body_seen:
            self.log(
                "INFO",
                f"日志中已包含请求体（{self.body_seen}/{self.entries_total} 条带体），检测能力完整",
            )
            return
        rule = next((r for r in self.analyzer.rules if r.id == "DEF-050"), None)
        if rule is None:
            return
        self.alert_fn(
            Alert(
                ts=time.time(),
                severity=Severity.LOW,
                tool=rule.tool,
                title=rule.title,
                rule_id=rule.id,
                score=rule.score,
                flow=f"{len(self.tailers)} 个日志源",
                source=LOG_SOURCE,
                evidence=(
                    f"已解析 {self.entries_total} 条日志，其中带请求体的 0 条。"
                    "当前日志格式未记录 $request_body，加密型 webshell 的载荷无法被检测。"
                ),
                advice=rule.advice,
                tags=rule.tags,
            )
        )

    def summary(self) -> str:
        return (
            f"日志监控：读取 {self.lines_total} 行，解析成功 {self.entries_total} 行，"
            f"失败 {self.parse_fail} 行，其中带请求体 {self.body_seen} 行"
        )
