"""
Windows 专属监控：IIS 日志、Windows 事件日志、可疑落地目录。

三个组件：

1. **IIS 日志监控（IisLogMonitor）**
   IIS 的 W3C 扩展日志格式是「`#Fields:` 表头定义列，后续行按列取值」，
   与 nginx 完全不同，因此单独解析。关键字段：
       cs-uri-query（查询串）、cs-uri-stem（路径）、cs(User-Agent)、
       cs(Referer)、sc-status、cs-method
   注意：IIS **默认不记录请求体**（IIS 无法直接记录 POST body），
   所以 Windows 上的检测主力是：
       · 明文形的蚁剑/菜刀类（URL + UA + 查询串里的载荷）
       · 文件巡检（找 ASPX/PHP 马）
       · 事件日志（找落地后的横向移动）
   要记录请求体，需要装 IIS 的 "Advanced Logging" 扩展或在前端挂 nginx。
   本工具会如实提示这一能力缺口（DEF-050）。

2. **Windows 事件日志监控（EventLogMonitor）**
   用系统自带的 PowerShell `Get-WinEvent` 取安全事件，无需第三方模块：
       4624 登录成功 / 4625 登录失败（含爆破统计）
       4672 授予特殊权限 / 4720 创建用户 / 4732 加入管理员组
       7045 服务安装（攻击者常用手法）
       4104 PowerShell 脚本块（可选，日志量大时慎开）
       Security 日志需要管理员权限，程序会检测并给出明确提示。

3. **可疑落地目录扫描（WindowsDropScanner）**
   webshell 拿到执行权限后，通常会把工具下载到
   C:\\Windows\\Temp、C:\\Users\\Public、C:\\ProgramData、计划任务目录。
   本组件只报告「近期新增的可执行文件」，并带白名单过滤常见噪声
   （Defender 扫描临时文件、.NET 编译缓存等）。
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from .logs import LOG_SOURCE, LogEntry, decode_body, FileTailer
from .models import Alert, Severity, Rule
from .rules import KIND_STAT

WIN_SOURCE = "Windows事件日志"
WIN_FILE_SOURCE = "Windows落地文件"

# ---------------------------------------------------------------------------
# 1. IIS 日志
# ---------------------------------------------------------------------------
#: IIS 日志里常见但本工具不需要的列
_IGNORED_FIELDS = {"s-sitename", "s-computername", "s-ip", "s-port", "cs-version", "sc-substatus"}


#: 事件日志名白名单（log_name 会拼入 PowerShell 命令）
_SAFE_LOG_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _./-]{0,127}$")


@dataclass
class IisLogFormat:
    """一个 IIS 日志文件的 #Fields 表头。"""

    fields: List[str] = field(default_factory=list)
    path: str = ""

    @property
    def has_user_agent(self) -> bool:
        return "cs(user-agent)" in [f.lower() for f in self.fields]


def parse_iis_header(line: str) -> Optional[List[str]]:
    """解析 `#Fields: date time s-ip cs-method ...` 表头行。"""
    if not line.startswith("#Fields:"):
        return None
    raw = line[len("#Fields:") :].strip()
    if not raw:
        return None
    return [f.strip().lower() for f in raw.split() if f.strip()]


def parse_iis_line(line: str, fields: Sequence[str], max_body: int = 262144) -> Optional[LogEntry]:
    """
    按表头解析一行 IIS W3C 日志。

    W3C 格式用空格分隔、用 "-" 表示空值，字段名带括号（如 cs(User-Agent)）。
    """
    line = line.rstrip("\r\n")
    if not line or line.startswith("#"):
        return None
    if len(line) > max_body:
        line = line[:max_body]
    parts = line.split(" ")
    # IIS 也可能出现字段数不足的行（截断），按可用长度对齐
    if len(parts) < min(6, len(fields)):
        return None
    values: Dict[str, str] = {}
    for i, name in enumerate(fields):
        values[name] = parts[i] if i < len(parts) else "-"

    def get(*names: str) -> str:
        for n in names:
            v = values.get(n)
            if v and v != "-":
                return v
        return ""

    date = get("date")
    tm = get("time")
    ts = time.time()
    if date:
        import calendar

        # IIS 的 date/time 是服务器本地时间，没有显式时区，按本地时间解释
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                text = f"{date} {tm}" if "%H" in fmt and tm else date
                parsed = time.strptime(text.strip(), fmt)
                ts = time.mktime(parsed) if "%H" in fmt else calendar.timegm(parsed)
                break
            except (ValueError, OverflowError):
                continue

    uri_stem = get("cs-uri-stem") or "/"
    uri_query = get("cs-uri-query")
    path = f"{uri_stem}?{uri_query}" if uri_query else uri_stem
    # IIS 会把查询串里的特殊字符写成 %XX，解码后便于特征匹配
    if "%" in path:
        try:
            from urllib.parse import unquote

            path = unquote(path)
        except Exception:
            pass

    method = (get("cs-method") or "GET").upper()
    try:
        status = int(get("sc-status") or 0)
    except ValueError:
        status = 0
    try:
        nbytes = int(get("sc-bytes") or 0)
    except ValueError:
        nbytes = 0

    # 请求体：IIS 默认没有；若启用了 Advanced Logging 且自定义了列，
    # 这里尝试读取名为 cs-request-body / request-body 的列
    body = ""
    raw_body = get("cs-request-body", "request-body", "cs-body")
    if raw_body:
        body = decode_body(raw_body)

    return LogEntry(
        ts=ts,
        client_ip=get("c-ip", "cs-host") or "",
        method=method,
        path=path,
        protocol="HTTP/1.1",
        status=status,
        bytes_sent=nbytes,
        referer=get("cs(referer)", "cs-referer"),
        user_agent=get("cs(user-agent)", "cs-user-agent"),
        body=body,
        host=get("cs(host)", "cs-host"),
        format_name="iis_w3c",
        raw=line[:600],
    )


class IisLogMonitor:
    """
    IIS 日志监控。

    与 WebLogMonitor 的差别：
      * 每个日志文件有自己的 #Fields 表头，需要逐文件维护；
      * 需要扫描「目录 + 日期文件名」模式（IIS 按天滚动，文件名形如 u_ex260113.log）；
      * 复用同一个防守规则求值逻辑与检测引擎。
    """

    def __init__(
        self,
        alert_fn: Callable[[Alert], None],
        log_fn: Callable[[str, str], None],
        analyzer,
        sources: Sequence[Dict],
        from_beginning: bool = False,
        max_line_bytes: int = 262144,
    ):
        self.alert_fn = alert_fn
        self.log = log_fn
        self.analyzer = analyzer
        self.max_line_bytes = max_line_bytes
        self.sources = list(sources)
        self.from_beginning = bool(from_beginning)
        self._states: Dict[str, Tuple[FileTailer, Optional[List[str]], str]] = {}
        self.entries_total = 0
        self.parse_fail = 0
        self.body_seen = 0
        self.headers_seen = 0
        # 复用 Web 日志的行为统计与规则求值
        from .logs import ScriptStats

        self.stats = ScriptStats(window=60, threshold=30)
        self._defense_rules = [
            r for r in analyzer.rules if r.kind in ("log", "stat")
        ]
        self._body_warned = False
        self._initialized = False

    # ------------------------------------------------------------------
    def _targets(self) -> List[Tuple[str, str]]:
        """展开配置里的日志目标，返回 [(来源名, 文件路径), ...]。"""
        out: List[Tuple[str, str]] = []
        for src in self.sources:
            name = str(src.get("name", "iis"))
            path = str(src.get("path", ""))
            if not path:
                continue
            if os.path.isdir(path):
                patterns = src.get("patterns") or ["u_ex*.log", "*.log"]
                newest = src.get("newest_files", 3)
                found: List[str] = []
                for pat in patterns:
                    try:
                        found.extend(
                            os.path.join(path, f)
                            for f in os.listdir(path)
                            if _match_glob(f, pat)
                        )
                    except OSError:
                        continue
                found = sorted(set(found), key=lambda p: os.path.getmtime(p) if os.path.exists(p) else 0)
                for f in found[-int(newest):]:
                    out.append((name, f))
            elif os.path.isfile(path):
                out.append((name, path))
            else:
                self.log("WARN", f"IIS 日志路径不存在：{path}")
        return out

    def poll_once(self) -> int:
        processed = 0
        for name, path in self._targets():
            state = self._states.get(path)
            if state is None:
                tailer = FileTailer(path, from_beginning=self.from_beginning or self._initialized,
                                    max_line_bytes=self.max_line_bytes)
                state = (tailer, None, name)
                self._states[path] = state
            tailer, fields, src_name = state
            rotations = tailer.rotations
            lines, notes = tailer.read_lines()
            if fields is None or tailer.rotations != rotations:
                # 实时启动跳过历史记录，但仍需读取文件开头的 W3C 字段定义。
                fields = None
                try:
                    with open(path, "rb") as fh:
                        prefix = fh.read(65536).decode("utf-8-sig", "replace")
                    for header in prefix.splitlines():
                        if header.startswith("#Fields:"):
                            fields = parse_iis_header(header)
                            break
                except OSError as exc:
                    self.log("WARN", f"读取 IIS 日志表头失败：{exc}")
                self._states[path] = (tailer, fields, src_name)
            for n in notes:
                if "不存在" not in n:
                    self.log("WARN", n)
            for line in lines:
                processed += 1
                if line.startswith("#Fields:"):
                    fields = parse_iis_header(line)
                    self._states[path] = (tailer, fields, src_name)
                    self.headers_seen += 1
                    self.log("INFO", f"IIS 日志 {os.path.basename(path)} 表头字段：{', '.join(fields or [])}")
                    continue
                if line.startswith("#"):
                    continue
                if fields is None:
                    self.parse_fail += 1
                    continue
                entry = parse_iis_line(line, fields, self.max_line_bytes)
                if entry is None:
                    self.parse_fail += 1
                    continue
                self.entries_total += 1
                if entry.body:
                    self.body_seen += 1
                self._handle(entry, src_name)
        self._initialized = True
        self._warn_no_body()
        return processed

    # ------------------------------------------------------------------
    def _handle(self, entry: LogEntry, src_name: str) -> None:
        from .logs import LogRuleContext, eval_log_rule

        where = f"{entry.host}/" if entry.host else ""
        flow = f"{entry.client_ip} -> {where}{entry.path.split('?', 1)[0][:70]}"
        stat_signals: Dict[str, object] = {}
        if entry.is_script:
            stat_signals = self.stats.add(entry.client_ip, entry.path, entry.ts or time.time())

        ctx = LogRuleContext(entry=entry, stats=stat_signals)
        for rule in self._defense_rules:
            if rule.kind == KIND_STAT:
                key = str((rule.meta or {}).get("counter", ""))
                if key in stat_signals:
                    self.alert_fn(
                        Alert(
                            ts=entry.ts or time.time(),
                            severity=Severity.from_score(rule.score),
                            tool=rule.tool,
                            title=rule.title,
                            rule_id=rule.id,
                            score=rule.score,
                            flow=flow,
                            source=f"{LOG_SOURCE}(IIS/{src_name})",
                            evidence=f"{key} = {stat_signals[key]}（阈值 {rule.meta.get('threshold')}）",
                            request=_render_entry(entry),
                            advice=rule.advice,
                            tags=rule.tags,
                        )
                    )
                continue
            got = eval_log_rule(rule, ctx)
            if got:
                self.alert_fn(
                    Alert(
                        ts=entry.ts or time.time(),
                        severity=Severity.from_score(got[0]),
                        tool=rule.tool,
                        title=rule.title,
                        rule_id=rule.id,
                        score=got[0],
                        flow=flow,
                        source=f"{LOG_SOURCE}(IIS/{src_name})",
                        evidence=got[1],
                        request=_render_entry(entry),
                        advice=rule.advice,
                        tags=rule.tags,
                    )
                )

        # 工具特征（复用检测引擎）
        from .models import Flow, FlowKey

        txn = entry.to_transaction(max_body=self.max_line_bytes)
        key = FlowKey(entry.client_ip or "0.0.0.0", 0, entry.host or "localhost", 80)
        flow_obj = Flow(key=key, source="IIS日志")
        flow_obj.transactions = [txn]
        flow_obj.first_ts = flow_obj.last_ts = txn.ts
        flow_obj.c2s_bytes = len(txn.body)
        for a in self.analyzer.analyze_flow(flow_obj):
            a.source = "IIS日志"
            a.flow = flow
            self.alert_fn(a)

    def _warn_no_body(self) -> None:
        """IIS 默认不记录请求体，达到一定样本量后提示一次能力缺口。"""
        if self._body_warned or self.entries_total < 50:
            return
        self._body_warned = True
        if self.body_seen:
            self.log("INFO", f"IIS 日志中包含请求体（{self.body_seen} 条），检测能力完整")
            return
        rule = next((r for r in self.analyzer.rules if r.id == "DEF-050"), None)
        if rule is None:
            return
        self.alert_fn(
            Alert(
                ts=time.time(),
                severity=Severity.LOW,
                tool=rule.tool,
                title="IIS 日志不记录 POST 请求体，加密型 webshell 检测受限",
                rule_id=rule.id,
                score=rule.score,
                flow=f"IIS 日志源 {len(self._states)} 个",
                source=LOG_SOURCE,
                evidence=(
                    f"已解析 {self.entries_total} 条 IIS 日志，全部没有请求体 —— "
                    "IIS 原生日志格式不包含 POST body。因此冰蝎/哥斯拉这类"
                    "把载荷放在请求体里的加密马只能靠文件巡检与事件日志发现。"
                ),
                advice=(
                    "建议二选一：① 安装 IIS Advanced Logging 扩展并记录请求体字段；"
                    "② 在 IIS 前面挂一层 nginx 反向代理，由 nginx 记录 $request_body "
                    "并用本工具的 weblog 监控（Linux 版配置可参考 README 第 3 节）；"
                    "③ 至少确保文件巡检（filescan）与事件日志监控开启，它们不受此限制。"
                ),
                tags=rule.tags,
            )
        )

    def summary(self) -> str:
        return (
            f"IIS 日志监控：读取 {self.entries_total} 行（表头 {self.headers_seen} 个），"
            f"解析失败 {self.parse_fail} 行，带请求体 {self.body_seen} 行"
        )


def _match_glob(name: str, pattern: str) -> bool:
    import fnmatch

    return fnmatch.fnmatch(name.lower(), pattern.lower())


def _render_entry(entry: LogEntry) -> str:
    lines = [
        f"{entry.method} {entry.path} {entry.protocol}",
        f"Host: {entry.host or '-'}",
        f"来源IP: {entry.client_ip}",
        f"User-Agent: {entry.user_agent or '-'}",
        f"Referer: {entry.referer or '-'}",
        f"状态码: {entry.status}  响应字节: {entry.bytes_sent}",
    ]
    if entry.body:
        lines.extend(["", "[请求体]", entry.body[:1500]])
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 2. Windows 事件日志
# ---------------------------------------------------------------------------
#: 事件 ID -> (计数器名, 说明)
EVENT_MAP: Dict[int, Tuple[str, str]] = {
    4624: ("win_logon_success", "Windows 登录成功"),
    4625: ("win_logon_failure", "Windows 登录失败"),
    4634: ("win_logoff", "Windows 注销"),
    4648: ("win_explicit_logon", "显式凭据登录（runas / 计划任务常用）"),
    4672: ("win_special_privilege", "授予特殊权限（管理员级别登录）"),
    4720: ("win_user_created", "创建本地用户"),
    4722: ("win_user_enabled", "启用本地用户"),
    4724: ("win_password_reset", "重置用户密码"),
    4726: ("win_user_deleted", "删除本地用户"),
    4728: ("win_group_add", "加入全局安全组（可能提权）"),
    4732: ("win_group_add", "加入本地管理员组"),
    7045: ("win_service_install", "安装系统服务（攻击者常用持久化手法）"),
    4104: ("win_ps_scriptblock", "PowerShell 脚本块记录"),
}

#: 与防守规则对应的计数器 -> 规则 ID
COUNTER_RULES = {
    "win_logon_failure": "DEF-040",
    "win_logon_success": "DEF-041",
    "win_special_privilege": "DEF-042",
    "win_user_created": "DEF-042",
    "win_user_enabled": "DEF-042",
    "win_password_reset": "DEF-042",
    "win_user_deleted": "DEF-042",
    "win_group_add": "DEF-042",
    "win_service_install": "DEF-043",
}

#: 生成事件查询脚本（用 Get-WinEvent，Windows 自带，无需第三方模块）
_PS_SCRIPT = r'''
param(
  [string]$LogName = "Security",
  [int[]]$Ids = @(4624,4625),
  [int]$MaxEvents = 200,
  [long]$AfterRecordId = 0,
  [string]$AfterTime = ""
)
$ErrorActionPreference = "Stop"
try {
  $filter = @{ LogName = $LogName; Id = $Ids }
  if ($AfterTime -ne "") {
    $filter["StartTime"] = [datetime]::Parse($AfterTime)
  }
  $events = Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction Stop
} catch {
  [Console]::Error.WriteLine($_.Exception.Message)
  exit 3
}
foreach ($e in $events) {
  if ($e.RecordId -le $AfterRecordId) { continue }
  $xml = [xml]$e.ToXml()
  $data = @{}
  foreach ($d in $xml.Event.EventData.Data) {
    if ($d.Name) { $data[$d.Name] = [string]$d.'#text' }
  }
  $obj = [ordered]@{
    record_id = [long]$e.RecordId
    id        = [int]$e.Id
    time      = $e.TimeCreated.ToString("yyyy-MM-ddTHH:mm:ss")
    log       = $LogName
    level     = [int]$e.Level
    message   = $e.Message
    data      = $data
  }
  $obj | ConvertTo-Json -Compress -Depth 4
}
'''.strip()


@dataclass
class WinEvent:
    record_id: int
    event_id: int
    ts: float
    log: str
    message: str
    data: Dict[str, str]

    @property
    def account(self) -> str:
        return (
            self.data.get("TargetUserName")
            or self.data.get("SubjectUserName")
            or self.data.get("param1")
            or ""
        )

    @property
    def source_ip(self) -> str:
        return self.data.get("IpAddress") or self.data.get("WorkstationName") or ""

    @property
    def logon_type(self) -> str:
        return self.data.get("LogonType") or ""

    @property
    def service_name(self) -> str:
        return self.data.get("ServiceName") or self.data.get("param1") or ""

    @property
    def service_image(self) -> str:
        return self.data.get("ImagePath") or self.data.get("param2") or ""


class EventLogMonitor:
    """通过 PowerShell Get-WinEvent 采集 Windows 安全事件。"""

    def __init__(
        self,
        alert_fn: Callable[[Alert], None],
        log_fn: Callable[[str, str], None],
        rules: Sequence[Rule],
        log_name: str = "Security",
        event_ids: Sequence[int] = (),
        max_events: int = 200,
        state_dir: str = ".",
        fail_window: int = 300,
        fail_threshold: int = 10,
        trusted_ips: Sequence[str] = (),
        use_whoami_filter: bool = True,
    ):
        self.alert_fn = alert_fn
        self.log = log_fn
        self.rules = {r.id: r for r in rules}
        # log_name 会拼进 PowerShell -Command 字符串，必须限制字符集防止命令注入
        self._log_name_ok = bool(_SAFE_LOG_NAME.match(log_name or ""))
        self.log_name = log_name if self._log_name_ok else "Security"
        self.event_ids = [int(x) for x in (event_ids or sorted(EVENT_MAP))]
        self.max_events = int(max_events)
        self.state_dir = state_dir
        self.fail_window = fail_window
        self.fail_threshold = fail_threshold
        self.trusted_ips = set(trusted_ips or ())
        self._state_path = os.path.join(state_dir, f"win-event-state-{log_name.lower()}.json")
        self._record_id = 0
        self._after_time = ""
        self._availability: Optional[Tuple[bool, str]] = None
        self.events_total = 0
        self._fails: Dict[str, List[float]] = {}
        self._fired: Dict[str, float] = {}
        self._script_path = ""
        self._load_state()
        self._noise_accounts = _noise_accounts() if use_whoami_filter else set()

    # ------------------------------------------------------------------
    def _load_state(self) -> None:
        try:
            with open(self._state_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            self._record_id = int(data.get("record_id", 0))
            self._after_time = str(data.get("after_time", ""))
        except (OSError, ValueError, json.JSONDecodeError):
            self._record_id = 0
            self._after_time = ""

    def _save_state(self) -> None:
        try:
            os.makedirs(self.state_dir, exist_ok=True)
            with open(self._state_path, "w", encoding="utf-8") as fh:
                json.dump(
                    {"record_id": self._record_id, "after_time": self._after_time}, fh
                )
        except OSError:
            pass

    # ------------------------------------------------------------------
    def check_available(self) -> Tuple[bool, str]:
        """检测能否读取目标事件日志（Security 需要管理员）。"""
        if self._availability is not None:
            return self._availability
        if not self._log_name_ok:
            self._availability = (False, "配置中的 log_name 含非法字符，已拒绝执行（防止 PowerShell 注入）")
            return self._availability
        if os.name != "nt":
            self._availability = (False, "非 Windows 平台")
            return self._availability
        ps = _powershell_path()
        if not ps:
            self._availability = (False, "未找到 powershell.exe")
            return self._availability
        script = (
            f"try {{ Get-WinEvent -LogName '{self.log_name}' -MaxEvents 1 -ErrorAction Stop "
            f"| Out-Null; exit 0 }} catch {{ [Console]::Error.WriteLine($_.Exception.Message); exit 3 }}"
        )
        try:
            proc = subprocess.run(
                [ps, "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True, text=True, timeout=30,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            self._availability = (False, f"调用 PowerShell 失败：{exc}")
            return self._availability
        if proc.returncode == 0:
            self._availability = (True, "可读")
        else:
            err = (proc.stderr or "").strip().splitlines()
            reason = err[-1] if err else f"返回码 {proc.returncode}"
            if "unauthorized" in reason.lower() or "拒绝" in reason or "authorized" in reason.lower():
                self._availability = (
                    False,
                    f"无权读取 {self.log_name} 事件日志 —— 请以管理员身份运行（右键“以管理员身份运行”），"
                    "或把本监控的服务账号加入「事件日志读取者」组",
                )
            else:
                self._availability = (False, f"读取 {self.log_name} 失败：{reason}")
        return self._availability

    # ------------------------------------------------------------------
    def poll_once(self) -> int:
        ok, reason = self.check_available()
        if not ok:
            # 只在第一次提示，避免刷屏
            if not self._warned_unavailable():
                self.log("WARN", f"Windows 事件日志监控不可用：{reason}")
            return 0
        script_path = self._ensure_script()
        if not script_path:
            return 0
        ps = _powershell_path()
        assert ps is not None
        args = [
            ps, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
            "-File", script_path,
            "-LogName", self.log_name,
            "-Ids", ",".join(str(i) for i in self.event_ids),
            "-MaxEvents", str(self.max_events),
            "-AfterRecordId", str(self._record_id),
        ]
        if self._after_time:
            args += ["-AfterTime", self._after_time]
        try:
            proc = subprocess.run(args, capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.SubprocessError) as exc:
            self.log("ERROR", f"查询事件日志失败：{exc}")
            return 0
        if proc.returncode not in (0, 1):
            err = (proc.stderr or "").strip().splitlines()
            self.log("WARN", f"事件查询返回码 {proc.returncode}：{err[-1] if err else ''}")
            return 0
        count = 0
        for line in (proc.stdout or "").splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                continue
            ev = self._to_event(raw)
            if ev is None:
                continue
            count += 1
            self.events_total += 1
            if ev.record_id > self._record_id:
                self._record_id = ev.record_id
            self._after_time = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(ev.ts))
            self._handle(ev)
        if count:
            self._save_state()
        return count

    def _warned_unavailable(self) -> bool:
        if getattr(self, "_warned", False):
            return True
        self._warned = True
        return False

    @staticmethod
    def _to_event(raw: Dict) -> Optional[WinEvent]:
        try:
            ts_text = str(raw.get("time") or "")
            ts = time.mktime(time.strptime(ts_text, "%Y-%m-%dT%H:%M:%S")) if ts_text else time.time()
        except (ValueError, OverflowError):
            ts = time.time()
        data = raw.get("data") or {}
        if not isinstance(data, dict):
            data = {}
        try:
            return WinEvent(
                record_id=int(raw.get("record_id") or 0),
                event_id=int(raw.get("id") or 0),
                ts=ts,
                log=str(raw.get("log") or ""),
                message=str(raw.get("message") or "")[:2000],
                data={str(k): str(v) for k, v in data.items()},
            )
        except (TypeError, ValueError):
            return None

    # ------------------------------------------------------------------
    def _handle(self, ev: WinEvent) -> None:
        counter, note = EVENT_MAP.get(ev.event_id, ("", f"Windows 事件 {ev.event_id}"))
        source = f"{WIN_SOURCE}({self.log_name})"

        if ev.event_id == 4625:
            count = self._add_failure(ev.source_ip or ev.account)
            if count:
                rule = self.rules.get("DEF-040")
                if rule:
                    self._emit(
                        rule, source,
                        f"Windows 登录失败 {count} 次：来源 {ev.source_ip or '未知'}，"
                        f"目标账户 {ev.account or '未知'}，类型 {ev.logon_type or '?'}；"
                        f"原始消息：{ev.message[:200]}",
                        flow=f"{ev.source_ip or '未知'} -> {self.log_name}",
                    )
            return

        if ev.event_id == 4624:
            if ev.logon_type in ("5", "3") and not ev.account:
                return
            if ev.account.lower().endswith("$"):
                return      # 机器账户登录，噪声大
            if ev.account in self._noise_accounts and not ev.source_ip:
                return
            rule = self.rules.get("DEF-041")
            if rule:
                fails = len(self._fails.get(ev.source_ip, [])) if ev.source_ip else 0
                trusted = (ev.source_ip or "") in self.trusted_ips
                extra = ""
                if trusted:
                    extra = "（来源在信任列表内）"
                elif fails:
                    extra = f"（该来源此前有 {fails} 次失败，高度可疑）"
                self._emit(
                    rule, source,
                    f"Windows 登录成功：账户 {ev.account or '?'}，来源 {ev.source_ip or '本机'}，"
                    f"登录类型 {ev.logon_type or '?'}{extra}",
                    flow=f"{ev.source_ip or '本机'} -> {ev.account or '?'}",
                    score_bonus=25 if (fails and not trusted) else 0,
                )
            return

        # 7045 安装服务：单独规则
        if ev.event_id == 7045:
            rule = self.rules.get("DEF-043")
            if rule:
                self._emit(
                    rule, source,
                    f"新服务被安装：服务名 {ev.service_name or '?'}，"
                    f"可执行路径 {ev.service_image or '?'}；原始消息：{ev.message[:200]}",
                    flow=f"服务 {ev.service_name or '?'}",
                )
            return

        # 4104 PowerShell 脚本块：只报包含高危关键字的
        if ev.event_id == 4104:
            rule = self.rules.get("DEF-044")
            if rule and _dangerous_ps(ev.message):
                self._emit(
                    rule, source,
                    f"PowerShell 脚本块包含可疑内容：{ev.message[:300]}",
                    flow="PowerShell",
                )
            return

        # 其余归入提权/账号变更
        rid = COUNTER_RULES.get(counter)
        rule = self.rules.get(rid) if rid else None
        if rule:
            who = ev.account or "-"
            self._emit(
                rule, source,
                f"{note}：账户 {who}，来源 {ev.source_ip or '本机'}；原始消息：{ev.message[:220]}",
                flow=f"{who}",
            )

    def _add_failure(self, key: str) -> int:
        if not key:
            return 0
        now = time.time()
        hits = self._fails.setdefault(key, [])
        hits.append(now)
        cutoff = now - self.fail_window
        while hits and hits[0] < cutoff:
            hits.pop(0)
        if len(hits) >= self.fail_threshold and now - self._fired.get(key, 0) > 600:
            self._fired[key] = now
            return len(hits)
        return 0

    def _ensure_script(self) -> str:
        if self._script_path and os.path.isfile(self._script_path):
            return self._script_path
        try:
            fd, path = tempfile.mkstemp(prefix="ww-evt-", suffix=".ps1")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(_PS_SCRIPT)
            self._script_path = path
            return path
        except OSError as exc:
            self.log("ERROR", f"写入事件查询脚本失败：{exc}")
            return ""

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
        ok, reason = self.check_available()
        state = "可用" if ok else f"不可用（{reason}）"
        return f"Windows 事件日志：{state}，累计处理 {self.events_total} 个事件"


def _powershell_path() -> str:
    for name in ("powershell.exe", "powershell", "pwsh.exe", "pwsh"):
        found = shutil.which(name)
        if found:
            return found
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    fallback = os.path.join(system_root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
    return fallback if os.path.isfile(fallback) else ""


def _noise_accounts() -> set:
    """构建噪声账户名单（本机常见系统账户）。"""
    names = {
        "system", "local service", "network service", "anonymous logon", "dwm-1",
        "umfd-0", "umfd-1", "font driver host", "window manager",
    }
    for env in ("COMPUTERNAME", "USERNAME"):
        v = os.environ.get(env)
        if v:
            names.add(v.lower())
    return names


#: PowerShell 脚本块里的高危关键字
_PS_DANGER = re.compile(
    r"(?:IEX|Invoke-Expression|DownloadString|DownloadFile|WebClient|"
    r"FromBase64String|EncodedCommand|Reflection\.Assembly|"
    r"New-Object\s+Net\.WebClient|Start-BitsTransfer|"
    r"powershell\s+-enc|schtasks\s+/create|"
    r"Add-MpPreference|Set-MpPreference|MpPreference\s+-ExclusionPath|"
    r"New-LocalUser|Add-LocalGroupMember)",
    re.IGNORECASE,
)


def _dangerous_ps(message: str) -> bool:
    return bool(_PS_DANGER.search(message or ""))


# ---------------------------------------------------------------------------
# 3. Windows 落地目录扫描
# ---------------------------------------------------------------------------
#: 可执行/脚本扩展名
EXEC_EXTS = (
    ".exe", ".dll", ".sys", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".wsh", ".hta", ".msi", ".jar", ".py", ".pl",
)

#: 默认要盯的落地目录（攻击者最常在这里放工具）
DEFAULT_DROP_DIRS = (
    r"C:\Windows\Temp",
    r"C:\Users\Public",
    r"C:\ProgramData",
    r"C:\Windows\Tasks",
    r"C:\Windows\System32\Tasks",
    r"C:\Windows\System32\spool\drivers\color",
    r"C:\Users\Public\Documents",
    r"C:\Users\Public\Downloads",
)

#: 噪声文件名的正则（系统/杀软/编译器的正常行为）
DROP_NOISE = re.compile(
    r"(?:MPCache|MpCmdRun|\.tmp$|~|^\{[0-9A-Fa-f-]{36}\}|"
    r"Microsoft\.NET|clr|ngen|\.etl$|\.log$|\.dat$|"
    r"Defender|Windows Defender|diagtrack|Cbs|"
    r"CrashpadMetrics|chrome_|EDR|Sophos|Sentinel)",
    re.IGNORECASE,
)


class WindowsDropScanner:
    """
    扫描常见「工具落地目录」里近期新增的可执行文件。

    只报告 mtime 在 lookback_days 天内的新文件，并带噪声过滤，
    避免把系统日常行为报成攻击。
    """

    def __init__(
        self,
        alert_fn: Callable[[Alert], None],
        log_fn: Callable[[str, str], None],
        rules: Sequence[Rule],
        directories: Sequence[str] = (),
        lookback_days: float = 7.0,
        max_files: int = 20000,
        state_dir: str = ".",
    ):
        self.alert_fn = alert_fn
        self.log = log_fn
        self.rules = {r.id: r for r in rules}
        self.directories = list(directories) or list(DEFAULT_DROP_DIRS)
        self.lookback = float(lookback_days) * 86400
        self.max_files = int(max_files)
        self.state_dir = state_dir
        self.state_path = os.path.join(state_dir, "windows-drop-seen.json")
        self._seen: Dict[str, float] = {}
        self._load_seen()
        self.files_reported = 0
        self._first_run = not self._seen

    def _load_seen(self) -> None:
        try:
            with open(self.state_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                self._seen = {str(k): float(v) for k, v in data.items()}
        except (OSError, ValueError, json.JSONDecodeError, TypeError):
            self._seen = {}

    def _save_seen(self) -> None:
        try:
            os.makedirs(self.state_dir, exist_ok=True)
            # 只保留最近 3 万条，避免状态文件无限增长
            if len(self._seen) > 30000:
                items = sorted(self._seen.items(), key=lambda x: -x[1])[:30000]
                self._seen = dict(items)
            with open(self.state_path, "w", encoding="utf-8") as fh:
                json.dump(self._seen, fh)
        except OSError:
            pass

    def scan_once(self) -> int:
        if os.name != "nt":
            return 0
        cutoff = time.time() - self.lookback
        found = 0
        scanned = 0
        for root in self.directories:
            if not os.path.isdir(root):
                continue
            for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: None):
                # 一些目录会有海量文件，限制规模
                if scanned > self.max_files:
                    break
                for name in filenames:
                    scanned += 1
                    low = name.lower()
                    if not low.endswith(EXEC_EXTS):
                        continue
                    if DROP_NOISE.search(name):
                        continue
                    full = os.path.join(dirpath, name)
                    try:
                        st = os.stat(full)
                    except (OSError, PermissionError):
                        continue
                    if st.st_mtime < cutoff:
                        continue
                    if self._seen.get(full) == st.st_mtime:
                        continue
                    self._seen[full] = st.st_mtime
                    # 首次运行只建状态，避免把历史文件全部报出来
                    if self._first_run:
                        continue
                    found += 1
                    self._report(full, st)
        if self._first_run:
            self._first_run = False
            self.log(
                "INFO",
                f"Windows 落地目录首次扫描完成，已记录 {len(self._seen)} 个近期可执行文件作为基线"
                "（本次不告警，之后的新增文件会告警）",
            )
        self._save_seen()
        self.files_reported += found
        return found

    def _report(self, path: str, st) -> None:
        rule = self.rules.get("DEF-037")
        if rule is None:
            return
        digest = ""
        try:
            if st.st_size <= 32 * 1024 * 1024:
                h = hashlib.sha256()
                with open(path, "rb") as fh:
                    for chunk in iter(lambda: fh.read(65536), b""):
                        h.update(chunk)
                digest = h.hexdigest()
        except (OSError, PermissionError):
            digest = ""
        owner = ""
        try:
            self._owner(path)
        except Exception:
            pass
        alert = Alert(
            ts=time.time(),
            severity=Severity.from_score(rule.score),
            tool=rule.tool,
            title=rule.title,
            rule_id=rule.id,
            score=rule.score,
            flow=path,
            source=WIN_FILE_SOURCE,
            evidence=(
                f"新增可执行文件：{path}（{st.st_size} 字节，"
                f"修改时间 {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(st.st_mtime))}）"
                + (f"，sha256={digest}" if digest else "")
            ),
            advice=rule.advice,
            tags=rule.tags,
        )
        self.alert_fn(alert)

    @staticmethod
    def _owner(path: str) -> str:
        return ""

    def summary(self) -> str:
        return (
            f"Windows 落地目录：监控 {len([d for d in self.directories if os.path.isdir(d)])} 个目录，"
            f"已记录 {len(self._seen)} 个文件，累计告警 {self.files_reported}"
        )
