"""
Web 目录文件巡检（防守端第二支柱）。

为什么需要它：日志只能证明「有人调用了某个脚本」，
而文件巡检能证明「服务器上真的多了/改了什么马」，
两者交叉确认基本可以排除误报。

做三件事：
    1. 发现新增 / 被修改的脚本文件（与基线比对）
    2. 对脚本内容做 webshell 特征扫描（一句话马、编码马、内存马片段）
    3. 报告危险权限（777、属主为 Web 进程用户），这是加固建议

基线存放于 state_dir/filescan-baseline.json，改完代码后可用
`wsp filescan --update-baseline` 重建，避免正常发布一直告警。
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, Tuple

try:  # pwd 仅存在于 Unix；Windows 上允许导入以便本地开发调试
    import pwd
except ImportError:  # pragma: no cover
    pwd = None  # type: ignore[assignment]

from .models import Alert, Severity, Rule

FILE_SOURCE = "文件巡检"

#: Web 进程常见属主（脚本属主是这些账号说明可被 Web 直接改写）
WEB_USERS = ("www-data", "nginx", "apache", "httpd", "tomcat", "nobody", "www", "lighttpd")

#: 静态特征：(名称, 正则, 分值权重, 说明)
SIGNATURES: List[Tuple[str, str, int, str]] = [
    # --- 一句话马：把外部输入直接交给执行函数 -----------------------------
    (
        "eval_input",
        r"@?\s*(?:eval|assert|create_function)\s*\(\s*\$_(?:POST|GET|REQUEST|COOKIE|SERVER)\b"
        r"|@?\s*(?:eval|assert)\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13|urldecode)\s*\(",
        60,
        "动态执行函数直接消费外部输入（典型一句话木马）",
    ),
    (
        "variable_function",
        r"\$[A-Za-z_]\w*\s*\(\s*\$_(?:POST|GET|REQUEST|COOKIE)\b"
        r"|\$_(?:POST|GET|REQUEST)\s*\[\s*['\"]?[A-Za-z_]\w*['\"]?\s*\]\s*\(",
        55,
        "变量函数调用外部输入（PHP 回调型木马常用写法）",
    ),
    (
        "system_chain",
        r"\b(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(\s*\$"
        r"|\b(?:system|shell_exec|passthru)\s*\(\s*\$_(?:POST|GET|REQUEST)",
        55,
        "命令执行函数接收变量参数",
    ),
    # --- 编码型/加密型马 ---------------------------------------------------
    (
        "encoded_payload",
        r"(?:eval|assert|create_function)\s*\(\s*(?:base64_decode|gzinflate|gzuncompress)"
        r"\s*\(\s*['\"][A-Za-z0-9+/=]{120,}",
        60,
        "大段 Base64/GZIP 数据解码后执行（混淆马）",
    ),
    (
        "hex_payload",
        r"(?:eval|assert)\s*\(\s*(?:chr|\\x[0-9a-f]{2})",
        50,
        "chr()/\\xNN 拼接后执行（绕过关键字检测）",
    ),
    (
        "behinder_php",
        r"openssl_decrypt\s*\(|AES128|e45e329feb5d925b|session_start\s*\(\s*\)\s*;\s*\$key",
        70,
        "PHP 加密马结构（冰蝎系：AES 解密后执行）",
    ),
    (
        "behinder_jsp",
        r"defineClass\s*\(|ClassLoader|javax\.crypto\.spec|Cipher\.getInstance\s*\(\s*[\"']AES",
        70,
        "JSP 加密马结构（ClassLoader 动态加载 / AES 解密）",
    ),
    # --- .NET / ASPX 一句话与加密马（Windows/IIS 场景必备）-----------------
    (
        "aspx_eval_chain",
        r"(?:Request|HttpContext\.Current\.Request)\s*(?:\.Item|\[|\.Form|\.QueryString)"
        r"[^\n]{0,60}(?:\.ToString\s*\(\s*\)\s*)?[\s\S]{0,40}?"
        r"(?:Assembly\.Load|CreateInstance|Invoke\s*\(|CompileAssemblyFromSource|"
        r"Process\.Start|Eval\s*\()",
        65,
        "ASPX 把请求参数交给动态编译/反射执行（一句话马）",
    ),
    (
        "aspx_eval_alias",
        r"\bEval\s*\(\s*Request|Execute\s*\(\s*Request|"
        r"Server\.CreateObject\s*\(\s*[\"']WScript\.Shell",
        60,
        "ASPX/ASP 直接执行请求内容或创建 WScript.Shell",
    ),
    (
        "aspx_deserialize",
        r"LosFormatter|ObjectStateFormatter|BinaryFormatter|"
        r"TypeConfuseDelegate|ObjectDataProvider|"
        r"System\.Web\.UI\.ObjectStateFormatter",
        60,
        ".NET 反序列化 gadget 特征（ViewState 反序列化利用链）",
    ),
    (
        "csharp_compile",
        r"CSharpCodeProvider|CompileAssemblyFromSource|"
        r"Microsoft\.CSharp\.CSharpCodeProvider|Assembly\.Load\s*\(",
        60,
        ".NET 动态编译执行（ASPX 内存马常见手法）",
    ),
    (
        "wscript_shell",
        r"WScript\.Shell|Shell\.Application|CreateObject\s*\(\s*[\"'](?:WScript|Shell)",
        55,
        "Windows 脚本宿主调用（ASP 命令执行）",
    ),
    (
        "godzilla_marker",
        r"javax\.crypto\.Cipher|java\.lang\.reflect|Class\.forName|"
        r"System\.Reflection|Assembly\.Load|CSharpCodeProvider",
        55,
        "哥斯拉系反射/动态编译特征",
    ),
    (
        "assert_post",
        r"assert\s*\(\s*\$_(?:POST|REQUEST|GET)|@assert\s*\(",
        55,
        "assert 直接接外部输入",
    ),
    (
        "dynamic_call",
        # 形如 $g = "ev"."al"; $g($payload); 的动态函数调用（分段拼接 + 变量函数）
        r"\$[A-Za-z_]\w*\s*\(\s*\$[A-Za-z_]\w*\s*\)"
        r"|['\"]\s*\.\s*['\"]\w*['\"]\s*\.\s*['\"]",   # "ev" . "al"
        45,
        "变量函数调用/字符串分段拼接（拆分关键字绕过 WAF 的常见写法）",
    ),
    # --- 常见 webshell 框架/马场残留 --------------------------------------
    (
        "known_family",
        r"eval\s*\(\s*\$_(?:POST|GET|REQUEST)\s*\[['\"]?(?:cmd|pass|shell|x|z0|z1|c)\b"
        r"|@?\$_(?:POST|GET|REQUEST)\s*\[['\"]?(?:cmd|pass|shell|z0|z1)['\"]?\s*\]\s*;",
        45,
        "参数名命中常见 webshell 约定（cmd/pass/shell/z0/z1）",
    ),
    # --- 内存马 / 反序列化 -------------------------------------------------
    (
        "java_memshell",
        r"javax\.servlet\.(?:Servlet|Filter)|jakarta\.servlet\.|"
        r"addServlet|registerServlet|StandardContext|"
        r"java\.io\.ObjectInputStream|readObject\s*\(",
        50,
        "Java 内存马 / 反序列化入口特征",
    ),
    (
        "php_disable_functions_bypass",
        r"ini_set\s*\(\s*[\"']disable_functions[\"']|"
        r"\$GLOBALS\s*\[[\"']?(?:func|function)[\"']?\]|"
        r"array_map\s*\(\s*['\"]?(?:assert|system|exec)",
        45,
        "绕过 disable_functions 的常见手法",
    ),
    # --- 后门式文件操作 ---------------------------------------------------
    (
        "file_write_backdoor",
        r"(?:file_put_contents|fwrite|fputs)\s*\(\s*\$_(?:POST|GET|REQUEST)"
        r"|move_uploaded_file\s*\(",
        45,
        "把外部输入写入文件（上传型后门）",
    ),
]


def _compile_signatures():
    """预编译特征正则（模块加载时一次）；非法正则被跳过，行为与逐次 re.search 相同。"""
    out = []
    for name, pattern, score, note in SIGNATURES:
        try:
            out.append((name, re.compile(pattern, re.IGNORECASE), score, note))
        except re.error:
            continue
    return out


_COMPILED_SIGNATURES = _compile_signatures()

#: 命中这些特征的名，进一步判定为「强特征」组合
STRONG_SIGS = {
    "eval_input",
    "encoded_payload",
    "behinder_php",
    "behinder_jsp",
    "variable_function",
    "assert_post",
    "dynamic_call",
    "aspx_eval_chain",
    "aspx_eval_alias",
    "aspx_deserialize",
    "csharp_compile",
    "wscript_shell",
}

#: 这些扩展名出现在 Web 目录说明有人在服务器上放了可执行的脚本语言文件，
#: 通常与「上传 webshell 后用系统命令执行」的攻击链有关。
NON_WEB_SCRIPT_EXTS = (".py", ".pl", ".sh", ".cgi", ".war")

#: Windows/IIS 下同样算「可执行脚本」的扩展名（用于文件类型异常判断）
WINDOWS_SCRIPT_EXTS = (".aspx", ".ashx", ".asmx", ".asp", ".cer", ".asa", ".cdx", ".htr")

#:  IIS 下典型的「上传目录」——这些目录里出现脚本文件本身就值得警惕
UPLOAD_DIR_HINTS = (
    "upload", "uploads", "attachment", "attachments", "file", "files",
    "media", "images", "img", "temp", "tmp", "cache", "data",
)

#: Web 配置文件：被新增/修改都值得警惕（可被用于持久化或提权）
WEB_CONFIG_NAMES = ("web.config", ".user.ini", ".htaccess", ".htpasswd", "php.ini")


@dataclass
class FileFinding:
    signature: str
    score: int
    note: str
    snippet: str


@dataclass
class FileRecord:
    path: str
    size: int
    mtime: float
    mode: int
    owner: str
    digest: str = ""


@dataclass
class ScanResult:
    scanned: int = 0
    new_files: List[FileRecord] = field(default_factory=list)
    modified_files: List[FileRecord] = field(default_factory=list)
    suspicious: List[Tuple[FileRecord, List[FileFinding]]] = field(default_factory=list)
    bad_modes: List[FileRecord] = field(default_factory=list)
    odd_scripts: List[FileRecord] = field(default_factory=list)
    upload_scripts: List[FileRecord] = field(default_factory=list)
    web_configs: List[FileRecord] = field(default_factory=list)
    unreadable: List[str] = field(default_factory=list)
    baseline_created: bool = False
    duration: float = 0.0

    def summary(self) -> str:
        return (
            f"扫描 {self.scanned} 个脚本文件；新增 {len(self.new_files)}，"
            f"修改 {len(self.modified_files)}，可疑内容 {len(self.suspicious)}，"
            f"权限异常 {len(self.bad_modes)}，类型异常 {len(self.odd_scripts)}，"
            f"上传目录脚本 {len(self.upload_scripts)}，Web配置 {len(self.web_configs)}，"
            f"不可读 {len(self.unreadable)}"
        )


class FileScanner:
    """Web 目录巡检器。"""

    def __init__(
        self,
        alert_fn: Callable[[Alert], None],
        log_fn: Callable[[str, str], None],
        rules: Sequence[Rule],
        webroots: Sequence[str],
        script_extensions: Sequence[str],
        state_dir: str,
        exclude_dirs: Sequence[str] = (),
        max_file_bytes: int = 2097152,
        follow_symlinks: bool = False,
    ):
        self.alert_fn = alert_fn
        self.log = log_fn
        self.rules = list(rules)
        self.webroots = [os.path.abspath(p) for p in webroots]
        self.extensions = tuple(e.lower() for e in script_extensions)
        self.exclude_dirs = tuple(os.path.abspath(d) if os.path.isabs(d) else d for d in exclude_dirs)
        self.max_file_bytes = max_file_bytes
        self.follow_symlinks = follow_symlinks
        self.baseline_path = os.path.join(self._pick_state_dir(state_dir), "filescan-baseline.json")
        self.baseline: Dict[str, dict] = {}
        self.baseline_missing = True
        self._load_baseline()
        self._rule = {r.id: r for r in self.rules}

    # ------------------------------------------------------------------
    def _pick_state_dir(self, state_dir: str) -> str:
        """
        选择可写的状态目录。

        配置里默认是 /var/lib/webshell-watch；如果该路径不可写
        （非 root 运行、或本地开发调试），退回到用户目录，避免因为
        写不了基线而让整个巡检失败。
        """
        candidates = [
            state_dir,
            os.path.join(os.path.expanduser("~"), ".webshell-watch"),
            os.path.join(os.getcwd(), ".webshell-watch-state"),
        ]
        for cand in candidates:
            if not cand:
                continue
            try:
                os.makedirs(cand, exist_ok=True)
                probe = os.path.join(cand, ".write-test")
                with open(probe, "w", encoding="utf-8") as fh:
                    fh.write("ok")
                os.unlink(probe)
                if cand != state_dir:
                    self.log(
                        "WARN",
                        f"状态目录 {state_dir} 不可写，已改用 {cand}（文件基线将保存在这里）",
                    )
                return cand
            except (OSError, PermissionError):
                continue
        return state_dir

    # ------------------------------------------------------------------
    def _load_baseline(self) -> None:
        try:
            with open(self.baseline_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                self.baseline = data.get("files", {}) or {}
                self.baseline_missing = False
        except (OSError, json.JSONDecodeError):
            self.baseline = {}
            self.baseline_missing = True

    def save_baseline(self, records: Dict[str, FileRecord]) -> bool:
        try:
            os.makedirs(os.path.dirname(self.baseline_path), exist_ok=True)
            payload = {
                "generated_at": time.time(),
                "generated_at_str": time.strftime("%Y-%m-%d %H:%M:%S"),
                "roots": self.webroots,
                "files": {
                    p: {
                        "size": r.size,
                        "mtime": r.mtime,
                        "mode": r.mode,
                        "owner": r.owner,
                        "digest": r.digest,
                    }
                    for p, r in records.items()
                },
            }
            tmp = self.baseline_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, ensure_ascii=False, indent=1)
            os.replace(tmp, self.baseline_path)
            return True
        except OSError as exc:
            self.log("ERROR", f"写入文件基线失败（{self.baseline_path}）：{exc}")
            return False

    def update_baseline(self) -> ScanResult:
        """重建基线（不告警）。"""
        result = ScanResult()
        records = self._walk(result)
        result.scanned = len(records)
        if self.save_baseline(records):
            self.baseline = {p: vars(r) for p, r in records.items()}
            self.baseline_missing = False
            result.baseline_created = True
            self.log("INFO", f"已重建文件基线：{len(records)} 个脚本文件 -> {self.baseline_path}")
        return result

    # ------------------------------------------------------------------
    def scan(self, update_baseline: bool = False) -> ScanResult:
        """执行一次巡检。"""
        t0 = time.time()
        result = ScanResult()
        records = self._walk(result)
        result.scanned = len(records)

        first_run = self.baseline_missing

        for path, rec in records.items():
            old = self.baseline.get(path)
            modified = False

            # 1) 新增 / 修改
            if old is None and not first_run:
                result.new_files.append(rec)
            elif old is not None:
                if (
                    int(old.get("size", -1)) != rec.size
                    or float(old.get("mtime", -1)) != rec.mtime
                    or (old.get("digest") and old["digest"] != rec.digest)
                ):
                    result.modified_files.append(rec)
                    modified = True

            # 2) 权限：只报真正能被 Web 进程改写的情况
            #    a. 全局可写（其他用户可写）
            #    b. 组可写且属主是 Web 进程用户（Web 进程可改写脚本 = 可植入后门）
            #    注意：Windows 没有 Unix 权限位，python 的 st_mode 会返回 0o777，
            #    直接判断会把所有文件都误报成 777，因此仅在类 Unix 平台启用。
            if os.name != "nt":
                if rec.mode & stat.S_IWOTH:
                    result.bad_modes.append(rec)
                elif rec.owner in WEB_USERS and (rec.mode & stat.S_IWGRP):
                    result.bad_modes.append(rec)

            # 2b) 类型异常：Web 目录里出现 .py/.pl/.sh/.cgi/.war 等可执行脚本
            if rec.path.lower().endswith(NON_WEB_SCRIPT_EXTS):
                result.odd_scripts.append(rec)

            # 2c) 上传/数据目录里出现脚本文件（Windows/IIS 与 Linux 都适用）
            low = rec.path.replace("\\", "/").lower()
            if any(f"/{hint}/" in low or f"/{hint}s/" in low for hint in UPLOAD_DIR_HINTS):
                if rec.path.lower().endswith(self.extensions):
                    result.upload_scripts.append(rec)

            # 2d) Web 配置文件（web.config/.user.ini/.htaccess）被新增或修改
            base = os.path.basename(rec.path).lower()
            if base in ("web.config", ".user.ini", ".htaccess", ".htpasswd", "php.ini"):
                if not first_run and (old is None or modified):
                    result.web_configs.append(rec)
                elif first_run:
                    result.web_configs.append(rec)

            # 3) 内容特征扫描（新增/修改/首次巡检的文件优先）
            if first_run or old is None or modified:
                findings = self.scan_content(path)
                if findings:
                    result.suspicious.append((rec, findings))

        result.duration = time.time() - t0
        # 告警仍需要旧基线；成功持久化后再切换内存状态。
        self._emit(result, first_run)
        if update_baseline or first_run:
            if self.save_baseline(records):
                self.baseline = {p: vars(r) for p, r in records.items()}
                self.baseline_missing = False
                result.baseline_created = first_run
        return result

    # ------------------------------------------------------------------
    def _walk(self, result: ScanResult) -> Dict[str, FileRecord]:
        records: Dict[str, FileRecord] = {}
        visited_dirs = 0
        for root in self.webroots:
            if not os.path.isdir(root):
                self.log("WARN", f"Web 目录不存在，已跳过：{root}")
                continue
            for dirpath, dirnames, filenames in os.walk(
                root, followlinks=self.follow_symlinks, onerror=lambda e: None
            ):
                visited_dirs += 1
                dirnames[:] = [
                    d
                    for d in dirnames
                    if not self._excluded(os.path.join(dirpath, d))
                    and not d.startswith(".git")
                ]
                for name in filenames:
                    low = name.lower()
                    if not (low.endswith(self.extensions) or low in WEB_CONFIG_NAMES):
                        continue
                    full = os.path.join(dirpath, name)
                    if self._excluded(full):
                        continue
                    rec = self._stat_file(full, result)
                    if rec:
                        records[full] = rec
        self.log("INFO", f"文件巡检遍历 {visited_dirs} 个目录，收集 {len(records)} 个脚本文件")
        return records

    def _excluded(self, path: str) -> bool:
        for ex in self.exclude_dirs:
            if ex and (path == ex or path.startswith(ex + os.sep) or (not os.path.isabs(ex) and ex in path)):
                return True
        return False

    def _stat_file(self, path: str, result: ScanResult) -> Optional[FileRecord]:
        try:
            # 不跟随符号链接时用 lstat，避免以 root 身份读取/哈希 Web 目录外的文件
            st = os.stat(path) if self.follow_symlinks else os.lstat(path)
        except (OSError, PermissionError):
            result.unreadable.append(path)
            return None
        if not stat.S_ISREG(st.st_mode):
            # FIFO/设备/符号链接等：open() 可能永久阻塞巡检线程，直接跳过
            return None
        owner = ""
        try:
            if pwd is not None:
                owner = pwd.getpwuid(st.st_uid).pw_name
            else:  # pragma: no cover - Windows 调试路径
                owner = str(st.st_uid)
        except (KeyError, OSError):
            owner = str(st.st_uid)
        digest = ""
        if st.st_size <= self.max_file_bytes:
            digest = self._digest(path)
        # Windows 上 st_mode 不反映真实权限，统一记为 0o644 以免误报
        mode = (st.st_mode & 0o777) if os.name != "nt" else 0o644
        return FileRecord(
            path=path,
            size=st.st_size,
            mtime=st.st_mtime,
            mode=mode,
            owner=owner,
            digest=digest,
        )

    @staticmethod
    def _digest(path: str) -> str:
        h = hashlib.sha256()
        try:
            with open(path, "rb") as fh:
                while True:
                    chunk = fh.read(65536)
                    if not chunk:
                        break
                    h.update(chunk)
        except (OSError, PermissionError):
            return ""
        return h.hexdigest()

    # ------------------------------------------------------------------
    def scan_content(self, path: str) -> List[FileFinding]:
        """对单个脚本文件做 webshell 特征扫描。"""
        try:
            st = os.stat(path) if self.follow_symlinks else os.lstat(path)
            if not stat.S_ISREG(st.st_mode):
                return []
            # 始终限长读取：文件在 stat 之后被追加写入也不会读入超大内容
            with open(path, "rb") as fh:
                data = fh.read(self.max_file_bytes)
        except (OSError, PermissionError):
            return []
        text = data.decode("utf-8", "ignore")
        if not text:
            text = data.decode("latin-1", "ignore")
        findings: List[FileFinding] = []
        seen: set = set()
        for name, regex, score, note in _COMPILED_SIGNATURES:
            m = regex.search(text)
            if not m:
                continue
            seen.add(name)
            start = max(0, m.start() - 40)
            snippet = text[start : m.start() + 120].replace("\n", " ")[:200]
            findings.append(FileFinding(signature=name, score=score, note=note, snippet=snippet))
        # 组合加成：多个独立特征命中，或强特征 + 编码数据
        strong = [f for f in findings if f.signature in STRONG_SIGS]
        if len(findings) >= 2:
            findings.append(
                FileFinding(
                    signature="multi_signal",
                    score=15,
                    note=f"同一文件命中 {len(findings)} 个独立特征：" + "、".join(sorted(seen)),
                    snippet="",
                )
            )
        if strong and re.search(r"[A-Za-z0-9+/=]{200,}", text):
            findings.append(
                FileFinding(
                    signature="big_encoded_blob",
                    score=15,
                    note="文件中存在 200 字符以上的连续 Base64 数据块",
                    snippet="",
                )
            )
        return findings

    # ------------------------------------------------------------------
    def _emit(self, result: ScanResult, first_run: bool) -> None:
        def rule(rid: str) -> Optional[Rule]:
            return self._rule.get(rid)

        # 新增脚本
        r_new = rule("DEF-030")
        content_findings = {rec.path: findings for rec, findings in result.suspicious}
        for rec in result.new_files:
            findings = content_findings.get(rec.path, [])
            extra = ""
            if findings:
                extra = "；内容同时命中：" + "、".join(f.note for f in findings[:3])
            self._alert(
                r_new,
                f"新增脚本文件 {rec.path}（{rec.size} 字节，属主 {rec.owner}，"
                f"权限 {rec.mode:o}，修改时间 {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(rec.mtime))}）{extra}",
                flow=rec.path,
            )
        # 修改
        r_mod = rule("DEF-034")
        for rec in result.modified_files:
            old = self.baseline.get(rec.path, {})
            self._alert(
                r_mod,
                f"脚本文件被修改 {rec.path}（大小 {old.get('size')} -> {rec.size}，"
                f"mtime {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(rec.mtime))}）",
                flow=rec.path,
            )
        # 内容特征
        r_sig = rule("DEF-031")
        r_obf = rule("DEF-032")
        for rec, findings in result.suspicious:
            total = sum(f.score for f in findings)
            strong = any(f.signature in STRONG_SIGS for f in findings)
            # 强特征命中，或累计分值已足够高 -> 判定为「明确的一句话/加密马」
            target = r_sig if (strong or total >= 55) else r_obf
            detail = " || ".join(f"[{f.signature}] {f.note}: {f.snippet}" for f in findings[:4])
            self._alert(
                target,
                f"{rec.path} 命中 {len(findings)} 个特征，累计 {total} 分 —— {detail}",
                flow=rec.path,
                extra_score=min(total, 40),
                response=f"文件哈希 sha256={rec.digest}" if rec.digest else "",
            )
        # 权限
        r_mode = rule("DEF-033")
        for rec in result.bad_modes[:50]:
            self._alert(
                r_mode,
                f"{rec.path} 权限 {rec.mode:o}，属主 {rec.owner}"
                + ("（全局可写，任何用户都能改）" if rec.mode & stat.S_IWOTH
                   else "（属主为 Web 进程用户且组可写，Web 进程可改写）"),
                flow=rec.path,
            )
        # 类型异常
        r_odd = rule("DEF-035")
        for rec in result.odd_scripts[:50]:
            self._alert(
                r_odd,
                f"Web 目录下存在非 Web 脚本：{rec.path}（{rec.size} 字节，属主 {rec.owner}）",
                flow=rec.path,
            )
        # 上传目录里的脚本
        r_up = rule("DEF-036")
        for rec in result.upload_scripts[:50]:
            self._alert(
                r_up,
                f"上传/数据目录中出现脚本文件：{rec.path}"
                f"（{rec.size} 字节，属主 {rec.owner}，修改时间 "
                f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(rec.mtime))}）",
                flow=rec.path,
            )
        # Web 配置文件新增/修改
        r_cfg = rule("DEF-038")
        for rec in result.web_configs[:50]:
            old = self.baseline.get(rec.path)
            state = "新增" if old is None else "内容被修改"
            self._alert(
                r_cfg,
                f"Web 配置文件{state}：{rec.path}（{rec.size} 字节，修改时间 "
                f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(rec.mtime))}）",
                flow=rec.path,
            )
        # 不可读 -> 能力基线提醒
        if result.unreadable:
            r_perm = rule("DEF-051")
            self._alert(
                r_perm,
                f"有 {len(result.unreadable)} 个脚本文件无法读取，例如："
                + "、".join(result.unreadable[:5]),
                flow="文件巡检",
            )
        if first_run:
            self.log(
                "INFO",
                "首次巡检完成（本次只报告可疑内容，不报告新增/修改）。"
                "正常发布代码后用 `wsp filescan --update-baseline` 更新基线。",
            )

    def _alert(
        self,
        rule: Optional[Rule],
        evidence: str,
        flow: str = "",
        extra_score: int = 0,
        response: str = "",
    ) -> Optional[Alert]:
        if rule is None:
            return None
        score = rule.score + extra_score
        alert = Alert(
            ts=time.time(),
            severity=Severity.from_score(score),
            tool=rule.tool,
            title=rule.title,
            rule_id=rule.id,
            score=score,
            flow=flow or FILE_SOURCE,
            source=FILE_SOURCE,
            evidence=evidence,
            advice=rule.advice,
            tags=rule.tags,
            response=response,
        )
        self.alert_fn(alert)
        return alert
