"""
取证解密：对冰蝎/哥斯拉的加密载荷做验证性解密，把“疑似特征”升级为“已确认内容”。

背景与边界（不夸大能力）：
  * 冰蝎 3.0/4.0：AES-128 + Base64。密钥是连接密码 MD5 的前 16 位。
    默认密码 rebeyond → 密钥 e45e329feb5d925b，因此**默认配置可被离线解密**。
    若攻击者改过密码，本模块会尝试口令字典（见 config 的 key_candidates）。
  * 冰蝎 PHP 在无 openssl 扩展时退化为 XOR + Base64，本模块会一并尝试。
  * 冰蝎 2.0：密钥动态协商，本模块只能从响应中寻找 16 字节随机密钥线索，命中率有限。
  * 哥斯拉：密钥由连接密码与固定盐做 MD5 派生，随后 XOR + Base64。
    已知口令时可解；未知口令时仅依据结构特征（响应体 md5+base64+md5）判定。
  * 蚁剑默认是明文流量（仅做 Base64/URL 编码），无需解密，直接解码即可。

所有解密都只是“尝试”，成功与否由解密结果的明文特征决定；失败不会影响检测。
"""

from __future__ import annotations

import base64
import binascii
import gzip
import hashlib
import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .aes import decrypt_cbc, decrypt_ecb, pkcs7_unpad
from .utils import looks_base64, printable_ratio, shannon_entropy

#: 冰蝎 3.0/4.0 默认密钥（连接密码 rebeyond 的 MD5 前 16 位）
BEHINDER_DEFAULT_KEY = "e45e329feb5d925b"

#: 常见弱口令 / 默认口令，用于派生冰蝎密钥（MD5 前 16 位）
DEFAULT_PASSWORDS = (
    "rebeyond",
    "admin",
    "123456",
    "pass",
    "password",
    "root",
    "test",
    "cmd",
    "shell",
    "key",
    "hack",
    "888888",
    "111111",
    "admin888",
    "webshell",
)

#: 用于识别“解密成功”的明文特征：出现这些词几乎一定是有意义的代码/命令
CODE_MARKERS = (
    # PHP
    "<?php", "eval(", "assert(", "base64_decode", "shell_exec", "passthru",
    "create_function", "call_user_func", "print_r", "phpinfo", "system(",
    "$_post", "$_request",
    # Java
    "runtime", "processbuilder", "getruntime", "classloader", "defineclass",
    "java.", "javax.", "import ", "public class", "getclass",
    # .NET
    "system.reflection", "assembly", "csharpcodeprovider", "createinstance",
    # 命令与文件操作
    "cmd.exe", "cmd|", "/bin/sh", "sh -c", "whoami", "ipconfig", "uname",
    "cat /etc", "/etc/passwd", "powershell", "wget ", "curl ",
    "whoami", "file", "upload", "download", "readfile", "writefile",
    "getbasicsinfo", "printf",
)


@dataclass
class DecryptionResult:
    """一次成功解密的结果。"""

    scheme: str                  # AES-128-ECB / AES-128-CBC / XOR-Base64 / Base64
    key: str = ""
    plaintext: bytes = b""
    notes: str = ""
    confidence: int = 0
    tool_guess: str = ""

    @property
    def preview(self) -> str:
        try:
            text = self.plaintext.decode("utf-8")
        except UnicodeDecodeError:
            text = self.plaintext.decode("latin-1", "ignore")
        text = "".join(ch if ch.isprintable() or ch in "\r\n\t" else "." for ch in text)
        return text[:600]


# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------
def _b64_variants(value: str) -> List[bytes]:
    """
    尽力把参数值还原成原始密文字节。

    关键点：Base64 的字符集本身就落在 ASCII 可打印范围内，如果既尝试
    “Base64 解码”又把原字符串本身当作密文，会凭空多出一个无意义的候选，
    并可能因为“可打印比例高”而被误判为解密成功。
    因此这里的原则是：看起来是 Base64 就只返回 Base64 解码结果；
    否则才把原字符串当作原始字节。
    """
    out: List[bytes] = []
    raw = value.strip()
    try:
        from urllib.parse import unquote

        raw = unquote(raw)
    except Exception:
        pass
    if not raw:
        return out
    raw = raw.strip('"\'')
    # 日志与表单里的 Base64 常带空白（换行、制表、URL 解码残留的空格），
    # 先去掉空白再做判定，否则会因为“不完全匹配 Base64 字符集”而漏掉密文。
    compact = re.sub(r"\s+", "", raw)
    if looks_base64(compact, 16):
        for candidate in (compact, compact.rstrip("=")):
            if not candidate:
                continue
            pad = (-len(candidate)) % 4
            try:
                decoded = base64.b64decode(candidate + "=" * pad, validate=False)
            except (binascii.Error, ValueError):
                continue
            if decoded and decoded not in out:
                out.append(decoded)
        if out:
            return out
    out.append(raw.encode("latin-1", "ignore"))
    return out


def md5_prefix(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()[:16]


def derive_behinder_keys(passwords: Iterable[str]) -> List[str]:
    """由口令列表派生冰蝎密钥（MD5 前 16 位），并始终包含默认密钥。"""
    keys = [BEHINDER_DEFAULT_KEY]
    for pwd in passwords:
        k = md5_prefix(pwd)
        if k not in keys:
            keys.append(k)
    return keys


def _xor(data: bytes, key: bytes, offset: int = 0) -> bytes:
    if not key:
        return data
    return bytes(b ^ key[(i + offset) % len(key)] for i, b in enumerate(data))


def plaintext_score(data: bytes) -> int:
    """
    给解密结果打分。判定“解密成功”必须有正向证据：出现可读的代码/命令特征词，
    或者明文具备明显的结构化特征。单纯“可打印比例高”不足以判定成功，
    否则把随机密文当明文就会产生误报。
    """
    if not data:
        return 0
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("latin-1", "ignore")
    low = text.lower()
    score = 0
    marker_hits = 0
    for marker in CODE_MARKERS:
        if marker.lower() in low:
            score += 12
            marker_hits += 1
    if printable_ratio(data) > 0.9:
        score += 10
    elif printable_ratio(data) > 0.7:
        score += 4
    if re.search(r"[A-Za-z_]{3,}\s*\([^)]{0,80}\)", text):
        score += 8
    if "<?php" in low or "class " in low or "import " in low:
        score += 6
    if marker_hits == 0:
        # 没有任何代码/命令特征词：不能认定为解密成功，最多给很低的分
        return min(score, 12)
    return min(score, 60)


def marker_hits(data: bytes) -> int:
    """返回命中的代码/命令特征词数量，用于判定是否为有效明文。"""
    try:
        text = data[:4000].decode("utf-8")
    except UnicodeDecodeError:
        text = data[:4000].decode("latin-1", "ignore")
    low = text.lower()
    return sum(1 for m in CODE_MARKERS if m.lower() in low)


def _maybe_gunzip(data: bytes) -> Tuple[bytes, str]:
    if data[:2] == b"\x1f\x8b":
        try:
            return gzip.decompress(data), "（已解 GZIP）"
        except OSError:
            pass
    return data, ""


def guess_tool(plaintext: bytes) -> str:
    low = plaintext.lower()
    if b"<?php" in low or b"eval(" in low or b"base64_decode" in low:
        return "冰蝎/哥斯拉(PHP)"
    if b"classloader" in low or b"defineclass" in low or b"java." in low:
        return "冰蝎/哥斯拉(JSP)"
    if b"system.reflection" in low or b"assembly" in low or b"csharpcodeprovider" in low:
        return "蚁剑/冰蝎(ASPX)"
    return "未知"


# ---------------------------------------------------------------------------
# 主入口
# ---------------------------------------------------------------------------
@dataclass
class CryptoProbe:
    """针对单个 HTTP 事务的加密载荷探查器。"""

    passwords: Sequence[str] = DEFAULT_PASSWORDS
    max_bytes: int = 64 * 1024
    results: List[DecryptionResult] = field(default_factory=list)
    tried_schemes: int = 0

    # -- 对外接口 ---------------------------------------------------------
    def probe_request(
        self, raw_params: Dict[str, str], body: bytes, content_type: str = ""
    ) -> List[DecryptionResult]:
        """尝试解密请求中的候选密文，返回成功结果。"""
        self.results = []
        keys = derive_behinder_keys(self.passwords)
        candidates: List[Tuple[str, bytes]] = []

        # 1) 表单参数中的 Base64 密文
        for name, value in raw_params.items():
            if not value or len(value) < 16:
                continue
            for raw in _b64_variants(value):
                if len(raw) >= 16:
                    candidates.append((f"参数 {name}", raw[: self.max_bytes]))

        # 2) octet-stream / 整体 Body 密文
        ctype = (content_type or "").lower()
        if body and len(body) >= 16:
            if "application/octet-stream" in ctype or not ctype:
                candidates.append(("请求体", body[: self.max_bytes]))
            if looks_base64(body[:4096].decode("latin-1", "ignore"), 16):
                for raw in _b64_variants(body.decode("latin-1", "ignore")[: self.max_bytes]):
                    candidates.append(("请求体(Base64)", raw))

        for where, data in candidates:
            if len(data) < 16:
                continue
            # AES-128-ECB：冰蝎 3.0/4.0 主流
            for key in keys:
                kb = key.encode("latin-1", "ignore")
                if len(kb) != 16:
                    continue
                self.tried_schemes += 1
                pt = pkcs7_unpad(decrypt_ecb(kb, data))
                self._record("冰蝎 AES-128-ECB", key, pt, where)
                for iv in (b"\x00" * 16,):
                    self.tried_schemes += 1
                    pt2 = pkcs7_unpad(decrypt_cbc(kb, data, iv=iv))
                    if pt2 != pt:
                        self._record("冰蝎 AES-128-CBC", key, pt2, where)
            # 冰蝎 PHP 无 openssl 时的 XOR + Base64
            for key in keys:
                kb = key.encode("latin-1", "ignore")
                for off in (0, 1):
                    self.tried_schemes += 1
                    pt = _xor(data, kb, off)
                    self._record(f"冰蝎 XOR-Base64(offset={off})", key, pt, where)
        return self.results

    # -- 内部 -------------------------------------------------------------
    def _record(self, scheme: str, key: str, plain: bytes, where: str) -> None:
        if len(plain) < 4:
            return
        plain, note = _maybe_gunzip(plain)
        # 必须出现可读的代码/命令特征词才认定为解密成功，避免把随机数据当明文
        if marker_hits(plain) == 0:
            return
        score = plaintext_score(plain[:2000])
        if score < 20:
            return
        result = DecryptionResult(
            scheme=scheme,
            key=key,
            plaintext=plain,
            notes=f"来源：{where}{note}",
            confidence=score,
            tool_guess=guess_tool(plain[:2000]),
        )
        for existing in self.results:
            if existing.scheme == scheme and existing.plaintext == plain:
                return
        self.results.append(result)

    def best(self) -> Optional[DecryptionResult]:
        if not self.results:
            return None
        return max(self.results, key=lambda r: r.confidence)


# ---------------------------------------------------------------------------
# 蚁剑/菜刀：Base64 + URL 编码的明文载荷（无需密钥）
# ---------------------------------------------------------------------------
ANTSWORD_MARKERS = (
    "@ini_set",
    "display_errors",
    "set_time_limit",
    "base64_decode",
    "eval(",
    "assert(",
    "$_POST",
    "$_REQUEST",
    "chr(",
    "Execute(",
    "Assembly",
)


def decode_antsword_payload(value: str) -> Optional[str]:
    """把蚁剑的 URL/Base64 载荷还原成明文代码，用于取证展示。"""
    try:
        from urllib.parse import unquote

        text = unquote(value)
    except Exception:
        text = value
    if not looks_base64(text, 24):
        return None
    pad = (-len(text)) % 4
    try:
        raw = base64.b64decode(text + "=" * pad)
    except (binascii.Error, ValueError):
        return None
    plain = raw.decode("utf-8", "ignore")
    if any(m.lower() in plain.lower() for m in ANTSWORD_MARKERS):
        return plain[:800]
    return None


def analyse_hex_payload(value: str) -> Optional[str]:
    """还原 ASP 变体的 0x… 十六进制载荷。"""
    m = re.findall(r"0x([0-9a-fA-F]{8,})", value)
    if not m:
        return None
    out = bytearray()
    for chunk in m:
        if len(chunk) % 2:
            chunk = chunk[:-1]
        try:
            out.extend(binascii.unhexlify(chunk))
        except binascii.Error:
            continue
    if not out:
        return None
    text = out.decode("latin-1", "ignore")
    if printable_ratio(out) > 0.6 and re.search(r"[A-Za-z]{3,}", text):
        return text[:800]
    return None


def entropy_of(value: str) -> float:
    try:
        return shannon_entropy(value.encode("latin-1", "ignore"))
    except Exception:
        return 0.0
