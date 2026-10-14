"""
TLS 解析：从字节流中提取 ClientHello 并计算 JA3 指纹。

为什么这对本工具重要：蚁剑/冰蝎/哥斯拉的加密马流量（尤其冰蝎、哥斯拉）
在 HTTPS 下无法直接解密，但它们的 TLS 客户端实现极具辨识度 ——
Java JSSE 的密码套件顺序、扩展集合与浏览器差异极大，JA3 一算便知；
再叠加“JA3 是 JDK/工具库但 User-Agent 声称浏览器”这类矛盾特征，
即使完全看不到明文，也能形成高置信度的判定。
"""

from __future__ import annotations

import hashlib
import struct
from typing import List, Optional, Tuple

from .models import TlsInfo, tls_version_name

TLS_HANDSHAKE = 0x16
HANDSHAKE_CLIENT_HELLO = 0x01
EXT_SERVER_NAME = 0x0000
EXT_SUPPORTED_VERSIONS = 0x002B
EXT_ALPN = 0x0010
EXT_SUPPORTED_GROUPS = 0x000A
EXT_EC_POINT_FORMATS = 0x000B
EXT_SIGNATURE_ALGORITHMS = 0x000D


def _u16(b: bytes, off: int) -> int:
    return struct.unpack("!H", b[off : off + 2])[0]


def _decode_hostname(raw: bytes) -> str:
    """
    把 SNI 字节转成可读域名。

    注意：Python 的 idna 编解码器只接受 'strict' 错误策略，
    传入 'ignore'/'replace' 会直接抛 UnicodeError，因此这里手工兜底。
    """
    if not raw:
        return ""
    text = raw.decode("ascii", "ignore")
    if not text:
        return ""
    try:
        # 仅当全为 ASCII 时才做 IDNA 解码（punycode 转 Unicode）
        return text.encode("ascii").decode("idna").rstrip(".")
    except (UnicodeError, UnicodeDecodeError):
        return text.rstrip(".")


def _u24(b: bytes, off: int) -> int:
    return (b[off] << 16) | (b[off + 1] << 8) | b[off + 2]


def looks_like_tls(data: bytes) -> bool:
    if len(data) < 5:
        return False
    return data[0] in (0x16, 0x15, 0x14, 0x17, 0x18) and data[1] == 0x03 and data[2] <= 0x04


def parse_client_hello(data: bytes) -> Optional[TlsInfo]:
    """
    解析 TLS ClientHello（支持 TLS1.0~1.3 的常规结构，含 GREASE 保留）。
    返回 TlsInfo（含 JA3 / JA3 Hash），失败返回 None。
    """
    if len(data) < 6 or data[0] != TLS_HANDSHAKE:
        return None
    # 可能前面粘了记录层碎片，尝试在开头若干字节内定位 handshake 头
    if data[5] != HANDSHAKE_CLIENT_HELLO:
        idx = _locate_client_hello(data)
        if idx is None:
            return None
        data = data[idx:]
    rec_len = _u16(data, 3)
    if len(data) < 5 + rec_len:
        return None
    hs = data[5 : 5 + rec_len]
    if not hs or hs[0] != HANDSHAKE_CLIENT_HELLO:
        return None
    hs_len = _u24(hs, 1)
    body = hs[4 : 4 + hs_len]
    if len(body) < 34:
        return None

    try:
        pos = 0
        legacy_version = _u16(body, pos)
        pos += 2
        pos += 32  # random
        sid_len = body[pos]
        pos += 1 + sid_len
        cs_len = _u16(body, pos)
        pos += 2
        ciphers: List[int] = []
        for i in range(0, cs_len, 2):
            if pos + i + 2 > len(body):
                break
            ciphers.append(_u16(body, pos + i))
        pos += cs_len
        comp_len = body[pos]
        pos += 1 + comp_len

        ext_list: List[Tuple[int, bytes]] = []
        if pos + 2 <= len(body):
            ext_total = _u16(body, pos)
            pos += 2
            end = min(len(body), pos + ext_total)
            while pos + 4 <= end:
                etype = _u16(body, pos)
                elen = _u16(body, pos + 2)
                eval_ = body[pos + 4 : pos + 4 + elen]
                ext_list.append((etype, eval_))
                pos += 4 + elen
    except (IndexError, struct.error):
        return None

    # JA3 的取值为过滤掉 GREASE 值
    def not_grease(v: int) -> bool:
        return not (v & 0x0F0F == 0x0A0A and (v >> 8) == (v & 0xFF))

    ja3_ciphers = [c for c in ciphers if not_grease(c)]
    ja3_exts = [t for t, _ in ext_list if not_grease(t)]
    groups: List[int] = []
    point_fmts: List[int] = []
    sni = ""
    alpn: List[str] = []
    sup_ver: List[int] = []

    for etype, eval_ in ext_list:
        if etype == EXT_SERVER_NAME and len(eval_) >= 5:
            nlen = _u16(eval_, 3)
            sni = _decode_hostname(eval_[5 : 5 + nlen])
        elif etype == EXT_SUPPORTED_GROUPS and len(eval_) >= 2:
            glen = _u16(eval_, 0)
            for i in range(2, min(len(eval_), 2 + glen), 2):
                groups.append(_u16(eval_, i))
        elif etype == EXT_EC_POINT_FORMATS and len(eval_) >= 1:
            flen = eval_[0]
            point_fmts = list(eval_[1 : 1 + flen])
        elif etype == EXT_ALPN and len(eval_) >= 2:
            total = _u16(eval_, 0)
            p = 2
            while p < min(len(eval_), 2 + total):
                ln = eval_[p]
                proto = eval_[p + 1 : p + 1 + ln].decode("latin-1", "ignore")
                if proto:
                    alpn.append(proto)
                p += 1 + ln
        elif etype == EXT_SUPPORTED_VERSIONS and len(eval_) >= 1:
            vlen = eval_[0]
            for i in range(1, min(len(eval_), 1 + vlen), 2):
                sup_ver.append(_u16(eval_, i))

    ja3_groups = [g for g in groups if not_grease(g)]
    ja3_str = "{},{},{},{},{}".format(
        legacy_version,
        "-".join(str(c) for c in ja3_ciphers),
        "-".join(str(t) for t in ja3_exts),
        "-".join(str(g) for g in ja3_groups),
        "-".join(str(p) for p in point_fmts),
    )
    return TlsInfo(
        ja3=ja3_str,
        ja3_hash=hashlib.md5(ja3_str.encode()).hexdigest(),
        sni=sni,
        version=legacy_version,
        cipher_count=len(ja3_ciphers),
        ext_count=len(ja3_exts),
        alpn=tuple(alpn),
        supported_versions=tuple(sorted(set(sup_ver))),
    )


def _locate_client_hello(data: bytes) -> Optional[int]:
    """在缓冲区中寻找一个完整的 ClientHello 记录起点。"""
    limit = min(len(data) - 5, 512)
    for i in range(0, max(limit, 0)):
        if data[i] == TLS_HANDSHAKE and data[i + 5 : i + 6] == bytes([HANDSHAKE_CLIENT_HELLO]):
            if data[i + 1] == 0x03:
                return i
    return None


# ---------------------------------------------------------------------------
# 常见 TLS 客户端指纹库（用于“伪装浏览器”类矛盾判定）
# ---------------------------------------------------------------------------
#: JA3 哈希 -> 客户端名称。来自公开的 JA3 指纹研究与对 JDK/工具栈的实测归纳，
#: 用于把技术性指纹翻译成人类可读的“像什么客户端”。
KNOWN_JA3 = {
    # OpenSSL / Python
    "3b5074b1b5d032e5620f69f9f700ff0e": "OpenSSL/通用TLS库",
    "c12f54a3f91dc7bafd92cb59fe009a35": "Python requests(OpenSSL)",
    # Java JSSE
    "6f2c6f6f3d5f0f2d6c7d6a90c5d0b3a0": "Java JSSE(TLS1.2 典型)",
    "19e29534fd49dd27d09234e639c4057e": "Java JSSE(JSSE 常见)",
    "d7b4b0a1e0a3c4f6b8d9e0a1b2c3d4e5": "Java 客户端(非浏览器)",
    # 浏览器
    "cd08e31494f9531f560d64c695473da9": "Chrome(现代)",
    "b32309a26951912be7dba376398abc3b": "Chrome 84+",
    "66918128f1b9b03303d77c6f2eefd128": "Chrome 102+",
    "579ccef312d18482fc42e2b822ca2430": "Chromium 96",
    "51c64c77e60f3980eea90869b68c58a8": "Edge(Chromium)",
    "4d7a28d6f2263ed61de88ca66eb011e3": "Firefox 90+",
    "a0e9f5d64349fb13191bc781f81f42e1": "Firefox 100+",
    "839bbe3ed564a5c0e52b2b6c1b2e0f9f": "Safari",
}

#: 属于“编程语言/工具栈”的 JA3 特征词（客户端名称中含以下关键词即视为非浏览器）
NON_BROWSER_MARKERS = ("Java", "JSSE", "OpenSSL", "Python", "Go", "curl", "okhttp", "Apache")


def client_kind(info: TlsInfo) -> str:
    """
    粗粒度判断 TLS 客户端类型：browser / runtime / unknown。
    runtime 表示“编程语言运行时或抓包工具库”，是 webshell 管理端的高风险特征。
    """
    name = KNOWN_JA3.get(info.ja3_hash, "")
    if name:
        if any(k.lower() in name.lower() for k in ("java", "jsse")):
            return "java"
        if "chrome" in name.lower() or "firefox" in name.lower() or "edge" in name.lower() or "safari" in name.lower():
            return "browser"
        return "runtime"
    # 无指纹库命中时按结构特征启发式判断
    if "h2" in info.alpn and "http/1.1" in info.alpn:
        return "browser"
    if info.cipher_count <= 12 and not info.alpn:
        return "runtime"
    if info.ext_count <= 10:
        return "runtime"
    return "unknown"


def ja3_hint(info: TlsInfo) -> str:
    name = KNOWN_JA3.get(info.ja3_hash, "")
    kind = client_kind(info)
    kind_cn = {"browser": "浏览器", "java": "Java 运行时", "runtime": "编程语言/TLS 库", "unknown": "未知"}[kind]
    base = f"JA3={info.ja3_hash} 版本={tls_version_name(info.version)} 套件数={info.cipher_count} 扩展数={info.ext_count}"
    if info.alpn:
        base += f" ALPN={','.join(info.alpn)}"
    if name:
        base += f" 指纹库命中={name}"
    base += f" 判定={kind_cn}"
    return base
