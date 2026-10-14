"""通用工具函数：熵计算、可打印化、时间格式化、配置读写。"""

from __future__ import annotations

import base64
import binascii
import json
import math
import os
import re
import time
from collections import Counter
from typing import Any, Dict, Iterable, Optional, Sequence

PRINTABLE = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}

#: 编码/加密流量的“均匀分布”特征阈值（Shannon 熵，单位 bit/byte，上限 8）
ENTROPY_HIGH = 7.2
ENTROPY_MID = 6.0


def shannon_entropy(data: bytes) -> float:
    """计算字节序列的香农熵（bit/byte）。"""
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    ent = 0.0
    for c in counts.values():
        p = c / n
        ent -= p * math.log2(p)
    return ent


def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    ok = sum(1 for b in data if b in PRINTABLE)
    return ok / len(data)


def to_text(data: bytes, limit: int = 0, encoding: str = "utf-8") -> str:
    """尽量把字节串转成可读文本，失败则用 latin-1 兜底并转义不可打印字符。"""
    if limit and len(data) > limit:
        data = data[:limit]
    try:
        text = data.decode(encoding)
        if printable_ratio(data) > 0.75:
            return text
    except UnicodeDecodeError:
        pass
    return "".join(chr(b) if b in PRINTABLE else f"\\x{b:02x}" for b in data)


def hexdump(data: bytes, limit: int = 256) -> str:
    out = []
    for i in range(0, min(len(data), limit), 16):
        chunk = data[i : i + 16]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if b in PRINTABLE else "." for b in chunk)
        out.append(f"{i:08x}  {hexpart:<47}  {asc}")
    if len(data) > limit:
        out.append(f"... 共 {len(data)} 字节，已截断")
    return "\n".join(out)


def ellipsis(text: str, n: int = 400) -> str:
    text = text.replace("\r\n", "\n")
    return text if len(text) <= n else text[:n] + f"…(+{len(text) - n}字符)"


_B64_RE = re.compile(rb"^[A-Za-z0-9+/=\r\n]+$")


def try_base64_decode(text: str, min_len: int = 16) -> Optional[bytes]:
    """尝试把整段文本按 Base64 解码（容忍缺失的 padding）。"""
    s = re.sub(r"\s+", "", text)
    if len(s) < min_len or not _B64_RE.match(s.encode("latin-1", "ignore")):
        return None
    pad = (-len(s)) % 4
    try:
        raw = base64.b64decode(s + "=" * pad, validate=False)
    except (binascii.Error, ValueError):
        return None
    return raw or None


def looks_base64(text: str, min_len: int = 24) -> bool:
    s = re.sub(r"\s+", "", text)
    if len(s) < min_len:
        return False
    if not _B64_RE.match(s.encode("latin-1", "ignore")):
        return False
    return len(s) % 4 in (0, 2, 3)


def now_str() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def stamp() -> str:
    return time.strftime("%Y%m%d-%H%M%S")


def ensure_dir(path: str) -> str:
    if path:
        os.makedirs(path, exist_ok=True)
    return path


def fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} GB"


def merge_dicts(base: Dict[str, Any], extra: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(base)
    out.update(extra or {})
    return out


def load_structured(path: str) -> Any:
    """
    读取 YAML 或 JSON 配置。YAML 需要 PyYAML；
    未安装时若同名 .json 存在则回退读取 JSON，否则返回 None。
    """
    if not path or not os.path.isfile(path):
        return None
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    if path.lower().endswith((".yaml", ".yml")):
        try:
            import yaml  # type: ignore
        except ImportError:
            alt = os.path.splitext(path)[0] + ".json"
            if os.path.isfile(alt):
                with open(alt, "r", encoding="utf-8") as fh:
                    return json.load(fh)
            return None
        return yaml.safe_load(text)
    return json.loads(text)


def as_list(value: Any) -> Sequence[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return value
    return [value]


def key_of(*parts: Iterable[Any]) -> str:
    return "|".join(str(p) for p in parts)
