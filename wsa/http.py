"""
HTTP/1.x 报文解析（纯标准库实现）。

设计目标：从 TCP 重组出来的字节流中切分请求/响应，供检测引擎做特征匹配。
支持：
  * 请求行 / 状态行解析，头部大小写不敏感
  * Content-Length 与 chunked 两种消息体长度
  * CONNECT 隧道识别（HTTPS 代理场景）
  * Form 表单、multipart、JSON 请求体解析
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

MAX_HEAD = 64 * 1024            # 头部最大长度
MAX_BODY = 8 * 1024 * 1024      # 单条消息体最大收集长度

_TOKEN_SAFE = re.compile(r"[^A-Za-z0-9_.\-]+")


@dataclass
class HttpRequest:
    method: str = ""
    target: str = ""
    version: str = "HTTP/1.1"
    headers: Dict[str, str] = field(default_factory=dict)
    raw_headers: List[Tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    raw_head: bytes = b""
    head_complete: bool = False
    body_complete: bool = False
    chunked: bool = False

    @property
    def header_bytes(self) -> bytes:
        return self.raw_head


@dataclass
class HttpResponse:
    version: str = "HTTP/1.1"
    status: int = 0
    reason: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    raw_headers: List[Tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    raw_head: bytes = b""
    head_complete: bool = False
    body_complete: bool = False
    chunked: bool = False


def parse_header_block(head: bytes) -> Tuple[str, List[Tuple[str, str]]]:
    """解析起始行 + 头部，返回 (起始行, [(名, 值), ...])。"""
    text = head.decode("latin-1", "ignore")
    lines = re.split(r"\r?\n", text)
    start = lines[0] if lines else ""
    headers: List[Tuple[str, str]] = []
    for line in lines[1:]:
        if not line:
            continue
        if line[:1] in (" ", "\t") and headers:
            # 头部折行续行
            name, value = headers[-1]
            headers[-1] = (name, value + " " + line.strip())
            continue
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        headers.append((name.strip(), value.strip()))
    return start, headers


def _find_head_end(buf: bytes) -> int:
    i = buf.find(b"\r\n\r\n")
    j = buf.find(b"\n\n")
    if i >= 0 and (j < 0 or i <= j):
        return i + 4
    if j >= 0:
        return j + 2
    return -1


def _headers_to_dict(items: List[Tuple[str, str]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k, v in items:
        lk = k.lower()
        if lk in out:
            out[lk] = out[lk] + ", " + v
        else:
            out[lk] = v
    return out


def _content_length(headers: Dict[str, str]) -> Optional[int]:
    raw = headers.get("content-length")
    if raw is None:
        return None
    try:
        return int(raw.strip().split(",")[0])
    except ValueError:
        return None


def _read_chunked(body: bytes) -> Tuple[bytes, bool, int]:
    """一次解析数据、完整性和边界；终止块后的空行也必须收到。"""
    out = bytearray()
    pos = 0
    while True:
        nl = body.find(b"\n", pos)
        if nl < 0:
            return bytes(out), False, len(body)
        size_line = body[pos:nl].strip().split(b";")[0]
        if not re.fullmatch(rb"[0-9A-Fa-f]+", size_line):
            return bytes(out), False, len(body)
        size = int(size_line, 16)
        pos = nl + 1
        if size == 0:
            while True:
                nl = body.find(b"\n", pos)
                if nl < 0:
                    return bytes(out), False, len(body)
                trailer = body[pos:nl].rstrip(b"\r")
                pos = nl + 1
                if not trailer:
                    return bytes(out), True, pos
        if pos + size > len(body):
            return bytes(out), False, len(body)
        remaining = MAX_BODY - len(out)
        if remaining > 0:
            out.extend(body[pos : pos + min(size, remaining)])
        pos += size
        if body[pos : pos + 2] == b"\r\n":
            pos += 2
        elif body[pos : pos + 1] == b"\n":
            pos += 1
        else:
            return bytes(out), False, len(body)


def _dechunk(body: bytes, complete_only: bool = False) -> Tuple[bytes, bool]:
    """兼容原接口，消息边界由同一解析器确定。"""
    data, complete, _consumed = _read_chunked(body)
    return data, complete


def parse_request(buf: bytes) -> Tuple[Optional[HttpRequest], int]:
    """
    从字节流头部解析一个 HTTP 请求。
    返回 (请求对象或 None, 已消费字节数)。
    数据不完整时返回 (None, 0)，调用方应等待更多数据。
    """
    end = _find_head_end(buf)
    if end < 0:
        if len(buf) > MAX_HEAD:
            # 头部异常巨大，丢弃前 1 字节以避免死锁
            return None, 1
        return None, 0
    if end > MAX_HEAD:
        return None, end
    head = buf[:end]
    start, items = parse_header_block(head)
    m = re.match(r"^([A-Za-z]{3,12})\s+(\S+)\s+(HTTP/\d\.\d)$", start.strip())
    if not m:
        return None, 1
    req = HttpRequest(
        method=m.group(1).upper(),
        target=m.group(2),
        version=m.group(3),
        raw_head=head,
    )
    req.raw_headers = items
    req.headers = _headers_to_dict(items)
    req.head_complete = True

    rest = buf[end:]
    cl = _content_length(req.headers)
    te = (req.headers.get("transfer-encoding") or "").lower()
    if "chunked" in te:
        req.chunked = True
        body, complete, consumed = _read_chunked(rest)
        if not complete and len(rest) < MAX_BODY:
            return None, 0  # 等更多数据
        req.body = body[:MAX_BODY]
        req.body_complete = complete
        return req, end + consumed
    if cl is not None:
        if cl < 0 or cl > MAX_BODY * 4:
            return req, end  # 异常长度，按无体处理
        if len(rest) < cl:
            return None, 0
        req.body = rest[:min(cl, MAX_BODY)]
        req.body_complete = True
        return req, end + cl
    # 无体（GET/HEAD 或未声明长度）
    req.body = b""
    req.body_complete = True
    return req, end


def _chunked_consumed(buf: bytes) -> int:
    """返回 chunked 体的边界，不吞掉流水线中的下一条报文。"""
    return _read_chunked(buf)[2]


def parse_response(buf: bytes) -> Tuple[Optional[HttpResponse], int]:
    """解析一个 HTTP 响应，语义同 parse_request。"""
    end = _find_head_end(buf)
    if end < 0:
        if len(buf) > MAX_HEAD:
            return None, 1
        return None, 0
    if end > MAX_HEAD:
        return None, end
    head = buf[:end]
    start, items = parse_header_block(head)
    m = re.match(r"^(HTTP/\d\.\d)\s+(\d{3})\s*(.*)$", start.strip())
    if not m:
        # 可能是 "ICY 200 OK" 之类的非标准响应
        return None, 1
    resp = HttpResponse(
        version=m.group(1),
        status=int(m.group(2)),
        reason=m.group(3),
        raw_head=head,
    )
    resp.raw_headers = items
    resp.headers = _headers_to_dict(items)
    resp.head_complete = True

    rest = buf[end:]
    # 1xx/204/304 无消息体
    if resp.status in (204, 304) or 100 <= resp.status < 200:
        resp.body_complete = True
        return resp, end
    te = (resp.headers.get("transfer-encoding") or "").lower()
    if "chunked" in te:
        resp.chunked = True
        body, complete, consumed = _read_chunked(rest)
        if not complete and len(rest) < MAX_BODY:
            return None, 0
        resp.body = body[:MAX_BODY]
        resp.body_complete = complete
        return resp, end + consumed
    cl = _content_length(resp.headers)
    if cl is not None:
        if cl < 0 or cl > MAX_BODY * 4:
            return resp, end
        if len(rest) < cl:
            return None, 0
        resp.body = rest[:min(cl, MAX_BODY)]
        resp.body_complete = True
        return resp, end + cl
    if (resp.headers.get("connection") or "").lower().startswith("close"):
        # 以连接关闭界定长度，此处把已有数据全当作体
        resp.body = rest[:MAX_BODY]
        resp.body_complete = False
        return resp, end + len(rest)
    resp.body = rest[:MAX_BODY]
    resp.body_complete = True
    return resp, end + len(rest)


def split_iterations(buf: bytes) -> List[bytes]:
    """把缓冲区按普通行切开，供“非 HTTP 明文”场景做逐行特征匹配。"""
    return [ln for ln in re.split(rb"\r\n|\n", buf) if ln]


# ---------------------------------------------------------------------------
# 请求参数解析
# ---------------------------------------------------------------------------
def parse_params(method: str, target: str, headers: Dict[str, str], body: bytes) -> Dict[str, str]:
    """
    汇总一次请求中的全部参数：URL query + form-urlencoded 体 + multipart 体。
    同名参数后出现的覆盖先出现的。
    """
    params: Dict[str, str] = {}

    def add_pairs(query: str) -> None:
        for k, v in urllib.parse.parse_qsl(query, keep_blank_values=True):
            params[k] = v

    if "?" in target:
        add_pairs(target.split("?", 1)[1])

    content_type = headers.get("content-type") or ""
    ctype = content_type.lower()
    if body and ("application/x-www-form-urlencoded" in ctype or (not ctype and b"=" in body[:2048])):
        try:
            add_pairs(body.decode("latin-1", "ignore"))
        except Exception:
            pass
    if body and "multipart/form-data" in ctype:
        boundary = ""
        m = re.search(r'boundary\s*=\s*("[^"]*"|[^;]+)', content_type, re.IGNORECASE)
        if m:
            boundary = m.group(1).strip().strip('"')
        if boundary:
            sep = ("--" + boundary).encode("latin-1", "ignore")
            for part in body.split(sep):
                if b"\r\n\r\n" not in part:
                    continue
                phead, pbody = part.split(b"\r\n\r\n", 1)
                nm = re.search(rb'name="([^"]*)"', phead)
                if not nm:
                    continue
                if pbody.endswith(b"\r\n"):
                    pbody = pbody[:-2]
                params[nm.group(1).decode("latin-1", "ignore")] = pbody.decode("latin-1", "ignore")
    return params


def request_repr(method: str, target: str, headers: Dict[str, str], body: bytes, limit: int = 300) -> str:
    """把请求摘要成一行，用于界面展示。"""
    head = f"{method} {target}"
    if headers.get("host"):
        head = f"{method} {headers['host']}{target}"
    return head[:limit]


def header_str(headers: Dict[str, str], names: Tuple[str, ...]) -> str:
    return " | ".join(f"{n}: {headers[n]}" for n in names if n in headers)


def normalize_path(target: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(target if "://" in target else "http://x" + target)
        return parsed.path or "/"
    except ValueError:
        return target
