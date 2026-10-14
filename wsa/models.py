"""
数据模型：网络五元组、TCP 流、HTTP 事务、告警事件。

本模块不依赖任何第三方库，保持纯粹的领域模型，方便被捕获层、检测层、
界面层共同引用而不产生循环依赖。
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


# --------------------------------------------------------------------------
# 严重级别
# --------------------------------------------------------------------------
class Severity:
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    #: 由低到高的顺序，用于比较与过滤
    ORDER = [INFO, LOW, MEDIUM, HIGH, CRITICAL]

    @staticmethod
    def rank(sev: str) -> int:
        try:
            return Severity.ORDER.index(sev)
        except ValueError:
            return 0

    @staticmethod
    def from_score(score: int) -> str:
        """按累计分值映射严重级别。"""
        if score >= 110:
            return Severity.CRITICAL
        if score >= 70:
            return Severity.HIGH
        if score >= 40:
            return Severity.MEDIUM
        if score >= 15:
            return Severity.LOW
        return Severity.INFO

    @staticmethod
    def cn(sev: str) -> str:
        return {
            Severity.INFO: "提示",
            Severity.LOW: "低危",
            Severity.MEDIUM: "中危",
            Severity.HIGH: "高危",
            Severity.CRITICAL: "严重",
        }.get(sev, sev)


# --------------------------------------------------------------------------
# 流量来源
# --------------------------------------------------------------------------
class Source:
    PCAP = "PCAP文件"
    PROXY = "内置代理"
    SNIFF = "原始套接字"
    SAMPLE = "样例数据"
    UNKNOWN = "未知"


# --------------------------------------------------------------------------
# 五元组 / 流
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class FlowKey:
    """一条 TCP 会话的双向标识。"""

    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int

    @property
    def server_port(self) -> int:
        return self.dst_port

    @property
    def is_http_port(self) -> bool:
        return self.dst_port in (80, 81, 88, 8080, 8000, 8888, 8081, 7001, 9090, 5000)

    @property
    def is_tls_port(self) -> bool:
        return self.dst_port in (443, 8443, 9443, 4443, 10443)

    def reverse(self) -> "FlowKey":
        return FlowKey(self.dst_ip, self.dst_port, self.src_ip, self.src_port)

    def __str__(self) -> str:
        return f"{self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port}"


@dataclass
class TcpSegment:
    """重组前的 TCP 载荷片段。"""

    seq: int
    payload: bytes
    ts: float = 0.0


@dataclass
class Reassembler:
    """
    单方向的 TCP 字节流重组器。

    处理乱序、重传与重叠片段：以 (seq -> payload) 记录片段，
    按序号排序后拼接去重，已投递位置之前的数据被丢弃。
    """

    isn: Optional[int] = None          # 初始序号（SYN 序号 + 1）
    next_seq: Optional[int] = None     # 已投递到应用层的下一个字节序号
    pending: Dict[int, bytes] = field(default_factory=dict)
    total_bytes: int = 0

    def add(self, seq: int, payload: bytes, syn: bool = False, fin: bool = False) -> None:
        if syn:
            # SYN 占用 1 个序号，数据从 seq+1 开始
            self.isn = (seq + 1) & 0xFFFFFFFF
            self.next_seq = self.isn
        if not payload:
            return
        start = seq & 0xFFFFFFFF
        if self.next_seq is None:
            # 没抓到握手时（例如只抓到会话中段），以首个数据包作为基线
            self.next_seq = start
        end = (start + len(payload)) & 0xFFFFFFFF
        # 已投递过的数据直接丢弃
        if self._seq_lt(end, self.next_seq):
            return
        if self._seq_lt(start, self.next_seq):
            cut = (self.next_seq - start) & 0xFFFFFFFF
            payload = payload[cut:]
            start = self.next_seq
            if not payload:
                return
        self.pending[start] = payload
        if fin:
            pass  # FIN 不计入数据，仅用于关闭判断

    @staticmethod
    def _seq_lt(a: int, b: int) -> bool:
        """处理序号回绕的 32 位比较。"""
        return ((a - b) & 0xFFFFFFFF) > 0x7FFFFFFF

    def pop_available(self) -> bytes:
        """取出当前连续的、可投递给应用层的数据。"""
        out = bytearray()
        while self.pending:
            if self.next_seq in self.pending:
                chunk = self.pending.pop(self.next_seq)
                out.extend(chunk)
                self.next_seq = (self.next_seq + len(chunk)) & 0xFFFFFFFF
                continue
            # 允许最多 8 字节的空洞（部分实现会丢少量字节），超出则等待
            advanced = False
            for gap in range(1, 9):
                candidate = (self.next_seq + gap) & 0xFFFFFFFF
                if candidate in self.pending:
                    # 存在空洞，先把已到达的后续数据补上，避免长期滞留
                    chunk = self.pending.pop(candidate)
                    out.extend(b"\x00" * gap)
                    out.extend(chunk)
                    self.next_seq = (candidate + len(chunk)) & 0xFFFFFFFF
                    advanced = True
                    break
            if not advanced:
                break
        self.total_bytes += len(out)
        return bytes(out)


@dataclass
class HttpTransaction:
    """一次 HTTP 请求/响应（或 CONNECT 隧道）。"""

    index: int
    ts: float
    method: str = ""
    url: str = ""
    host: str = ""
    path: str = ""
    version: str = "HTTP/1.1"
    headers: Dict[str, str] = field(default_factory=dict)
    raw_headers: List[Tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    raw_head: bytes = b""
    # 响应
    status: int = 0
    resp_headers: Dict[str, str] = field(default_factory=dict)
    resp_body: bytes = b""
    resp_head: bytes = b""
    note: str = ""

    @property
    def header_blob(self) -> bytes:
        """把所有头部拼成一整块便于做特征匹配。"""
        parts = [self.raw_head or b""]
        if self.resp_head:
            parts.append(self.resp_head)
        out = b"\r\n".join(parts)
        for k, v in list(self.headers.items())[:40]:
            out += f"\r\n{k}: {v}".encode("latin-1", "ignore")
        return out


@dataclass
class TlsInfo:
    """TLS ClientHello 观测量与 JA3 指纹。"""

    ja3: str = ""
    ja3_hash: str = ""
    sni: str = ""
    version: int = 0
    cipher_count: int = 0
    ext_count: int = 0
    alpn: Tuple[str, ...] = ()
    supported_versions: Tuple[int, ...] = ()
    server_cert_subject: str = ""
    server_cert_issuer: str = ""
    self_signed: bool = False

    @property
    def version_str(self) -> str:
        return tls_version_name(self.version)


def tls_version_name(v: int) -> str:
    return {
        0x0300: "SSLv3",
        0x0301: "TLS1.0",
        0x0302: "TLS1.1",
        0x0303: "TLS1.2",
        0x0304: "TLS1.3",
    }.get(v, f"0x{v:04x}")


@dataclass
class Flow:
    """一条完整的 TCP 会话及其派生的分析素材。"""

    key: FlowKey
    source: str = Source.UNKNOWN
    first_ts: float = 0.0
    last_ts: float = 0.0
    packets: int = 0
    c2s_bytes: int = 0
    s2c_bytes: int = 0
    transactions: List[HttpTransaction] = field(default_factory=list)
    tls: List[TlsInfo] = field(default_factory=list)
    tls_binary: bytes = b""
    c2s_sample: bytes = b""
    s2c_sample: bytes = b""
    score: int = 0
    verdict: str = "未判定"

    def touch(self, ts: float) -> None:
        if not self.first_ts:
            self.first_ts = ts
        self.last_ts = ts

    @property
    def info(self) -> str:
        if self.transactions:
            t = self.transactions[0]
            return f"{t.method} {t.host or self.key.dst_ip}{t.path}"
        if self.tls:
            return f"TLS1.x SNI={self.tls[0].sni or '-'}"
        return f"{self.c2s_bytes + self.s2c_bytes} bytes"


@dataclass
class Alert:
    """一条检测告警。"""

    ts: float
    severity: str
    tool: str
    title: str
    rule_id: str
    score: int
    flow: str
    source: str
    evidence: str = ""
    request: str = ""
    response: str = ""
    advice: str = ""
    tags: Tuple[str, ...] = ()
    #: 产生告警的主机名（多机集中收集时用于区分来源）
    host: str = ""

    @property
    def time_str(self) -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.ts)) + (
            f".{int((self.ts % 1) * 1000):03d}"
        )

    def to_dict(self) -> dict:
        return {
            "time": self.time_str,
            "timestamp": round(self.ts, 6),
            "host": self.host,
            "severity": self.severity,
            "severity_cn": Severity.cn(self.severity),
            "tool": self.tool,
            "rule_id": self.rule_id,
            "title": self.title,
            "score": self.score,
            "flow": self.flow,
            "source": self.source,
            "evidence": self.evidence,
            "advice": self.advice,
            "tags": list(self.tags),
            "request": self.request,
            "response": self.response,
        }

    def one_line(self) -> str:
        return (
            f"[{self.time_str}] [{self.severity}] [{self.tool}] {self.title} "
            f"| 规则={self.rule_id} 分值={self.score} | {self.flow} | 证据: {self.evidence}"
        )


@dataclass
class Rule:
    """检测规则定义。"""

    id: str
    tool: str
    title: str
    score: int
    severity: str = ""
    kind: str = "substr"          # substr | regex | header | param | entropy | flow
    pattern: str = ""
    fields: Tuple[str, ...] = ("all",)   # all | head | body | url | request | response | params
    flags: str = ""
    advice: str = ""
    enabled: bool = True
    tags: Tuple[str, ...] = ()
    min_len: int = 0
    max_entropy: float = 0.0
    meta: dict = field(default_factory=dict)


def md5_hex(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()
