"""
流量装配：把 TCP 数据包还原成 Flow（含 HTTP 事务与 TLS 指纹）。

三种流量来源共用这一层：
    * PCAP/PCAPNG 文件回放（离线取证）
    * 内置代理（在线旁路，能拿到 TLS 明文）
    * 原始套接字嗅探（在线网卡级，只见密文但可提取 JA3）

装配策略：
    以“服务器端口”为方向基准，把 (客户端 -> 服务器) 记为 c2s，反之为 s2c；
    两个方向分别做 TCP 重组，再用轻量 HTTP 解析器切分请求与响应，
    按出现顺序配对成 HttpTransaction。
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

from . import http as httpmod
from . import tls as tlsmod
from .models import Flow, FlowKey, HttpTransaction, Reassembler, Source
from .pcap import Packet

#: 常见 Web 端口，用于判断哪一侧是服务端
COMMON_SERVER_PORTS = (
    80, 81, 82, 83, 84, 85, 86, 87, 88, 89,
    443, 444, 445, 446, 447, 448, 449, 450,
    3000, 5000, 7001, 7002, 8000, 8001, 8008, 8009, 8010,
    8080, 8081, 8082, 8083, 8085, 8088, 8090, 8180, 8443, 8444,
    8880, 8888, 9000, 9001, 9043, 9060, 9080, 9090, 9091, 9443, 10443,
)

#: 单条流保留的最大应用层字节数（防止大文件传输占满内存）
MAX_STREAM_KEEP = 4 * 1024 * 1024


@dataclass
class HalfStream:
    """单方向的流缓冲 + 重组器。"""

    reasm: Reassembler = field(default_factory=Reassembler)
    buffer: bytearray = field(default_factory=bytearray)
    seen_bytes: int = 0

    def feed(self, pkt: Packet) -> None:
        self.reasm.add(pkt.seq, pkt.payload, syn=pkt.syn)
        data = self.reasm.pop_available()
        if not data:
            return
        self.seen_bytes += len(data)
        if len(self.buffer) < MAX_STREAM_KEEP:
            room = MAX_STREAM_KEEP - len(self.buffer)
            self.buffer.extend(data[:room])


@dataclass
class FlowState:
    """一条流的装配状态。"""

    key: FlowKey
    source: str
    c2s: HalfStream = field(default_factory=HalfStream)
    s2c: HalfStream = field(default_factory=HalfStream)
    flow: Optional[Flow] = None
    http_done: bool = False
    tls_extracted: bool = False

    def __post_init__(self) -> None:
        if self.flow is None:
            self.flow = Flow(key=self.key, source=self.source)


class FlowTable:
    """
    维护所有流的状态。

    典型用法：
        table = FlowTable(source=Source.PCAP)
        for pkt in reader.packets():
            table.feed(pkt)
        for flow in table.finish():
            analyzer.analyze_flow(flow)
    """

    def __init__(self, source: str = Source.UNKNOWN, local_ips: Iterable[str] = ()):
        self.source = source
        self.local_ips = set(local_ips or ())
        self.flows: Dict[FlowKey, FlowState] = {}
        self.packet_count = 0
        self.finished: List[Flow] = []
        #: 已确定方向的会话（包含双向 key），避免同一会话被拆成两条流
        self._known_keys: set = set()

    # -- 方向判定 ---------------------------------------------------------
    def _orient(self, pkt: Packet) -> Optional[Tuple[FlowKey, bool]]:
        """
        返回 (规范化的 FlowKey, 是否为 c2s)。
        规范化规则：服务端端口较小/属于常见 Web 端口的一侧作为 dst。
        """
        src, dst = pkt.src_ip, pkt.dst_ip
        sport, dport = pkt.src_port, pkt.dst_port
        forward = FlowKey(src, sport, dst, dport)
        reverse = FlowKey(dst, dport, src, sport)

        # 1) 首次见到该会话：用握手包或端口特征定方向并登记。
        #    注意：这里只查 self.flows（已经真正建立方向的会话），不能查
        #    双向登记表，否则 SYN 之后紧跟的 SYN+ACK 会被当成“已知方向”处理。
        if forward not in self.flows and reverse not in self.flows:
            if pkt.syn and not pkt.ack_flag:
                # 纯 SYN：目标端口即服务端端口，发起方是客户端
                chosen, is_c2s = forward, True
            elif pkt.syn and pkt.ack_flag:
                # SYN+ACK：发起方是服务端，收到 SYN 的一方才是客户端
                chosen, is_c2s = reverse, False
            elif src in self.local_ips and dst not in self.local_ips:
                chosen, is_c2s = forward, True
            elif dst in self.local_ips and src not in self.local_ips:
                chosen, is_c2s = forward, True
            elif self._is_server_port(dport) and not self._is_server_port(sport):
                chosen, is_c2s = forward, True
            elif self._is_server_port(sport) and not self._is_server_port(dport):
                chosen, is_c2s = reverse, False
            elif dport <= sport:
                # 都像或都不像：端口小的一侧当服务端
                chosen, is_c2s = forward, True
            else:
                chosen, is_c2s = reverse, False
            self._known_keys.add(forward)
            self._known_keys.add(reverse)
            return chosen, is_c2s

        # 2) 会话已存在：按规范 key 归属（两个方向都归入同一条流）
        if forward in self.flows:
            return forward, True
        return reverse, False

    @staticmethod
    def _is_server_port(port: int) -> bool:
        return port in COMMON_SERVER_PORTS or port < 1024

    # -- 投喂 -------------------------------------------------------------
    def feed(self, pkt: Packet) -> Optional[Flow]:
        """投喂一个数据包；返回刚刚结束的流（如有）。"""
        if pkt.payload == b"" and not pkt.syn and not pkt.fin:
            return None
        oriented = self._orient(pkt)
        if oriented is None:
            return None
        key, is_c2s = oriented
        state = self.flows.get(key)
        if state is None:
            state = FlowState(key=key, source=self.source)
            self.flows[key] = state
        self.packet_count += 1
        flow = state.flow
        if flow is None:  # pragma: no cover - __post_init__ 已保证
            return None
        flow.packets += 1
        flow.touch(pkt.ts)

        half = state.c2s if is_c2s else state.s2c
        half.feed(pkt)
        if is_c2s:
            flow.c2s_bytes += len(pkt.payload)
        else:
            flow.s2c_bytes += len(pkt.payload)

        # 提取 TLS ClientHello（可能分片在多个包里）
        if not state.tls_extracted and is_c2s:
            data = bytes(state.c2s.buffer[:8192])
            if tlsmod.looks_like_tls(data):
                info = tlsmod.parse_client_hello(data)
                if info:
                    flow.tls.append(info)
                    flow.tls_binary = data
                    state.tls_extracted = True
        if pkt.rst or pkt.fin:
            self._close(key)
        return None

    def _close(self, key: FlowKey) -> None:
        state = self.flows.get(key)
        if state is None:
            return
        self._assemble(state)
        flow = state.flow
        if flow is not None and (
            flow.transactions or flow.tls or flow.c2s_sample or flow.s2c_sample
        ):
            self.finished.append(flow)
        self.flows.pop(key, None)

    # -- HTTP 配对 --------------------------------------------------------
    def _assemble(self, state: FlowState) -> None:
        if state.http_done:
            return
        state.http_done = True
        flow = state.flow
        if flow is None:
            return
        req_buf = bytes(state.c2s.buffer)
        resp_buf = bytes(state.s2c.buffer)
        if not req_buf:
            return
        # 非 HTTP 且非 TLS 的流，只保留样本供熵值/魔数分析
        if tlsmod.looks_like_tls(req_buf):
            return
        head_end = httpmod._find_head_end(req_buf)
        first_token = req_buf.split(b" ", 2)[0] if b" " in req_buf[:32] else b""
        if head_end < 0 and not first_token.isalpha():
            flow.c2s_sample = req_buf[:65536]
            flow.s2c_sample = resp_buf[:65536]
            return

        reqs = self._split_requests(req_buf)
        resps = self._split_responses(resp_buf)
        for i, req in enumerate(reqs):
            txn = HttpTransaction(index=i, ts=flow.first_ts)
            txn.method = req.method
            txn.version = req.version
            txn.headers = req.headers
            txn.raw_headers = list(req.raw_headers)
            txn.raw_head = req.raw_head
            txn.body = req.body
            txn.host = req.headers.get("host", "")
            txn.path = req.target
            if txn.host and "://" not in req.target:
                txn.url = f"http://{txn.host}{req.target}"
            else:
                txn.url = req.target
            if i < len(resps):
                resp = resps[i]
                txn.status = resp.status
                txn.resp_headers = resp.headers
                txn.resp_head = resp.raw_head
                txn.resp_body = resp.body
            flow.transactions.append(txn)
        flow.c2s_sample = req_buf[:65536]
        flow.s2c_sample = resp_buf[:65536]

    @staticmethod
    def _split_requests(buf: bytes) -> List[httpmod.HttpRequest]:
        out: List[httpmod.HttpRequest] = []
        pos = 0
        guard = 0
        while pos < len(buf) and guard < 512:
            guard += 1
            chunk = buf[pos:]
            # 跳过前导空行（Keep-Alive 之间的 CRLF）
            stripped = chunk.lstrip(b"\r\n")
            if len(stripped) != len(chunk):
                pos += len(chunk) - len(stripped)
                chunk = stripped
            if not chunk:
                break
            req, used = httpmod.parse_request(chunk)
            if req is None:
                if used <= 0:
                    break
                pos += used
                continue
            out.append(req)
            pos += used if used > 0 else len(chunk)
        return out

    @staticmethod
    def _split_responses(buf: bytes) -> List[httpmod.HttpResponse]:
        out: List[httpmod.HttpResponse] = []
        pos = 0
        guard = 0
        while pos < len(buf) and guard < 512:
            guard += 1
            chunk = buf[pos:]
            stripped = chunk.lstrip(b"\r\n")
            if len(stripped) != len(chunk):
                pos += len(chunk) - len(stripped)
                chunk = stripped
            if not chunk:
                break
            resp, used = httpmod.parse_response(chunk)
            if resp is None:
                if used <= 0:
                    break
                pos += used
                continue
            out.append(resp)
            pos += used if used > 0 else len(chunk)
        return out

    # -- 收尾 -------------------------------------------------------------
    def finish(self) -> List[Flow]:
        """结束所有未关闭的流并返回全部流。"""
        for key in list(self.flows):
            self._close(key)
        return self.finished

    def flush_idle(self, idle_seconds: float = 20.0, now: Optional[float] = None) -> List[Flow]:
        """
        把“长时间没有新数据包”的流提前结束并返回，供在线抓包实时分析使用。
        （长连接可能永远不发送 FIN，若不主动刷新就会一直看不到结果。）
        """
        now = now if now is not None else time.time()
        out: List[Flow] = []
        for key, state in list(self.flows.items()):
            flow = state.flow
            if flow is None:
                continue
            last = flow.last_ts or flow.first_ts
            if last and now - last >= idle_seconds:
                self._close(key)
                if self.finished:
                    out.append(self.finished.pop())
        return out

    def total_flows(self) -> int:
        return len(self.finished) + len(self.flows)

    def live_flows(self) -> Iterator[Flow]:
        for state in self.flows.values():
            self._assemble(state)
            if state.flow is not None:
                yield state.flow
