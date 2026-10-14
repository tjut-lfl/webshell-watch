"""
PCAP / PCAPNG 写出（用于生成自测样例与导出取证片段）。

只依赖标准库，保证自测脚本与主程序在不安装 scapy/dpkt 的环境下同样可用。
"""

from __future__ import annotations

import struct
from typing import List, Sequence, Tuple

LINKTYPE_ETHERNET = 1

#: 一个待写出的以太网帧
Frame = Tuple[float, bytes]


def _ip_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def build_ethernet_ipv4_tcp(
    src_mac: bytes,
    dst_mac: bytes,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    seq: int,
    ack: int,
    flags: int,
    payload: bytes = b"",
    ttl: int = 64,
    ip_id: int = 0,
) -> bytes:
    """构造一个完整的以太网 + IPv4 + TCP 帧（含正确校验和）。"""
    eth = dst_mac + src_mac + struct.pack("!H", 0x0800)
    tcp = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        seq & 0xFFFFFFFF,
        ack & 0xFFFFFFFF,
        5 << 4,
        flags,
        65535,   # window
        0,       # checksum 占位
        0,       # urgent
    ) + payload
    total_len = 20 + len(tcp)
    src_b = bytes(int(x) for x in src_ip.split("."))
    dst_b = bytes(int(x) for x in dst_ip.split("."))
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_len,
        ip_id & 0xFFFF,
        0x4000,  # DF
        ttl,
        6,
        0,
        src_b,
        dst_b,
    )
    csum = _ip_checksum(ip_hdr)
    ip_hdr = ip_hdr[:10] + struct.pack("!H", csum) + ip_hdr[12:]
    # TCP 校验和（带伪首部）
    pseudo = src_b + dst_b + struct.pack("!BBH", 0, 6, len(tcp))
    tcp_csum = _ip_checksum(pseudo + tcp)
    tcp = tcp[:16] + struct.pack("!H", tcp_csum) + tcp[18:]
    return eth + ip_hdr + tcp


def write_pcap(path: str, frames: Sequence[Frame], linktype: int = LINKTYPE_ETHERNET) -> None:
    """写出经典 libpcap 文件（微秒精度，小端）。"""
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype))
        for ts, data in frames:
            sec = int(ts)
            usec = int(round((ts - sec) * 1_000_000))
            if usec >= 1_000_000:
                sec += 1
                usec -= 1_000_000
            fh.write(struct.pack("<IIII", sec, usec, len(data), len(data)))
            fh.write(data)


def write_pcapng(path: str, frames: Sequence[Frame], linktype: int = LINKTYPE_ETHERNET) -> None:
    """写出 PCAPNG 文件（含 SHB / IDB / 每帧一个 EPB），用于验证解析器兼容性。"""
    with open(path, "wb") as fh:
        # Section Header Block
        body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
        block = struct.pack("<II", 0x0A0D0D0A, len(body) + 12) + body + struct.pack("<I", len(body) + 12)
        fh.write(block)
        # Interface Description Block（tsresol = 6，微秒）
        body = struct.pack("<HHI", linktype, 0, 65535)
        opt = struct.pack("<HH", 9, 1) + b"\x06" + b"\x00\x00\x00"
        body += opt
        block = struct.pack("<II", 1, len(body) + 12) + body + struct.pack("<I", len(body) + 12)
        fh.write(block)
        # Enhanced Packet Blocks
        for ts, data in frames:
            ticks = int(round(ts * 1_000_000))
            pad = (4 - len(data) % 4) % 4
            # 接口ID(4) + 时间戳高位(4) + 时间戳低位(4) + 捕获长度(4) + 原始长度(4)
            body = struct.pack(
                "<IIIII", 0, (ticks >> 32) & 0xFFFFFFFF, ticks & 0xFFFFFFFF, len(data), len(data)
            ) + data + b"\x00" * pad
            total = len(body) + 12
            fh.write(struct.pack("<II", 6, total) + body + struct.pack("<I", total))


# ---------------------------------------------------------------------------
# 会话构造助手：把一段 HTTP 对话变成若干帧
# ---------------------------------------------------------------------------
class ConversationBuilder:
    """为一个 TCP 会话生成握手 + 数据 + 挥手帧，自动维护序号。"""

    def __init__(
        self,
        client_ip: str = "10.0.0.66",
        server_ip: str = "10.0.0.10",
        server_port: int = 80,
        client_port: int = 51500,
        t0: float = 0.0,
        mss: int = 1400,
    ):
        self.client_ip = client_ip
        self.server_ip = server_ip
        self.server_port = server_port
        self.client_port = client_port
        self.t = t0
        self.mss = mss
        self.client_mac = b"\x02\x00\x00\x00\x00\x01"
        self.server_mac = b"\x02\x00\x00\x00\x00\x02"
        self.cseq = 1000000
        self.sseq = 2000000
        self.frames: List[Frame] = []

    # -- 基础 -------------------------------------------------------------
    def _frame(self, to_server: bool, seq: int, ack: int, flags: int, payload: bytes) -> None:
        if to_server:
            raw = build_ethernet_ipv4_tcp(
                self.client_mac, self.server_mac, self.client_ip, self.server_ip,
                self.client_port, self.server_port, seq, ack, flags, payload,
            )
        else:
            raw = build_ethernet_ipv4_tcp(
                self.server_mac, self.client_mac, self.server_ip, self.client_ip,
                self.server_port, self.client_port, seq, ack, flags, payload,
            )
        self.frames.append((self.t, raw))

    def segment(self, payload: bytes, to_server: bool = True) -> None:
        """切分并按顺序发送一段数据（模拟 TCP 分段）。"""
        offset = 0
        while offset < len(payload) or offset == 0:
            chunk = payload[offset : offset + self.mss]
            if to_server:
                self._frame(True, self.cseq, self.sseq, 0x18, chunk)
                self.cseq += len(chunk)
            else:
                self._frame(False, self.sseq, self.cseq, 0x18, chunk)
                self.sseq += len(chunk)
            self.t += 0.001
            offset += len(chunk)
            if offset >= len(payload):
                break

    def handshake(self) -> None:
        self._frame(True, self.cseq, 0, 0x02, b"")
        self.cseq += 1
        self._frame(False, self.sseq, self.cseq, 0x12, b"")
        self.sseq += 1
        self._frame(True, self.cseq, self.sseq, 0x10, b"")
        self.t += 0.001

    def close(self) -> None:
        self._frame(True, self.cseq, self.sseq, 0x11, b"")
        self.cseq += 1
        self._frame(False, self.sseq, self.cseq, 0x11, b"")
        self.sseq += 1
        self._frame(True, self.cseq, self.sseq, 0x10, b"")
        self.t += 0.001


def http_request_bytes(
    method: str,
    path: str,
    host: str,
    headers: Sequence[Tuple[str, str]] = (),
    body: bytes = b"",
) -> bytes:
    lines = [f"{method} {path} HTTP/1.1", f"Host: {host}"]
    for k, v in headers:
        lines.append(f"{k}: {v}")
    if body and not any(k.lower() == "content-length" for k, _ in headers):
        lines.append(f"Content-Length: {len(body)}")
    lines.append("")
    lines.append("")
    return "\r\n".join(lines).encode("latin-1") + body


def http_response_bytes(
    status: int = 200,
    reason: str = "OK",
    headers: Sequence[Tuple[str, str]] = (),
    body: bytes = b"",
    close: bool = True,
) -> bytes:
    lines = [f"HTTP/1.1 {status} {reason}"]
    for k, v in headers:
        lines.append(f"{k}: {v}")
    if not any(k.lower() == "content-length" for k, _ in headers):
        lines.append(f"Content-Length: {len(body)}")
    if close:
        lines.append("Connection: close")
    lines.append("")
    lines.append("")
    return "\r\n".join(lines).encode("latin-1") + body
