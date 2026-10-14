"""
PCAP / PCAPNG 文件解析（纯标准库实现）。

支持：
  * 经典 libpcap 格式（magic 0xa1b2c3d4 / 0xd4c3b2a1，微秒与纳秒精度）
  * PCAPNG 格式（0x0a0d0d0a），解析 IDB/EPB/SPB 块
  * 链路层类型：以太网(LINKTYPE_ETHERNET=1)、Linux SLL(113)、原始 IP(101)、
    RAW(12/14)、IPv4(228)、IPv6(229)、Linux SLL2(276)
  * VLAN (802.1Q / QinQ)、PPPoE 会话、IPv4 分片标记
  * IPv4 / IPv6 / TCP 头部解析

输出的解析状态通过 Pitfall 报告，避免“静默漏检”。
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass, field
from typing import BinaryIO, Iterator, List, Optional, Tuple

# ---------------------------------------------------------------------------
# 链路层类型
# ---------------------------------------------------------------------------
LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229
LINKTYPE_LINUX_SLL2 = 276

PCAP_MAGIC_LE = 0xA1B2C3D4
PCAP_MAGIC_BE = 0xD4C3B2A1
PCAP_MAGIC_NS_LE = 0xA1B23C4D
PCAP_MAGIC_NS_BE = 0x4D3CB2A1
PCAPNG_MAGIC = 0x0A0D0D0A

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_VLAN = 0x8100
ETHERTYPE_QINQ = 0x88A8
ETHERTYPE_QINQ_OLD = 0x9100
ETHERTYPE_PPPOE = 0x8864

PROTO_TCP = 6
PROTO_UDP = 17


@dataclass
class Packet:
    """从链路层剥离后得到的 IPv4/IPv6 + TCP 数据包。"""

    ts: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    seq: int
    ack: int
    flags: int
    payload: bytes
    ip_version: int = 4
    ttl: int = 0
    frame_len: int = 0
    fragmented: bool = False

    @property
    def syn(self) -> bool:
        return bool(self.flags & 0x02)

    @property
    def fin(self) -> bool:
        return bool(self.flags & 0x01)

    @property
    def rst(self) -> bool:
        return bool(self.flags & 0x04)

    @property
    def psh(self) -> bool:
        return bool(self.flags & 0x08)

    @property
    def ack_flag(self) -> bool:
        return bool(self.flags & 0x10)

    def flag_str(self) -> str:
        out = []
        for bit, name in ((0x02, "S"), (0x10, "A"), (0x08, "P"), (0x01, "F"), (0x04, "R")):
            if self.flags & bit:
                out.append(name)
        return "".join(out) or "-"


@dataclass
class Pitfall:
    ts: float
    kind: str
    message: str


@dataclass
class ParseStats:
    total_frames: int = 0
    tcp_frames: int = 0
    udp_frames: int = 0
    other_frames: int = 0
    ipv6_frames: int = 0
    non_ip_frames: int = 0
    fragmented_frames: int = 0
    undecodable_frames: int = 0
    linktype: int = 0
    format: str = ""
    pitfalls: List[Pitfall] = field(default_factory=list)
    first_ts: float = 0.0
    last_ts: float = 0.0

    def note(self, ts: float, kind: str, message: str) -> None:
        # 同一类型的问题只记录前若干条，避免刷屏
        same = [p for p in self.pitfalls if p.kind == kind]
        if len(same) < 8:
            self.pitfalls.append(Pitfall(ts, kind, message))


# ---------------------------------------------------------------------------
# 链路层
# ---------------------------------------------------------------------------
def _mac(data: bytes, off: int) -> str:
    return ":".join(f"{b:02x}" for b in data[off : off + 6])


def _strip_link_layer(
    linktype: int, data: bytes, stats: ParseStats, ts: float
) -> Optional[Tuple[int, bytes]]:
    """剥离链路层，返回 (ethertype/ip_version_marker, payload)。"""
    if linktype == LINKTYPE_ETHERNET:
        if len(data) < 14:
            return None
        etype = struct.unpack("!H", data[12:14])[0]
        off = 14
        # VLAN 可能叠加多层
        while etype in (ETHERTYPE_VLAN, ETHERTYPE_QINQ, ETHERTYPE_QINQ_OLD):
            if len(data) < off + 4:
                return None
            etype = struct.unpack("!H", data[off + 2 : off + 4])[0]
            off += 4
        if etype == ETHERTYPE_PPPOE:
            # PPPoE 会话头 6 字节 + PPP 协议 2 字节
            if len(data) < off + 8:
                return None
            ppp_proto = struct.unpack("!H", data[off + 6 : off + 8])[0]
            off += 8
            etype = ETHERTYPE_IPV4 if ppp_proto == 0x0021 else ETHERTYPE_IPV6
        return etype, data[off:]
    if linktype == LINKTYPE_LINUX_SLL:
        if len(data) < 16:
            return None
        return struct.unpack("!H", data[14:16])[0], data[16:]
    if linktype == LINKTYPE_LINUX_SLL2:
        if len(data) < 20:
            return None
        return struct.unpack("!H", data[0:2])[0], data[20:]
    if linktype in (LINKTYPE_RAW, 12, 14):
        # 裸 IP，按首字节版本号判断
        if not data:
            return None
        ver = data[0] >> 4
        return (ETHERTYPE_IPV4 if ver == 4 else ETHERTYPE_IPV6), data
    if linktype == LINKTYPE_IPV4:
        return ETHERTYPE_IPV4, data
    if linktype == LINKTYPE_IPV6:
        return ETHERTYPE_IPV6, data
    if linktype == LINKTYPE_NULL:
        if len(data) < 4:
            return None
        fam = struct.unpack("<I", data[:4])[0]
        return (ETHERTYPE_IPV4 if fam in (2, 24, 28) else ETHERTYPE_IPV6), data[4:]
    stats.undecodable_frames += 1
    stats.note(ts, "linktype", f"不支持的链路层类型 {linktype}，跳过该帧")
    return None


# ---------------------------------------------------------------------------
# IP / TCP
# ---------------------------------------------------------------------------
def parse_ipv4(data: bytes, ts: float, frame_len: int, stats: ParseStats) -> Optional[Packet]:
    if len(data) < 20:
        return None
    ver_ihl = data[0]
    ihl = (ver_ihl & 0x0F) * 4
    if ihl < 20 or len(data) < ihl:
        stats.undecodable_frames += 1
        return None
    total_len = struct.unpack("!H", data[2:4])[0]
    flags_frag = struct.unpack("!H", data[6:8])[0]
    ttl = data[8]
    proto = data[9]
    src = ".".join(str(b) for b in data[12:16])
    dst = ".".join(str(b) for b in data[16:20])
    more_frags = bool(flags_frag & 0x2000)
    frag_off = flags_frag & 0x1FFF
    fragmented = more_frags or frag_off > 0
    if fragmented:
        stats.fragmented_frames += 1
    body = data[ihl:total_len] if 0 < total_len <= len(data) else data[ihl:]
    if proto != PROTO_TCP:
        return None
    pkt = parse_tcp(body, ts, src, dst, 4, ttl, frame_len, stats, fragmented)
    return pkt


def parse_ipv6(data: bytes, ts: float, frame_len: int, stats: ParseStats) -> Optional[Packet]:
    if len(data) < 40:
        return None
    payload_len = struct.unpack("!H", data[4:6])[0]
    next_hdr = data[6]
    src = _fmt_ipv6(data[8:24])
    dst = _fmt_ipv6(data[24:40])
    body = data[40 : 40 + payload_len] if payload_len else data[40:]
    # 走一遍扩展头链
    hops = 0
    while next_hdr in (0, 43, 60, 51, 50) and hops < 8:
        if len(body) < 8:
            return None
        nxt = body[0]
        ext_len = (body[1] + 1) * 8 if next_hdr != 51 else (body[1] + 2) * 4
        body = body[ext_len:]
        next_hdr = nxt
        hops += 1
    if next_hdr == 44:  # 分片头
        stats.fragmented_frames += 1
        if len(body) < 8:
            return None
        next_hdr = body[0]
        body = body[8:]
    if next_hdr != PROTO_TCP:
        return None
    return parse_tcp(body, ts, src, dst, 6, 0, frame_len, stats, True)


def _fmt_ipv6(raw: bytes) -> str:
    parts = [f"{struct.unpack('!H', raw[i : i + 2])[0]:x}" for i in range(0, 16, 2)]
    # 压缩最长的连续零段
    best_i = best_j = -1
    i = 0
    while i < 8:
        if parts[i] == "0":
            j = i
            while j < 8 and parts[j] == "0":
                j += 1
            if j - i > (best_j - best_i):
                best_i, best_j = i, j
            i = j
        else:
            i += 1
    if best_j - best_i > 1:
        return ":".join(parts[:best_i]) + "::" + ":".join(parts[best_j:])
    return ":".join(parts)


def parse_tcp(
    data: bytes,
    ts: float,
    src_ip: str,
    dst_ip: str,
    ip_version: int,
    ttl: int,
    frame_len: int,
    stats: ParseStats,
    fragmented: bool,
) -> Optional[Packet]:
    if len(data) < 20:
        return None
    sport, dport, seq, ack = struct.unpack("!HHII", data[:12])
    data_off = (data[12] >> 4) * 4
    if data_off < 20 or len(data) < data_off:
        stats.undecodable_frames += 1
        return None
    flags = data[13]
    payload = data[data_off:]
    stats.tcp_frames += 1
    return Packet(
        ts=ts,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=sport,
        dst_port=dport,
        seq=seq,
        ack=ack,
        flags=flags,
        payload=payload,
        ip_version=ip_version,
        ttl=ttl,
        frame_len=frame_len,
        fragmented=fragmented,
    )


# ---------------------------------------------------------------------------
# 文件读取
# ---------------------------------------------------------------------------
class PcapReader:
    """迭代式读取 PCAP / PCAPNG，逐帧产出 Packet（仅 TCP）。"""

    def __init__(self, path: str, stats: Optional[ParseStats] = None):
        self.path = path
        self.stats = stats or ParseStats()
        self._fh: Optional[BinaryIO] = None

    # -- 上下文管理 ---------------------------------------------------------
    def __enter__(self) -> "PcapReader":
        self._fh = open(self.path, "rb")
        return self

    def __exit__(self, *exc) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None

    def packets(self) -> Iterator[Packet]:
        if self._fh is None:
            self._fh = open(self.path, "rb")
        head = self._fh.read(4)
        if len(head) < 4:
            self.stats.note(0.0, "empty", "文件为空或不足 4 字节")
            return
        magic = struct.unpack("<I", head)[0]
        if magic == PCAPNG_MAGIC:
            # 注意：这里必须传原始字节 head（它就是 SHB 的块类型），
            # 不能传解出来的整数，否则解析器会把长度字段当成块类型而整体错位。
            yield from self._read_pcapng(head)
        elif magic in (PCAP_MAGIC_LE, PCAP_MAGIC_NS_LE, PCAP_MAGIC_BE, PCAP_MAGIC_NS_BE):
            yield from self._read_pcap(head)
        else:
            self.stats.note(0.0, "magic", f"无法识别的文件魔数 0x{magic:08x}，不是 PCAP/PCAPNG")
            return

    # -- 经典 PCAP ---------------------------------------------------------
    def _read_pcap(self, head: bytes) -> Iterator[Packet]:
        assert self._fh is not None
        magic = struct.unpack("<I", head)[0]
        little = magic in (PCAP_MAGIC_LE, PCAP_MAGIC_NS_LE)
        nanosec = magic in (PCAP_MAGIC_NS_LE, PCAP_MAGIC_NS_BE)
        endian = "<" if little else ">"
        rest = self._fh.read(20)
        if len(rest) < 20:
            self.stats.note(0.0, "truncated", "全局头不完整")
            return
        _, _, _, _, _, linktype = struct.unpack(endian + "HHiIII", rest[:20])
        self.stats.linktype = linktype
        self.stats.format = "PCAP(ns)" if nanosec else "PCAP(us)"
        scale = 1_000_000_000.0 if nanosec else 1_000_000.0
        while True:
            hdr = self._fh.read(16)
            if len(hdr) < 16:
                break
            ts_sec, ts_frac, incl_len, orig_len = struct.unpack(endian + "IIII", hdr)
            if incl_len > 0x4000000:  # 64MB 以上视为异常
                self.stats.note(ts_sec, "badlen", f"异常帧长度 {incl_len}，停止解析")
                break
            data = self._fh.read(incl_len)
            if len(data) < incl_len:
                self.stats.note(ts_sec, "truncated", "文件末尾数据被截断")
                break
            ts = ts_sec + ts_frac / scale
            yield from self._emit(linktype, data, ts, orig_len)

    # -- PCAPNG ------------------------------------------------------------
    def _read_pcapng(self, first_block_head: bytes) -> Iterator[Packet]:
        """
        PCAPNG 块流解析。

        字节布局（引用 pcapng 规范）：
            Block = BlockType(4) + BlockTotalLength(4) + BlockBody(N) + BlockTotalLength(4)
            BlockTotalLength = 12 + N
        Section Header Block 的 BlockBody 开头 4 字节是字节序标识（BOM）。
        传入的 first_block_head 是已被 packets() 读掉的块类型（0x0A0D0D0A）。
        """
        assert self._fh is not None
        self.stats.format = "PCAPNG"
        linktypes: List[int] = []
        tsresol = 6                      # 默认微秒（10^-6）
        endian = "<"
        first: Optional[bytes] = first_block_head

        while True:
            if first is None:
                first = self._read_exact(4)
                if first is None:
                    break

            if first == b"\x0a\x0d\x0d\x0a":
                # ---- Section Header Block ----
                len_raw = self._read_exact(4)
                bom_raw = self._read_exact(4)
                if len_raw is None or bom_raw is None:
                    break
                if bom_raw == b"\x4d\x3c\x2b\x1a":
                    endian = "<"
                elif bom_raw == b"\x1a\x2b\x3c\x4d":
                    endian = ">"
                else:
                    self.stats.note(0.0, "pcapng", "SHB 字节序标识异常，按小端继续")
                    endian = "<"
                total_len = struct.unpack(endian + "I", len_raw)[0]
                # 新 Section 内接口编号和时间精度重新开始（pcapng 规范）
                linktypes = []
                tsresol = 6
                if total_len < 16 or total_len > 0x4000000:
                    self.stats.note(0.0, "badblock", f"SHB 长度异常 {total_len}")
                    break
                # 已消费 12 字节（type 4 + length 4 + BOM 4），还需跳过剩余部分
                if self._read_exact(total_len - 12) is None:
                    break
                first = None
                continue

            # ---- 普通块 ----
            block_type = struct.unpack(endian + "I", first)[0]
            len_raw = self._read_exact(4)
            if len_raw is None:
                break
            total_len = struct.unpack(endian + "I", len_raw)[0]
            if total_len < 12 or total_len > 0x4000000:
                self.stats.note(0.0, "badblock", f"块长度异常 {total_len}，停止解析")
                break
            # 已消费 8 字节（type 4 + length 4），还需读 total_len - 8 字节的
            # （块体 + 结尾的长度字段）
            tail = self._read_exact(total_len - 8)
            if tail is None:
                self.stats.note(0.0, "truncated", "文件末尾块被截断")
                break
            first = None
            body = tail[:-4] if len(tail) >= 4 else b""
            trailer = tail[-4:]
            if trailer and struct.unpack(endian + "I", trailer)[0] != total_len:
                self.stats.note(0.0, "pcapng", f"块 {block_type} 结尾长度与块头不一致，仍按块头解析")

            if block_type == 0x00000001:  # Interface Description Block
                if len(body) >= 8:
                    lt = struct.unpack(endian + "H", body[:2])[0]
                    linktypes.append(lt)
                    if self.stats.linktype == 0:
                        self.stats.linktype = lt
                else:
                    linktypes.append(LINKTYPE_ETHERNET)
                # 解析 if_tsresol 选项（选项码 9）
                off = 8
                while off + 4 <= len(body):
                    code, olen = struct.unpack(endian + "HH", body[off : off + 4])
                    if code == 0:
                        break
                    val = body[off + 4 : off + 4 + olen]
                    if code == 9 and val:
                        b = val[0]
                        if b & 0x80:
                            tsresol = -1 * (b & 0x7F)   # 负值表示 2 的幂
                        else:
                            tsresol = b
                    off += 4 + olen + ((4 - olen % 4) % 4)
            elif block_type == 0x00000006:  # Enhanced Packet Block
                if len(body) < 20:
                    continue
                iface, ts_high, ts_low, cap_len, orig_len = struct.unpack(
                    endian + "IIIII", body[:20]
                )
                data = body[20 : 20 + cap_len]
                ts = self._ng_ts(ts_high, ts_low, tsresol)
                lt = linktypes[iface] if iface < len(linktypes) else LINKTYPE_ETHERNET
                yield from self._emit(lt, data, ts, orig_len)
            elif block_type == 0x00000003:  # Simple Packet Block
                if len(body) < 4:
                    continue
                orig_len = struct.unpack(endian + "I", body[:4])[0]
                data = body[4:]
                lt = linktypes[0] if linktypes else LINKTYPE_ETHERNET
                yield from self._emit(lt, data, 0.0, orig_len)
            # 其余块（NRB/ISB/DSB 等）忽略

    def _read_exact(self, n: int) -> Optional[bytes]:
        assert self._fh is not None
        if n < 0:
            return None
        buf = b""
        while len(buf) < n:
            chunk = self._fh.read(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    @staticmethod
    def _ng_ts(high: int, low: int, tsresol: int) -> float:
        ticks = (high << 32) | low
        if tsresol == 6:
            return ticks / 1e6
        if tsresol == 9:
            return ticks / 1e9
        try:
            if tsresol < 0:
                # if_tsresol 最高位为 1 时表示 2^-n 秒（tsresol 存为 -n）
                return ticks / float(2 ** (-tsresol))
            return ticks / (10 ** tsresol)
        except (OverflowError, ZeroDivisionError):
            return ticks / 1e6

    # -- 统一出口 ----------------------------------------------------------
    def _emit(self, linktype: int, data: bytes, ts: float, orig_len: int) -> Iterator[Packet]:
        self.stats.total_frames += 1
        if not self.stats.first_ts:
            self.stats.first_ts = ts
        self.stats.last_ts = ts
        stripped = _strip_link_layer(linktype, data, self.stats, ts)
        if stripped is None:
            self.stats.non_ip_frames += 1
            return
        etype, body = stripped
        pkt: Optional[Packet] = None
        if etype == ETHERTYPE_IPV4:
            pkt = parse_ipv4(body, ts, orig_len, self.stats)
        elif etype == ETHERTYPE_IPV6:
            self.stats.ipv6_frames += 1
            pkt = parse_ipv6(body, ts, orig_len, self.stats)
        else:
            self.stats.non_ip_frames += 1
            return
        if pkt is None:
            self.stats.other_frames += 1
            return
        yield pkt


def sniff_files(paths: List[str]) -> Tuple[List[str], List[str]]:
    """把目录展开成 pcap/pcapng 文件列表，返回 (文件列表, 跳过的文件)。"""
    files: List[str] = []
    skipped: List[str] = []
    exts = (".pcap", ".pcapng", ".cap", ".dmp")
    for p in paths:
        if os.path.isdir(p):
            for name in sorted(os.listdir(p)):
                full = os.path.join(p, name)
                if os.path.isfile(full) and name.lower().endswith(exts):
                    files.append(full)
        elif os.path.isfile(p):
            files.append(p)
        else:
            skipped.append(p)
    return files, skipped
