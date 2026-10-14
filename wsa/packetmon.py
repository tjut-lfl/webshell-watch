"""
网卡抓包监控（Linux AF_PACKET 原始套接字）。

诚实说明能力边界：
    服务器上看到的 HTTPS 是密文，抓包**看不到**加密马的载荷；
    因此抓包只适用于两种情况：
      1. 站点本身是 HTTP（明文），能完整看到请求体；
      2. 作为 HTTPS 的补充，提取 ClientHello 的 SNI/JA3 与请求头特征
         （例如攻击者用 HTTP 代理回连、或管理端直连 HTTP 端口）。
    需要看 HTTPS 明文，请使用访问日志（服务端在 TLS 之后记录明文）。

权限：需要 root 或 CAP_NET_RAW。systemd 单元已配置 AmbientCapabilities=CAP_NET_RAW。
"""

from __future__ import annotations

import os
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from .capture import FlowTable
from .models import Alert, Flow
from .pcap import ETHERTYPE_IPV4, ETHERTYPE_IPV6, Packet, ParseStats, parse_ipv4, parse_ipv6

SNIFF_SOURCE = "抓包(明文HTTP)"

ETH_P_ALL = 0x0003
SO_ATTACH_FILTER = 26


def _euid() -> int:
    """获取有效 uid；Windows 上没有 geteuid，返回 -1 表示不适用。"""
    getter = getattr(os, "geteuid", None)
    return getter() if callable(getter) else -1


@dataclass
class SniffStats:
    frames: int = 0
    tcp: int = 0
    bytes: int = 0
    dropped_fragments: int = 0
    other: int = 0
    started_at: float = field(default_factory=time.time)


class PacketMonitor:
    """AF_PACKET 抓包 + 流重组 + 复用检测引擎。"""

    def __init__(
        self,
        analyzer,
        alert_fn: Callable[[Alert], None],
        log_fn: Callable[[str, str], None],
        interface: str = "any",
        idle_flush: float = 20.0,
        max_flows: int = 20000,
        local_ips: Optional[List[str]] = None,
    ):
        self.analyzer = analyzer
        self.alert_fn = alert_fn
        self.log = log_fn
        self.interface = interface or "any"
        self.idle_flush = float(idle_flush)
        self.max_flows = int(max_flows)
        self.local_ips = list(local_ips or self._local_ips())
        self.stats = SniffStats()
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._table: Optional[FlowTable] = None
        self._pstats = ParseStats()
        self.alerts_emitted = 0
        self.flows_analyzed = 0

    # ------------------------------------------------------------------
    @staticmethod
    def _local_ips() -> List[str]:
        ips: List[str] = []
        try:
            hostname = socket.gethostname()
            for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
                ip = info[4][0]
                if ip not in ips:
                    ips.append(ip)
        except OSError:
            pass
        return ips

    # ------------------------------------------------------------------
    def start(self) -> tuple[bool, str]:
        if self._running:
            return True, "抓包已在运行"
        if not hasattr(socket, "AF_PACKET"):
            return False, "当前平台不支持 AF_PACKET（本功能仅限 Linux）"
        if _euid() != 0 and not self._has_cap_net_raw():
            return False, (
                "抓包需要 root 或 CAP_NET_RAW 权限。"
                "请用 sudo 运行，或按 README 给 systemd 单元配置 AmbientCapabilities。"
            )
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
            if self.interface and self.interface != "any":
                sock.bind((self.interface, 0))
            sock.settimeout(1.0)
        except PermissionError:
            return False, "创建原始套接字被拒绝：请用 root 或授予 CAP_NET_RAW"
        except OSError as exc:
            return False, f"创建抓包套接字失败：{exc}"

        self._sock = sock
        self._running = True
        self._table = FlowTable(source=SNIFF_SOURCE, local_ips=self.local_ips)
        self._thread = threading.Thread(target=self._loop, name="packet-monitor", daemon=True)
        self._thread.start()
        self.log(
            "INFO",
            f"抓包已启动：接口={self.interface}，本机地址={','.join(self.local_ips) or '未知'}；"
            "仅能分析明文 HTTP 与 TLS 指纹",
        )
        return True, "抓包已启动"

    @staticmethod
    def _has_cap_net_raw() -> bool:
        """通过 /proc/self/status 判断是否具备 CAP_NET_RAW。"""
        try:
            with open("/proc/self/status", "r", encoding="utf-8") as fh:
                for line in fh:
                    if line.startswith("CapEff:"):
                        mask = int(line.split(":")[1].strip(), 16)
                        return bool(mask & (1 << 13))
        except (OSError, ValueError):
            pass
        return False

    def stop(self) -> None:
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        if self._thread:
            self._thread.join(timeout=3)
            self._thread = None
        if self._table:
            for flow in self._table.finish():
                self._analyze(flow)
            self._table = None
        self.log("INFO", self.summary())

    # ------------------------------------------------------------------
    def _loop(self) -> None:
        sock = self._sock
        table = self._table
        if sock is None or table is None:
            return
        iface_index = 0
        if self.interface and self.interface != "any":
            try:
                iface_index = socket.if_nametoindex(self.interface)
            except OSError:
                iface_index = 0
        last_flush = time.time()
        while self._running:
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                data, addr = b"", None
            except OSError:
                break
            if data and len(data) >= 14:
                if iface_index and addr and addr[0] != iface_index:
                    continue
                self.stats.frames += 1
                self.stats.bytes += len(data)
                pkt = self._parse_eth(data)
                if pkt is not None:
                    self.stats.tcp += 1
                    try:
                        table.feed(pkt)
                    except Exception:
                        self.stats.other += 1
            now = time.time()
            if now - last_flush >= 1.0:
                last_flush = now
                for flow in table.flush_idle(self.idle_flush, now=now):
                    self._analyze(flow)
                # 尚未结束的流：先取 TLS 指纹与 HTTP 事务做一次分析
                for flow in table.live_flows():
                    if flow.transactions or flow.tls:
                        found = self.analyzer.analyze_flow(flow)
                        if found:
                            self.alerts_emitted += len(found)
                            for a in found:
                                a.source = SNIFF_SOURCE
                                self.alert_fn(a)

    def _parse_eth(self, data: bytes) -> Optional[Packet]:
        etype = struct.unpack("!H", data[12:14])[0]
        body = data[14:]
        # VLAN 叠加
        while etype == 0x8100 or etype == 0x88A8:
            if len(body) < 4:
                return None
            etype = struct.unpack("!H", body[2:4])[0]
            body = body[4:]
        if etype == ETHERTYPE_IPV4:
            pkt = parse_ipv4(body, time.time(), len(data), self._pstats)
        elif etype == ETHERTYPE_IPV6:
            pkt = parse_ipv6(body, time.time(), len(data), self._pstats)
        else:
            self.stats.other += 1
            return None
        if pkt is None:
            return None
        if pkt.fragmented:
            self.stats.dropped_fragments += 1
            return None
        return pkt

    def _analyze(self, flow: Flow) -> None:
        self.flows_analyzed += 1
        found = self.analyzer.analyze_flow(flow)
        if found:
            self.alerts_emitted += len(found)
            for a in found:
                a.source = SNIFF_SOURCE
                self.alert_fn(a)

    def summary(self) -> str:
        s = self.stats
        return (
            f"抓包统计：帧 {s.frames}，TCP {s.tcp}，流量 {s.bytes / 1024:.0f} KB，"
            f"分析会话 {self.flows_analyzed}，告警 {self.alerts_emitted}"
        )
