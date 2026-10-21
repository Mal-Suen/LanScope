"""入侵检测：被动嗅探 ARP/DHCP（实时发现新设备、ARP 欺骗检测）＋
网关 MAC 主动监控。

被动路径依赖 scapy＋Npcap；不可用时自动退化为仅主动网关监控。
"""
from __future__ import annotations

import ipaddress
import threading
import time
from typing import Callable, Dict, Optional, Tuple

from .netinfo import NetEnv, norm_mac
from .discover import read_arp_table

_OBSERVE_THROTTLE = 30.0      # 同一 (mac, ip) 被动上报节流秒数
_BINDING_ACTIVE = 600.0       # 旧绑定视为活跃的窗口，超出则不判冲突
_CONFLICT_RATELIMIT = 600.0   # 同一 (ip, mac) 冲突告警限流秒数


class ArpWatch:
    """监听局域网 ARP/DHCP 流量，维护 IP↔MAC 绑定并检测异常。"""

    def __init__(
        self,
        env: NetEnv,
        on_observation: Callable,
        on_alert: Callable,
    ):
        self.env = env
        self.on_observation = on_observation
        self.on_alert = on_alert
        self._stop = threading.Event()
        self._bindings: Dict[str, Tuple[str, float]] = {}  # ip -> (mac, last_ts)
        self._gateway_mac: Optional[str] = None
        self._conflict_alerted: Dict[Tuple[str, str], float] = {}
        self._observed: Dict[Tuple[str, str], float] = {}
        self._sniff_thread: Optional[threading.Thread] = None
        self._gw_thread: Optional[threading.Thread] = None
        self._layers = None

    # ---------- 生命周期 ----------

    def start(self) -> None:
        self._gw_thread = threading.Thread(
            target=self._gateway_loop, daemon=True, name="lanscope-gwmon"
        )
        self._gw_thread.start()
        if not self.env.scapy_ok:
            return
        try:
            import logging

            logging.getLogger("scapy").setLevel(logging.CRITICAL)
            from scapy.all import ARP, sniff
            from scapy.layers.dhcp import BOOTP, DHCP

            self._layers = (ARP, BOOTP, DHCP)
        except Exception:
            return
        self._sniff_thread = threading.Thread(
            target=self._sniff_loop, daemon=True, name="lanscope-sniffer"
        )
        self._sniff_thread.start()

    def stop(self) -> None:
        self._stop.set()

    # ---------- 被动嗅探 ----------

    def _sniff_loop(self) -> None:
        from scapy.all import sniff

        while not self._stop.is_set():
            try:
                sniff(
                    prn=self._handle_packet,
                    filter="arp or (udp and (port 67 or port 68))",
                    timeout=5,
                    store=0,
                    iface=self.env.scapy_iface,
                    stop_filter=lambda _p: self._stop.is_set(),
                )
            except Exception:
                time.sleep(5)

    def _handle_packet(self, pkt) -> None:
        try:
            ARP, BOOTP, DHCP = self._layers
            if pkt.haslayer(ARP):
                self._handle_arp(pkt[ARP])
            elif pkt.haslayer(BOOTP):
                self._handle_dhcp(pkt, BOOTP, DHCP)
        except Exception:
            pass

    def _handle_arp(self, arp) -> None:
        ip = str(arp.psrc)
        mac = norm_mac(str(arp.hwsrc))
        if not mac or not ip or mac == self.env.mac:
            return
        try:
            if ipaddress.ip_address(ip) not in self.env.network:
                return
        except ValueError:
            return
        self._learn(ip, mac)
        self._report(mac, ip, None)

    def _handle_dhcp(self, pkt, BOOTP, DHCP) -> None:
        bootp = pkt[BOOTP]
        mac = norm_mac(bytes(bootp.chaddr)[:6].hex())
        if not mac or mac == self.env.mac:
            return
        opts: Dict[object, object] = {}
        if pkt.haslayer(DHCP):
            for opt in pkt[DHCP].options:
                if isinstance(opt, tuple) and len(opt) >= 2:
                    opts[opt[0]] = opt[1]
        ip = ""
        try:
            yiaddr = str(bootp.yiaddr)
            if yiaddr and yiaddr != "0.0.0.0":
                ip = yiaddr
        except Exception:
            pass
        if not ip:
            req = opts.get("requested_addr")
            if req:
                ip = req.decode(errors="replace") if isinstance(req, bytes) else str(req)
        if not ip:
            try:
                ciaddr = str(bootp.ciaddr)
                if ciaddr and ciaddr != "0.0.0.0":
                    ip = ciaddr
            except Exception:
                pass
        hostname = ""
        hn = opts.get("hostname")
        if isinstance(hn, bytes):
            hostname = hn.decode("utf-8", errors="replace").strip()
        elif hn:
            hostname = str(hn).strip()
        if ip:
            self._learn(ip, mac)
            self._report(mac, ip, hostname or None)

    def _report(self, mac: str, ip: str, hostname: Optional[str]) -> None:
        key = (mac, ip)
        now = time.time()
        if now - self._observed.get(key, 0) < _OBSERVE_THROTTLE and not hostname:
            return
        self._observed[key] = now
        try:
            self.on_observation(mac, ip, hostname=hostname, source="passive")
        except Exception:
            pass

    # ---------- 绑定与告警 ----------

    def _learn(self, ip: str, mac: str) -> None:
        now = time.time()
        entry = self._bindings.get(ip)
        if entry:
            old_mac, old_ts = entry
            if old_mac != mac and now - old_ts <= _BINDING_ACTIVE:
                self._bindings[ip] = (mac, now)
                if ip == self.env.gateway:
                    self.on_alert(
                        "critical",
                        "gateway_change",
                        f"网关 {ip} 的 MAC 地址从 {old_mac} 变为 {mac}，"
                        f"疑似 ARP 欺骗（中间人攻击）或网关更换",
                        mac,
                        ip,
                    )
                    return
                key = (ip, mac)
                if now - self._conflict_alerted.get(key, 0) > _CONFLICT_RATELIMIT:
                    self._conflict_alerted[key] = now
                    self.on_alert(
                        "critical",
                        "arp_conflict",
                        f"IP {ip} 同时被 {old_mac} 与 {mac} 两个 MAC 声称，"
                        f"疑似 ARP 欺骗",
                        mac,
                        ip,
                    )
                return
        self._bindings[ip] = (mac, now)

    # ---------- 主动网关监控 ----------

    def _gateway_loop(self) -> None:
        time.sleep(2.0)
        self._refresh_gateway_baseline()
        while not self._stop.wait(60.0):
            try:
                self._check_gateway()
            except Exception:
                pass

    def _gateway_entries(self):
        for e in read_arp_table():
            if e["ip"] == self.env.gateway and (
                not e["iface"] or e["iface"] == self.env.ip
            ):
                yield e

    def _refresh_gateway_baseline(self) -> None:
        if not self.env.gateway:
            return
        for e in self._gateway_entries():
            self._gateway_mac = e["mac"]
            self._bindings[self.env.gateway] = (e["mac"], time.time())
            return

    def _check_gateway(self) -> None:
        if not self.env.gateway:
            return
        for e in self._gateway_entries():
            cur = e["mac"]
            if self._gateway_mac and cur != self._gateway_mac:
                old = self._gateway_mac
                self._gateway_mac = cur
                self.on_alert(
                    "critical",
                    "gateway_change",
                    f"网关 {self.env.gateway} 的 MAC 从 {old} 变为 {cur}，"
                    f"疑似 ARP 欺骗（中间人攻击）或网关更换",
                    cur,
                    self.env.gateway,
                )
            elif not self._gateway_mac:
                self._gateway_mac = cur
            self._bindings[self.env.gateway] = (cur, time.time())
            return
