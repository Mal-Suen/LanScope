"""主机发现：scapy ARP 全网段扫描为主，ping 扫描＋ARP 表解析为兜底。

scapy 路径能发现不响应 ping 的静默设备；无 Npcap 权限时自动降级。
"""
from __future__ import annotations

import ipaddress
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Tuple

from .netinfo import NetEnv, _run_cmd, norm_mac


def arp_sweep(
    env: NetEnv, timeout: float = 2.5, chunk_size: int = 256
) -> Optional[List[Dict[str, str]]]:
    """scapy ARP 扫描全网段，返回 [{ip, mac}]；不可用时返回 None。"""
    if not env.scapy_ok:
        return None
    try:
        import logging

        logging.getLogger("scapy").setLevel(logging.CRITICAL)
        from scapy.all import ARP, Ether, srp
    except Exception:
        return None
    targets = env.hosts()
    found: Dict[str, str] = {}
    try:
        for i in range(0, len(targets), chunk_size):
            chunk = targets[i : i + chunk_size]
            ans, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=chunk),
                timeout=timeout,
                iface=env.scapy_iface,
                verbose=0,
            )
            for _snd, rcv in ans:
                ip = rcv[ARP].psrc
                mac = norm_mac(rcv[Ether].src)
                if mac and mac != env.mac and ip != env.ip:
                    found[ip] = mac
    except Exception:
        if not found:
            return None
    return [{"ip": ip, "mac": mac} for ip, mac in found.items()]


def ping_sweep(env: NetEnv, workers: int = 100, timeout_ms: int = 600) -> List[str]:
    """并发 ping 全网段，返回存活 IP（TTL 判定，兼容中英文系统）。"""

    def ping(ip: str) -> Optional[str]:
        try:
            out = subprocess.run(
                ["ping", "-n", "1", "-w", str(timeout_ms), ip],
                capture_output=True,
                timeout=timeout_ms / 1000 + 2,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        low = out.stdout.lower()
        return ip if b"ttl=" in low else None

    targets = env.hosts()
    live: List[str] = []
    if not targets:
        return live
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for r in ex.map(ping, targets):
            if r:
                live.append(r)
    return live


_ARP_IF_RE = re.compile(r"^(?:接口|Interface)\s*[:：]\s*(\d+\.\d+\.\d+\.\d+)")
_ARP_ROW_RE = re.compile(
    r"^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9A-Fa-f]{2}(?:[-:][0-9A-Fa-f]{2}){5})\s+(\S+)"
)


def parse_arp_table(text: str) -> List[Dict[str, str]]:
    """解析 arp -a 输出（中英文均支持），过滤组播/广播伪条目。"""
    entries: List[Dict[str, str]] = []
    cur_if = ""
    for line in text.splitlines():
        stripped = line.strip()
        m = _ARP_IF_RE.match(stripped)
        if m:
            cur_if = m.group(1)
            continue
        rm = _ARP_ROW_RE.match(stripped)
        if rm:
            ip, mac, typ = rm.group(1), norm_mac(rm.group(2)), rm.group(3)
            if not mac:
                continue
            if mac.startswith(("01:00:5E", "33:33", "FF:FF:FF")):
                continue
            entries.append({"iface": cur_if, "ip": ip, "mac": mac, "type": typ})
    return entries


def read_arp_table() -> List[Dict[str, str]]:
    return parse_arp_table(_run_cmd(["arp", "-a"]))


def ping_arp_discover(env: NetEnv) -> List[Dict[str, str]]:
    """兜底发现：ping 扫描＋ARP 表合并（含未回 ping 但有动态 ARP 记录的静默设备）。"""
    live = set(ping_sweep(env))
    found: Dict[str, str] = {}
    for e in read_arp_table():
        if e["iface"] and e["iface"] != env.ip:
            continue
        if e["ip"] == env.ip or e["mac"] == env.mac:
            continue
        try:
            if ipaddress.ip_address(e["ip"]) not in env.network:
                continue
        except ValueError:
            continue
        if e["ip"] in live or e["type"].lower() in ("动态", "dynamic"):
            found[e["ip"]] = e["mac"]
    return [{"ip": ip, "mac": mac} for ip, mac in found.items()]


def discover_hosts(env: NetEnv) -> Tuple[List[Dict[str, str]], str]:
    """返回 (设备列表, 发现方式)。

    scapy 可用时：ARP 扫描与 ping 扫描互补合并——实测两类方式各有
    对方发现不了的设备（手机省电模式可能漏 ARP，个别设备不回 ping）；
    ping 独有的存活主机从 ARP 表补 MAC。scapy 不可用时整体降级。
    """
    arp_result = arp_sweep(env)
    if arp_result is None:
        return ping_arp_discover(env), "ping"
    found = {h["ip"]: h["mac"] for h in arp_result}
    live = ping_sweep(env)
    missing = [ip for ip in live if ip not in found]
    if missing:
        table = {
            e["ip"]: e["mac"]
            for e in read_arp_table()
            if e["iface"] in ("", env.ip)
        }
        for ip in missing:
            mac = table.get(ip)
            if mac and mac != env.mac:
                found[ip] = mac
    return [{"ip": ip, "mac": mac} for ip, mac in found.items()], "arp"
