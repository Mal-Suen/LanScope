"""本机网络环境识别：解析 ipconfig、选择局域网网卡、定位网关、对接 scapy 网卡。

兼容中文与英文 Windows 的 ipconfig 输出；自动排除 Clash TUN、VPN、虚拟机等
非物理局域网适配器。
"""
from __future__ import annotations

import ipaddress
import re
import subprocess
from dataclasses import dataclass, field
from typing import Any, List, Optional

_ADAPTER_RE = re.compile(r"^(.*?(?:适配器|[Aa]dapter).*)[:：]\s*$")
_FIELD_RE = re.compile(r"^\s*([^:.]+?)\s*(?:\.\s*)+[:：]\s*(.*)$")
_IPV4_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")

_EXCLUDE_RE = re.compile(
    r"(clash|meta|\btun\b|\btap\b|wireguard|tailscale|openvpn|vmware|virtualbox|"
    r"hyper-v|loopback|bluetooth|isatap|teredo|tunnel|隧道|回环|蓝牙)",
    re.IGNORECASE,
)

_NAME_PREFIXES = (
    "无线局域网适配器",
    "以太网适配器",
    "隧道适配器",
    "PPP 适配器",
    "Wireless LAN adapter",
    "Ethernet adapter",
    "Unknown adapter",
    "Tunnel adapter",
    "PPP adapter",
)


def norm_mac(s: str) -> str:
    """把任意分隔符的 MAC 规范化为 AA:BB:CC:DD:EE:FF，非法输入返回空串。"""
    hexpart = re.sub(r"[^0-9A-Fa-f]", "", s or "")[:12]
    if len(hexpart) < 12:
        return ""
    h = hexpart.upper()
    return ":".join(h[i : i + 2] for i in range(0, 12, 2))


def _run_cmd(cmd: List[str], timeout: int = 15) -> str:
    try:
        out = subprocess.run(cmd, capture_output=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    raw = out.stdout
    for enc in ("utf-8", "gbk", "oem"):
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("utf-8", errors="replace")


@dataclass
class Adapter:
    title: str
    name: str = ""
    description: str = ""
    mac: str = ""
    ipv4: List[str] = field(default_factory=list)
    netmasks: List[str] = field(default_factory=list)
    gateway: str = ""
    dhcp: bool = False


def _clean_name(title: str) -> str:
    name = title
    for prefix in _NAME_PREFIXES:
        if name.startswith(prefix):
            name = name[len(prefix) :]
            break
    return name.strip()


def parse_ipconfig(text: str) -> List[Adapter]:
    """解析 ipconfig /all 输出为适配器列表（中英文标签均支持）。"""
    adapters: List[Adapter] = []
    cur: Optional[Adapter] = None
    for line in text.splitlines():
        m = _ADAPTER_RE.match(line)
        if m:
            title = m.group(1).strip()
            cur = Adapter(title=title, name=_clean_name(title))
            adapters.append(cur)
            continue
        if cur is None:
            continue
        fm = _FIELD_RE.match(line)
        if not fm:
            continue
        label = fm.group(1).strip()
        value = fm.group(2).strip()
        low = label.lower()
        if "ipv4" in low:
            ipm = _IPV4_RE.search(value)
            if ipm:
                try:
                    if not ipaddress.ip_address(ipm.group(1)).is_link_local:
                        cur.ipv4.append(ipm.group(1))
                except ValueError:
                    pass
        elif "子网掩码" in label or "subnet mask" in low:
            mm = _IPV4_RE.search(value)
            if mm:
                cur.netmasks.append(mm.group(1))
        elif "默认网关" in label or "default gateway" in low:
            gm = _IPV4_RE.search(value)
            if gm:
                cur.gateway = gm.group(1)
        elif "描述" in label or "description" in low:
            cur.description = value
        elif "物理地址" in label or "physical address" in low:
            cur.mac = norm_mac(value)
        elif "dhcp" in low and ("已启用" in label or "enabled" in low):
            cur.dhcp = value.lower() in ("是", "yes", "true")
    return adapters


def _adapter_score(a: Adapter) -> int:
    if not a.ipv4:
        return -1000
    try:
        ip = ipaddress.ip_address(a.ipv4[0])
    except ValueError:
        return -1000
    if ip.is_loopback or ip.is_link_local:
        return -1000
    if ip in ipaddress.ip_network("198.18.0.0/15"):  # Clash fake-ip 段
        return -1000
    blob = f"{a.title} {a.name} {a.description}"
    score = 0
    if _EXCLUDE_RE.search(blob):
        score -= 500
    if ip.is_private:
        score += 10
    if a.gateway:
        score += 20
        mask = a.netmasks[0] if a.netmasks else "255.255.255.0"
        try:
            net = ipaddress.ip_network(f"{a.ipv4[0]}/{mask}", strict=False)
            if ipaddress.ip_address(a.gateway) in net:
                score += 10
        except ValueError:
            pass
    if a.dhcp:
        score += 3
    if str(ip).startswith("192.168."):
        score += 2
    return score


def select_lan_adapter(adapters: List[Adapter]) -> Optional[Adapter]:
    best, best_score = None, -10**9
    for a in adapters:
        s = _adapter_score(a)
        if s > best_score:
            best, best_score = a, s
    if best is None or best_score <= -1000:
        return None
    return best


@dataclass
class NetEnv:
    ip: str
    netmask: str
    gateway: str
    adapter: str
    mac: str
    scapy_iface: Any = None
    scapy_ok: bool = False

    @property
    def network(self) -> ipaddress.IPv4Network:
        return ipaddress.ip_network(f"{self.ip}/{self.netmask}", strict=False)

    @property
    def cidr(self) -> str:
        return str(self.network)

    def hosts(self, limit: int = 4096) -> List[str]:
        hosts = [str(h) for h in self.network.hosts()]
        if len(hosts) > limit:
            hosts = hosts[:limit]
        return [h for h in hosts if h != self.ip]

    def describe(self) -> str:
        return f"网卡 {self.adapter}｜本机 {self.ip}｜网段 {self.cidr}｜网关 {self.gateway}"


def _iter_scapy_ifaces() -> List[Any]:
    try:
        from scapy.config import conf

        _ = conf.iface  # 触发 scapy 接口系统惰性初始化（2.8+）
        ifaces = conf.ifaces
        if hasattr(ifaces, "values"):
            return list(ifaces.values())
        if hasattr(ifaces, "data") and hasattr(ifaces.data, "values"):
            return list(ifaces.data.values())
        return list(ifaces)
    except Exception:
        return []


def _find_scapy_iface(adapter: Adapter, ip: str) -> Optional[Any]:
    ifaces = _iter_scapy_ifaces()
    for itf in ifaces:
        if str(getattr(itf, "ip", "") or "") == ip:
            return itf
    if adapter.mac:
        for itf in ifaces:
            if norm_mac(str(getattr(itf, "mac", "") or "")) == adapter.mac:
                return itf
    desc = (adapter.description or "")[:16]
    if desc:
        for itf in ifaces:
            if desc in (getattr(itf, "description", "") or ""):
                return itf
    if adapter.name:
        for itf in ifaces:
            if str(getattr(itf, "name", "") or "") == adapter.name:
                return itf
    return _default_scapy_iface(ip, adapter.mac)


def _default_scapy_iface(ip: str, own_mac: str) -> Optional[Any]:
    """conf.ifaces 不可用时，校验 scapy 默认网卡是否就是目标局域网卡。"""
    try:
        from scapy.config import conf

        itf = conf.iface
        if itf is None:
            return None
        itf_ip = str(getattr(itf, "ip", "") or "")
        itf_mac = norm_mac(str(getattr(itf, "mac", "") or ""))
        if itf_ip and itf_ip == ip:
            return itf
        if own_mac and itf_mac and itf_mac == own_mac:
            return itf
        if not itf_ip and not itf_mac:
            return itf  # 属性不可读时信任 scapy 的默认选择
        return None
    except Exception:
        return None


def _scapy_default_gateway() -> Optional[str]:
    try:
        from scapy.config import conf

        route = conf.route.route("0.0.0.0")
        if len(route) >= 3:
            gw = str(route[2])
            if gw and gw != "0.0.0.0":
                return gw
    except Exception:
        pass
    return None


def _guess_gateway(ip: str, mask: str) -> Optional[str]:
    try:
        net = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
        return str(net.network_address + 1)
    except ValueError:
        return None


def _attach_scapy(env: NetEnv, adapter: Adapter) -> None:
    try:
        import logging

        logging.getLogger("scapy").setLevel(logging.CRITICAL)
        import scapy.all  # noqa: F401 —— 触发 Windows 网卡/路由完整初始化，仅 import scapy.config 时 conf.iface 为 None
        from scapy.config import conf

        itf = _find_scapy_iface(adapter, env.ip)
        if itf is None:
            return
        conf.iface = itf
        env.scapy_iface = itf
        env.scapy_ok = True
    except Exception:
        env.scapy_ok = False


def detect_env() -> NetEnv:
    """识别当前局域网环境；找不到可用网卡时抛出 RuntimeError。"""
    text = _run_cmd(["ipconfig", "/all"])
    adapters = parse_ipconfig(text)
    best = select_lan_adapter(adapters)
    if best is None or not best.ipv4:
        raise RuntimeError("未能从 ipconfig 中识别出可用的局域网网卡")
    ip = best.ipv4[0]
    mask = best.netmasks[0] if best.netmasks else "255.255.255.0"
    gateway = best.gateway or _guess_gateway(ip, mask) or _scapy_default_gateway() or ""
    env = NetEnv(
        ip=ip,
        netmask=mask,
        gateway=gateway,
        adapter=best.name or best.title,
        mac=best.mac,
    )
    _attach_scapy(env, best)
    return env
