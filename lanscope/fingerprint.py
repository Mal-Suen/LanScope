"""设备指纹：OUI 厂商库（内置兜底＋IEEE 自动更新）、主机名解析
（反向 DNS／mDNS／NetBIOS／SSDP）、设备类型推断。

OUI 库免维护：首次使用自动下载 IEEE 全量库并缓存，超过 30 天自动刷新；
下载失败时退回内置精简库（覆盖常见消费级厂商）。
"""
from __future__ import annotations

import json
import re
import socket
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Set

from .netinfo import _run_cmd, norm_mac

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
OUI_CACHE = DATA_DIR / "oui.json"
OUI_URL = "https://standards-oui.ieee.org/oui/oui.txt"
OUI_MAX_AGE = 30 * 24 * 3600

# 内置精简 OUI（离线兜底，仅收录高置信度前缀；全量库由 IEEE 自动下载）
EMBEDDED_OUI = {
    "ACDE48": "Apple, Inc.",
    "001B63": "Apple, Inc.",
    "3C0754": "Apple, Inc.",
    "F01898": "Apple, Inc.",
    "1499E2": "Apple, Inc.",
    "001632": "Samsung Electronics",
    "8C7712": "Samsung Electronics",
    "640980": "Xiaomi Communications",
    "8CBEBE": "Xiaomi Communications",
    "04CF8C": "Xiaomi Communications",
    "50C7BF": "TP-Link",
    "14CC20": "TP-Link",
    "04D9F5": "ASUSTek Computer",
    "2C4D54": "ASUSTek Computer",
    "B827EB": "Raspberry Pi Trading",
    "DCA632": "Raspberry Pi Trading",
    "E45F01": "Raspberry Pi Trading",
    "246F28": "Espressif",
    "30AEA4": "Espressif",
    "A4CF12": "Espressif",
    "001B21": "Intel Corporate",
    "3CA9F4": "Intel Corporate",
    "A0369F": "Intel Corporate",
    "00E04C": "Realtek Semiconductor",
    "525400": "QEMU (KVM)",
    "000C29": "VMware",
    "005056": "VMware",
    "000569": "VMware",
    "080027": "PCS Systemtechnik (VirtualBox)",
    "00155D": "Microsoft (Hyper-V)",
    "001422": "Dell",
    "F8DB88": "Dell",
    "3CD92B": "HP",
    "001AA1": "Cisco",
    "0418D6": "Ubiquiti Networks",
    "24A43C": "Ubiquiti Networks",
}

_oui_map: Optional[Dict[str, str]] = None
_oui_source = ""
_oui_ts = 0.0


def parse_oui_text(text: str) -> Dict[str, str]:
    """解析 IEEE oui.txt 的 (hex) 行为 {前缀: 厂商} 映射。"""
    out: Dict[str, str] = {}
    for line in text.splitlines():
        m = re.match(
            r"^\s*([0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2})\s+\(hex\)\s+(.+?)\s*$", line
        )
        if m:
            out[m.group(1).replace("-", "")] = m.group(2)
    return out


OUI_DOWNLOAD_DEADLINE = 300  # 下载总时限（秒）——IEEE 服务器国内访问约 30～40KB/s，全量约 6.6MB


def refresh_oui() -> bool:
    """下载并缓存 IEEE 全量 OUI 库（分块读取＋总时限，防慢速连接挂死）。"""
    try:
        req = urllib.request.Request(OUI_URL, headers={"User-Agent": "LanScope/1.0"})
        deadline = time.time() + OUI_DOWNLOAD_DEADLINE
        chunks = []
        with urllib.request.urlopen(req, timeout=30) as resp:
            while True:
                if time.time() > deadline:
                    return False
                chunk = resp.read(65536)
                if not chunk:
                    break
                chunks.append(chunk)
        text = b"".join(chunks).decode("utf-8", errors="replace")
        mapping = parse_oui_text(text)
        if len(mapping) < 1000:
            return False
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        tmp = OUI_CACHE.with_suffix(".json.tmp")
        tmp.write_text(
            json.dumps({"ts": time.time(), "map": mapping}, ensure_ascii=False),
            encoding="utf-8",
        )
        tmp.replace(OUI_CACHE)
        return True
    except Exception:
        return False


def _cache_data() -> Optional[Dict]:
    if not OUI_CACHE.exists():
        return None
    try:
        return json.loads(OUI_CACHE.read_text(encoding="utf-8"))
    except Exception:
        return None


def _cache_mtime() -> float:
    try:
        return OUI_CACHE.stat().st_mtime
    except OSError:
        return 0.0


def load_oui() -> Dict[str, str]:
    """加载 OUI 映射：优先本地缓存（不联网），否则内置精简库。

    以缓存文件 mtime 判断新旧——缓存被外部替换或引导后，运行中的进程
    也能在下次调用时自动换用新库，无需重启。
    """
    global _oui_map, _oui_source, _oui_ts
    mtime = _cache_mtime()
    if _oui_map is not None and mtime <= _oui_ts:
        return _oui_map
    data = _cache_data()
    if data and len(data.get("map", {})) > 1000:
        _oui_map = dict(data["map"])
        _oui_source = "ieee"
        _oui_ts = mtime
        return _oui_map
    if _oui_map is not None:
        return _oui_map
    _oui_map = dict(EMBEDDED_OUI)
    _oui_source = "embedded"
    _oui_ts = 0.0
    return _oui_map


def _refresh_and_load() -> None:
    if refresh_oui():
        load_oui()


def ensure_oui(background: bool = False) -> None:
    """缓存缺失或过期时刷新 IEEE 库；background=True 时不阻塞调用方。"""
    mtime = _cache_mtime()
    if mtime and time.time() - mtime <= OUI_MAX_AGE:
        load_oui()
        return
    if background:
        threading.Thread(target=_refresh_and_load, daemon=True).start()
    else:
        _refresh_and_load()


def oui_status() -> Dict[str, object]:
    loaded = load_oui()
    mtime = _cache_mtime()
    return {
        "source": _oui_source,
        "count": len(loaded),
        "ts": _oui_ts if _oui_source == "ieee" else 0.0,
        "fresh": bool(
            _oui_source == "ieee" and mtime and time.time() - mtime <= OUI_MAX_AGE
        ),
    }


def lookup_vendor(mac: str, oui: Optional[Dict[str, str]] = None) -> str:
    oui = oui or load_oui()
    return oui.get(mac.replace(":", "").upper()[:6], "") or ""


# ---------- 主机名解析 ----------


def _rdns_one(ip: str):
    try:
        return ip, socket.gethostbyaddr(ip)[0]
    except Exception:
        return ip, ""


def resolve_rdns(ips: List[str], timeout: float = 6.0) -> Dict[str, str]:
    """并发反向 DNS，整体超时；无结果者不出现于返回值。"""
    results: Dict[str, str] = {}
    if not ips:
        return results
    ex = ThreadPoolExecutor(max_workers=min(64, max(8, len(ips))))
    futures = [ex.submit(_rdns_one, ip) for ip in ips]
    try:
        for fut in as_completed(futures, timeout=timeout):
            ip, name = fut.result()
            if name:
                results.setdefault(ip, name)
    except TimeoutError:
        pass
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    return results


def _nbtstat_one(ip: str):
    out = _run_cmd(["nbtstat", "-A", ip], timeout=6)
    m = re.search(r"^(\S{1,15})\s*<00>\s+UNIQUE", out, re.M | re.I)
    return ip, (m.group(1).strip() if m else "")


def netbios_names(ips: List[str], timeout: float = 10.0) -> Dict[str, str]:
    """nbtstat 并发解析 NetBIOS 主机名（主要覆盖 Windows 设备）。"""
    results: Dict[str, str] = {}
    if not ips:
        return results
    ex = ThreadPoolExecutor(max_workers=min(12, max(4, len(ips))))
    futures = [ex.submit(_nbtstat_one, ip) for ip in ips]
    try:
        for fut in as_completed(futures, timeout=timeout):
            ip, name = fut.result()
            if name:
                results.setdefault(ip, name)
    except TimeoutError:
        pass
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    return results


_MDNS_SERVICE_HINTS = {
    "_googlecast": "tv",
    "_chromecast": "tv",
    "_airplay": "tv",
    "_raop": "tv",
    "_companion-link": "phone",
    "_ipp": "printer",
    "_printer": "printer",
    "_uscan": "printer",
    "_pdl-datastream": "printer",
    "_ssh": "pc",
    "_sftp-ssh": "pc",
    "_adisk": "nas",
    "_smb": "pc",
    "_workstation": "pc",
}

_MDNS_NAME_HINTS = {
    "android": "phone",
    "appletv": "tv",
    "homepod": "tv",
    "chromecast": "tv",
    "googlecast": "tv",
    "printer": "printer",
    "raspberrypi": "pc",
    "imac": "pc",
    "macbook": "pc",
    "synology": "nas",
    "ps4": "console",
    "ps5": "console",
    "xbox": "console",
    "nintendo": "console",
}


def mdns_names(
    ips: List[str], iface=None, timeout: float = 2.5
) -> Dict[str, Dict[str, object]]:
    """对每个 IP 发反向 mDNS 查询（in-addr.arpa.local），返回
    {ip: {"name": 主机名, "hints": [类型提示...]}}。需要 scapy。"""
    if not ips:
        return {}
    try:
        import logging

        logging.getLogger("scapy").setLevel(logging.CRITICAL)
        from scapy.all import DNS, DNSQR, IP, UDP, send, sniff
        from scapy.layers.dns import DNSRR
    except Exception:
        return {}

    def rev(ip: str) -> str:
        return ".".join(reversed(ip.split("."))) + ".in-addr.arpa"

    queries = [
        IP(dst="224.0.0.251")
        / UDP(sport=5353, dport=5353)
        / DNS(rd=1, qd=DNSQR(qname=rev(ip), qtype="PTR"))
        for ip in ips
    ]

    def sender():
        try:
            send(queries, inter=0.008, verbose=0)
        except Exception:
            pass

    out: Dict[str, Dict[str, object]] = {}
    try:
        captured = sniff(
            filter="udp port 5353",
            timeout=timeout,
            started_callback=sender,
            iface=iface,
            store=True,
        )
    except Exception:
        return out

    for p in captured:
        try:
            if not p.haslayer(DNS) or not p.haslayer(IP):
                continue
            if p[UDP].sport != 5353:
                continue
            src = p[IP].src
            info = out.setdefault(src, {"name": "", "hints": []})
            hints: Set[str] = set(info["hints"])  # type: ignore[arg-type]
            rr = p[DNS].an
            guard = 0
            while rr is not None and guard < 32:
                if isinstance(rr, DNSRR):
                    guard += 1
                    raw_name = rr.rrname
                    name_s = (
                        raw_name.decode(errors="replace")
                        if isinstance(raw_name, bytes)
                        else str(raw_name)
                    )
                    rdata = rr.rdata
                    rdata_s = (
                        rdata.decode(errors="replace")
                        if isinstance(rdata, bytes)
                        else str(rdata)
                    )
                    for token, hint in _MDNS_SERVICE_HINTS.items():
                        if token in name_s.lower() or token in rdata_s.lower():
                            hints.add(hint)
                    for token, hint in _MDNS_NAME_HINTS.items():
                        if token in rdata_s.lower():
                            hints.add(hint)
                    if rr.type == 12 and not info["name"]:
                        target = rdata_s
                        if target.endswith(".local."):
                            target = target[:-7]
                        elif target.endswith(".local"):
                            target = target[:-6]
                        info["name"] = target.strip(".")
                    rr = rr.payload if rr.payload else None
                else:
                    rr = None
            info["hints"] = sorted(hints)
        except Exception:
            continue
    return out


_MSEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 2\r\n"
    "ST: ssdp:all\r\n\r\n"
).encode()


def ssdp_discover(timeout: float = 3.0) -> Dict[str, Dict[str, str]]:
    """SSDP（UPnP）发现，返回 {ip: {"server":..., "location":..., "st":...}}。"""
    out: Dict[str, Dict[str, str]] = {}
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(0.8)
        sock.sendto(_MSEARCH, ("239.255.255.250", 1900))
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            ip = addr[0]
            headers: Dict[str, str] = {}
            for line in data.decode("utf-8", errors="replace").splitlines():
                if ":" in line:
                    k, _, v = line.partition(":")
                    headers[k.strip().upper()] = v.strip()
            entry = out.setdefault(ip, {})
            for key in ("LOCATION", "SERVER", "ST", "USN"):
                if headers.get(key):
                    entry[key.lower()] = headers[key]
    except Exception:
        pass
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass
    return out


def ssdp_details(
    discovered: Dict[str, Dict[str, str]], timeout: float = 3.0, max_fetch: int = 24
) -> Dict[str, Dict[str, str]]:
    """对 SSDP LOCATION 拉取设备描述 XML，提取友好名与设备类型。"""
    results: Dict[str, Dict[str, str]] = {}

    def grab(xml: str, tag: str) -> str:
        m = re.search(rf"<{tag}>(.*?)</{tag}>", xml, re.S)
        return m.group(1).strip() if m else ""

    for ip, info in list(discovered.items())[:max_fetch]:
        loc = info.get("location", "")
        if not loc:
            continue
        try:
            req = urllib.request.Request(loc, headers={"User-Agent": "LanScope/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                xml = resp.read(65536).decode("utf-8", errors="replace")
            dt = grab(xml, "deviceType")
            results[ip] = {
                "friendly_name": grab(xml, "friendlyName"),
                "device_type": dt.split(":")[-2] if ":" in dt else dt,
                "manufacturer": grab(xml, "manufacturer"),
                "model": grab(xml, "modelName"),
            }
        except Exception:
            continue
    return results


# ---------- 设备类型推断 ----------

ROUTER_VENDOR_KEYS = (
    "tp-link", "tplink", "tp link", "d-link", "dlink", "tenda", "mercury",
    "netcore", "netgear", "asustek", "asus", "ruijie", "mikrotik", "openwrt",
    "glinet", "ubiquiti", "zte", "fiberhome", "huawei", "xiaomi", "redmi",
)
PHONE_VENDOR_KEYS = (
    "xiaomi", "redmi", "honor", "oppo", "vivo", "oneplus", "meizu", "realme",
    "samsung", "huawei", "apple", "google", "motorola", "lenovo mobile",
)
IOT_VENDOR_KEYS = (
    "espressif", "tuya", "shenzhen", "beken", "queclink", "mokosmart",
    "sonoff", "philips", "legrand", "schneider",
)
NAS_VENDOR_KEYS = ("synology", "qnap", "western digital", "asustor", "ter master")
CAMERA_VENDOR_KEYS = ("hikvision", "dahua", "axis communications", "foscam", "vivotek")
PC_VENDOR_KEYS = (
    "dell", "hp", "lenovo", "asustek", "acer", "msi", "gigabyte", "intel",
    "apple", "raspberry pi", "microsoft",
)

DEVICE_TYPES = (
    "router", "pc", "phone", "tv", "console", "nas",
    "printer", "camera", "iot", "unknown",
)


def _vendor_match(vendor: str, keys) -> bool:
    low = (vendor or "").lower()
    return any(k in low for k in keys)


def infer_device_type(
    *,
    vendor: str = "",
    hostname: str = "",
    ports=None,
    mdns_hints=None,
    mdns_name: str = "",
    ssdp_type: str = "",
) -> str:
    """按信号强度推断设备类型；规则有序，先命中先返回。"""
    ports = set(ports or [])
    hints = set(mdns_hints or [])
    name_blob = f"{hostname} {mdns_name}".lower()

    if ssdp_type in ("InternetGatewayDevice", "WANDevice", "WANConnectionDevice"):
        return "router"
    if ssdp_type == "MediaRenderer":
        return "tv"
    if ssdp_type == "MediaServer":
        return "nas"
    if ssdp_type == "Printer":
        return "printer"

    if "printer" in hints:
        return "printer"
    if "tv" in hints:
        return "tv"
    if "console" in hints:
        return "console"
    if "nas" in hints and _vendor_match(vendor, NAS_VENDOR_KEYS):
        return "nas"

    if ports & {9100, 631}:
        return "printer"
    if 554 in ports:
        return "camera"
    if ports & {502, 47808}:
        return "iot"
    if _vendor_match(vendor, CAMERA_VENDOR_KEYS):
        return "camera"

    if "android" in name_blob:
        return "phone"
    if any(k in name_blob for k in ("appletv", "homepod", "chromecast", "googlecast")):
        return "tv"
    if any(k in name_blob for k in ("ps4", "ps5", "xbox", "nintendo")):
        return "console"
    if "raspberry" in name_blob:
        return "pc"
    if "printer" in name_blob:
        return "printer"
    if any(k in name_blob for k in ("xiaoqiang", "miwifi")):
        return "router"
    if any(k in name_blob for k in ("iphone", "ipad")):
        return "phone"
    if "phone" in hints:
        return "phone"
    if "pc" in hints:
        return "pc"

    if 3389 in ports:
        return "pc"
    if _vendor_match(vendor, NAS_VENDOR_KEYS) and 445 in ports:
        return "nas"
    if 445 in ports:
        return "pc"
    if 23 in ports:
        return "router"
    if ports & {80, 443, 8080}:
        if _vendor_match(vendor, ROUTER_VENDOR_KEYS):
            return "router"
        if _vendor_match(vendor, IOT_VENDOR_KEYS):
            return "iot"
    if _vendor_match(vendor, IOT_VENDOR_KEYS):
        return "iot"
    if _vendor_match(vendor, PHONE_VENDOR_KEYS):
        return "phone"
    if 22 in ports:
        return "pc"
    if _vendor_match(vendor, PC_VENDOR_KEYS):
        return "pc"
    return "unknown"
