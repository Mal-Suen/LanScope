"""深度侦察：对单台设备做全端口扫描、服务指纹、OS 识别、暴露面风险
规则与已知漏洞签名匹配，产出可导出的攻击面报告。

定位是侦察与识别层——漏洞利用不进本工具；报告可导出 JSON，
衔接 Kali/Metasploit 工作流。
"""
from __future__ import annotations

import re
import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional

from .netinfo import _run_cmd
from .portscan import _decode

# 本机安全软件「邮件防护」会 WFP 劫持的端口——对任何目标都握手成功，
# 全端口扫描必须跳过，否则报告全是假阳性（见 portscan.COMMON_PORTS 注释）
HIJACKED_PORTS = {25, 110, 143}

PORT_NAMES: Dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain",
    80: "http", 110: "pop3", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 443: "https", 445: "microsoft-ds", 465: "smtps",
    500: "isakmp", 502: "modbus", 515: "printer", 548: "afp",
    554: "rtsp", 587: "submission", 631: "ipp", 636: "ldaps",
    873: "rsync", 993: "imaps", 995: "pop3s", 1080: "socks",
    1433: "mssql", 1521: "oracle", 1723: "pptp", 1900: "upnp",
    2323: "telnet-alt", 2375: "docker", 2376: "docker-tls",
    3128: "squid", 3306: "mysql", 3389: "rdp", 4848: "glassfish",
    5000: "upnp", 5060: "sip", 5432: "postgresql", 5555: "adb",
    5601: "kibana", 5672: "amqp", 5900: "vnc", 5984: "couchdb",
    6379: "redis", 6667: "irc", 7547: "tr069-cwmp", 8000: "http-alt",
    8008: "http-alt", 8080: "http-proxy", 8081: "http-alt",
    8443: "https-alt", 8888: "http-alt", 9000: "http-alt",
    9090: "websm", 9100: "jetdirect", 9200: "elasticsearch",
    10000: "webmin", 11211: "memcached", 27017: "mongodb",
    32400: "plex", 37215: "huawei-upnp", 49152: "upnp",
    62078: "iphone-sync",
}

_HTTP_GUESS = {
    80, 81, 280, 591, 8000, 8008, 8080, 8081, 8082, 8088, 8181,
    8888, 9000, 9090, 10000, 32400, 5000, 5001,
}
_TLS_PORTS = {443, 8443, 9443}
_PREBANNER_PORTS = {21, 22, 23, 25, 110, 143, 587, 993, 995, 6667}


# ---------- 全端口扫描 ----------

def full_port_scan(
    ip: str, timeout: float = 0.8, workers: int = 500
) -> List[int]:
    """1～65535 connect 扫描（跳过本机被劫持端口）。

    局域网设备对关闭端口立即回 RST，实测单台约 10～40 秒；
    静默丢包（filtered）的端口占满超时，最坏约 2 分钟。
    """

    def probe(p: int) -> Optional[int]:
        if p in HIJACKED_PORTS:
            return None
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            return p if s.connect_ex((ip, p)) == 0 else None
        except OSError:
            return None
        finally:
            try:
                s.close()
            except OSError:
                pass

    results: List[int] = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for r in ex.map(probe, range(1, 65536)):
            if r is not None:
                results.append(r)
    return results


# ---------- 服务指纹 ----------

def grab_banner(ip: str, port: int, timeout: float = 2.5) -> str:
    """等待服务主动发送的问候 banner（SSH/FTP 等）。"""
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        s.settimeout(timeout)
        data = s.recv(512)
        s.close()
        return data.decode("utf-8", errors="replace").strip()[:200]
    except OSError:
        return ""


def _cert_subjects(der: bytes) -> List[str]:
    """从 DER 证书里尽力提取 CN（OID 2.5.4.3），失败返回空。"""
    try:
        found = re.findall(
            rb"\x55\x04\x03[\x0c\x13][\x01-\x40]([\x20-\x7e]{1,64})", der
        )
        return [f.decode("ascii", errors="replace") for f in found[:2]]
    except Exception:
        return []


def http_probe(
    ip: str, port: int, use_tls: bool = False, timeout: float = 3.0
) -> Dict[str, Any]:
    """GET / 并解析状态码、Server 头、标题、登录页特征。"""
    out: Dict[str, Any] = {
        "status": 0, "server": "", "x_powered_by": "", "title": "",
        "login_page": False, "body_bytes": 0, "cert": [],
    }
    try:
        raw = socket.create_connection((ip, port), timeout=timeout)
        raw.settimeout(timeout)
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(raw, server_hostname=ip)
            der = s.getpeercert(binary_form=True)
            if der:
                out["cert"] = _cert_subjects(der)
        else:
            s = raw
        s.sendall(
            f"GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: LanScope/1.1\r\n"
            f"Connection: close\r\n\r\n".encode()
        )
        data = b""
        while len(data) < 16384:
            try:
                chunk = s.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
        s.close()
    except OSError:
        return {}
    if not data:
        return {}
    text = _decode(data)
    head, _, body = text.partition("\r\n\r\n")
    m = re.match(r"HTTP/[\d.]+\s+(\d{3})", head)
    if not m:
        return {}
    out["status"] = int(m.group(1))
    for line in head.splitlines()[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            low_key = k.strip().lower()
            if low_key == "server":
                out["server"] = v.strip()[:120]
            elif low_key == "x-powered-by":
                out["x_powered_by"] = v.strip()[:120]
    tm = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    if tm:
        out["title"] = re.sub(r"\s+", " ", tm.group(1)).strip()[:80]
    low = body.lower()
    out["login_page"] = bool(
        re.search(r"<input[^>]*type=[\"']?password", body, re.I)
    ) or any(kw in low for kw in ("登录", "login", "password", "管理", "admin"))
    out["body_bytes"] = len(body)
    return out


def _service_from_banner(banner: str, fallback: str) -> str:
    low = banner.lower()
    if "ssh" in low:
        return "ssh"
    if "ftp" in low or low.startswith("220"):
        return "ftp"
    if "smtp" in low or "esmtp" in low:
        return "smtp"
    if "telnet" in low:
        return "telnet"
    if "rtsp" in low:
        return "rtsp"
    if "rfb" in low:
        return "vnc"
    if "mysql" in low or "mariadb" in low:
        return "mysql"
    if banner.startswith("\x16\x03") or banner.startswith("\x15\x03"):
        return "tls"
    return fallback


def fingerprint_port(ip: str, port: int, timeout: float = 3.0) -> Dict[str, Any]:
    """识别单个开放端口：服务名、banner、HTTP/HTTPS、TLS 证书、协议探针。"""
    info: Dict[str, Any] = {
        "port": port,
        "service": PORT_NAMES.get(port, ""),
        "banner": "",
        "http": None,
        "product": "",
        "version": "",
        "extrainfo": "",
        "cert": [],
    }
    if port in _HTTP_GUESS or port in _TLS_PORTS:
        http = http_probe(ip, port, use_tls=port in _TLS_PORTS, timeout=timeout)
        if http:
            info["http"] = http
            info["cert"] = http.get("cert", [])
            info["service"] = info["service"] or (
                "https" if port in _TLS_PORTS else "http"
            )
            return info
    if port in _PREBANNER_PORTS:
        info["banner"] = grab_banner(ip, port, timeout)
        if info["banner"]:
            info["service"] = _service_from_banner(info["banner"], info["service"])
            return info
    # 未知端口：HTTP 试探 → 协议探针 → TLS 证书 → banner 等待
    http = http_probe(ip, port, timeout=2.0)
    if http:
        info["http"] = http
        info["service"] = info["service"] or "http"
        return info
    proto = probe_unknown_port(ip, port, timeout=1.5)
    if proto and proto.get("service"):
        info["service"] = proto["service"]
        info["banner"] = proto.get("banner", "")
        return info
    if proto and proto.get("banner"):
        info["banner"] = proto["banner"]
    tls = tls_probe(ip, port, timeout=2.0)
    if tls["tls"]:
        info["service"] = "tls"
        info["cert"] = tls["cert"]
        info["banner"] = "TLS" + (
            f"（证书：{' / '.join(tls['cert'])}）" if tls["cert"] else ""
        )
        return info
    if not info["banner"]:
        b = grab_banner(ip, port, timeout=1.5)
        if b:
            info["banner"] = b
            info["service"] = _service_from_banner(b, info["service"])
    return info


# ---------- 协议探测库 ----------

_MQTT_CONNECT = (
    b"\x10\x1a"                      # CONNECT, 剩余长度 26
    b"\x00\x04MQTT\x04\x02\x00\x3c"  # 协议名/级别4/清洁会话/保活60
    b"\x00\x0elanscope-probe"         # 客户端 ID
)


def _smb_negotiate() -> bytes:
    """SMB1 协商请求（无方言），任何 SMB 响应都含 \\xffSMB。"""
    payload = b"\xffSMB\x72" + b"\x00" * 25 + b"\x00" + b"\x00\x00"
    return b"\x00" + len(payload).to_bytes(2, "big") + payload


def probe_unknown_port(
    ip: str, port: int, timeout: float = 1.5
) -> Optional[Dict[str, Any]]:
    """对未识别端口依次发送协议握手，命中即返回；全部未中但有响应则带回 banner。"""
    probes = [
        ("rtsp", b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n",
         rb"RTSP/[\d.]+\s+\d{3}"),
        ("sip",
         b"OPTIONS sip:probe@lan SIP/2.0\r\nVia: SIP/2.0/UDP lanscope\r\n"
         b"From: <sip:probe@lan>\r\nTo: <sip:probe@lan>\r\nCall-ID: ls\r\n"
         b"CSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n",
         rb"SIP/2\.0\s+\d{3}"),
        ("redis", b"PING\r\n",
         rb"^\+PONG|^-(NOAUTH|ERR|DENIED|WRONG|AUTH)"),
        ("mqtt", _MQTT_CONNECT, rb"^\x20"),
        ("smb", _smb_negotiate(), rb"\xffSMB"),
    ]
    fallback_banner = ""
    for name, payload, pattern in probes:
        try:
            s = socket.create_connection((ip, port), timeout=timeout)
            s.settimeout(timeout)
            s.sendall(payload)
            data = s.recv(256)
            s.close()
        except OSError:
            continue
        if not data:
            continue
        if re.search(pattern, data, re.S):
            return {
                "service": name,
                "banner": data.decode("utf-8", errors="replace").strip()[:200],
            }
        if not fallback_banner:
            fallback_banner = data.decode("utf-8", errors="replace").strip()[:200]
    if fallback_banner:
        return {"service": "", "banner": fallback_banner}
    return None


def tls_probe(ip: str, port: int, timeout: float = 2.0) -> Dict[str, Any]:
    """仅做 TLS 握手提取证书（不发应用数据），识别 TLS 服务。"""
    out: Dict[str, Any] = {"tls": False, "cert": []}
    try:
        raw = socket.create_connection((ip, port), timeout=timeout)
        raw.settimeout(timeout)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(raw, server_hostname=ip)
        der = s.getpeercert(binary_form=True)
        out["tls"] = True
        if der:
            out["cert"] = _cert_subjects(der)
        s.close()
    except OSError:
        pass
    return out


def fingerprint_all(
    ip: str, ports: List[int], timeout: float = 3.0, workers: int = 24
) -> List[Dict[str, Any]]:
    """并发指纹全部开放端口。"""
    if not ports:
        return []
    with ThreadPoolExecutor(max_workers=min(workers, len(ports))) as ex:
        infos = list(ex.map(lambda p: fingerprint_port(ip, p, timeout), ports))
    return infos


# ---------- OS 识别 ----------

def os_fingerprint(ip: str, timeout: float = 4.0) -> Dict[str, Any]:
    """TTL 为主、服务特征为辅的 OS 猜测（局域网单跳，TTL≈初始值）。"""
    out: Dict[str, Any] = {"ttl": None, "guess": "unknown", "basis": ""}
    text = _run_cmd(["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip])
    m = re.search(r"TTL=(\d+)", text, re.I)
    if not m:
        return out
    ttl = int(m.group(1))
    out["ttl"] = ttl
    if ttl <= 32:
        out["guess"], out["basis"] = "Windows（旧协议栈）", f"TTL={ttl}"
    elif 60 <= ttl <= 64:
        out["guess"], out["basis"] = "Linux/Android/iOS/macOS", f"TTL={ttl}"
    elif 100 <= ttl <= 128:
        out["guess"], out["basis"] = "Windows", f"TTL={ttl}"
    elif 190 <= ttl <= 200:
        out["guess"], out["basis"] = "打印机/扫描仪等外设", f"TTL={ttl}"
    elif 240 <= ttl <= 255:
        out["guess"], out["basis"] = "嵌入式设备（路由器/交换机）", f"TTL={ttl}"
    else:
        out["guess"], out["basis"] = "未知", f"TTL={ttl}"
    return out


# ---------- SNMP 探测 ----------

_SYSDESCR_OID = "1.3.6.1.2.1.1.1.0"
_SYSNAME_OID = "1.3.6.1.2.1.1.5.0"


def _ber_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    out = []
    while n:
        out.insert(0, n & 0xFF)
        n >>= 8
    return bytes([0x80 | len(out)]) + bytes(out)


def _ber_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _ber_len(len(value)) + value


def _oid_encode(oid: str) -> bytes:
    parts = [int(x) for x in oid.split(".")]
    out = bytes([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        if p == 0:
            out += b"\x00"
            continue
        stack = []
        while p:
            stack.insert(0, p & 0x7F)
            p >>= 7
        for i in range(1, len(stack)):
            stack[i] |= 0x80
        out += bytes(stack)
    return out


def _snmp_get_request(oids, community: str = "public") -> bytes:
    """构造 SNMP v2c GET 请求（version 字段 1＝v2c）。"""
    varbinds = b""
    for oid in oids:
        varbinds += _ber_tlv(
            0x30, _ber_tlv(0x06, _oid_encode(oid)) + _ber_tlv(0x05, b"")
        )
    pdu = (
        _ber_tlv(0x02, b"\x01")       # request-id
        + _ber_tlv(0x02, b"\x00")     # error-status
        + _ber_tlv(0x02, b"\x00")     # error-index
        + _ber_tlv(0x30, varbinds)
    )
    msg = (
        _ber_tlv(0x02, b"\x01")
        + _ber_tlv(0x04, community.encode())
        + _ber_tlv(0xA0, pdu)
    )
    return _ber_tlv(0x30, msg)


def _ber_parse(buf: bytes):
    """极简 TLV 解析，返回 (tag, value, rest) 或 None。"""
    if len(buf) < 2:
        return None
    tag = buf[0]
    i = 1
    first = buf[i]
    i += 1
    if first < 0x80:
        length = first
    else:
        n = first & 0x7F
        if i + n > len(buf):
            return None
        length = int.from_bytes(buf[i:i + n], "big")
        i += n
    if i + length > len(buf):
        return None
    return tag, buf[i:i + length], buf[i + length:]


def _snmp_parse_response(data: bytes) -> Dict[str, str]:
    """从 v2c GET 响应中提取 sysDescr/sysName。"""
    out: Dict[str, str] = {}
    targets = {
        _oid_encode(_SYSDESCR_OID): "sysDescr",
        _oid_encode(_SYSNAME_OID): "sysName",
    }

    def walk(buf: bytes) -> None:
        while buf:
            parsed = _ber_parse(buf)
            if not parsed:
                return
            tag, value, buf = parsed
            if tag == 0x30 or (0xA0 <= tag <= 0xAF):  # SEQUENCE / PDU
                inner = _ber_parse(value)
                if inner and inner[0] == 0x06:  # OID 开头的序列 → varbind
                    oid_val, rest = inner[1], inner[2]
                    nxt = _ber_parse(rest)
                    if nxt and nxt[0] == 0x04:
                        name = targets.get(oid_val)
                        if name:
                            out[name] = nxt[1].decode(
                                "utf-8", errors="replace"
                            )[:200]
                walk(value)

    walk(data)
    return out


def snmp_probe(
    ip: str, community: str = "public", timeout: float = 2.0
) -> Dict[str, str]:
    """SNMP v2c GET sysDescr/sysName——家用路由器/摄像头/打印机常开 public 社区名。"""
    out: Dict[str, str] = {}
    pkt = _snmp_get_request([_SYSDESCR_OID, _SYSNAME_OID], community)
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(pkt, (ip, 161))
        data, _ = sock.recvfrom(4096)
        out = _snmp_parse_response(data)
    except OSError:
        pass
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass
    return out


# ---------- nmap 桥接（可选依赖） ----------


def _nmap_available() -> Optional[str]:
    try:
        import shutil

        return shutil.which("nmap")
    except Exception:
        return None


def _is_admin() -> bool:
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def nmap_version_scan(
    ip: str, ports: List[int], timeout: int = 150
) -> Optional[Dict[str, Any]]:
    """本机装有 nmap 时跑 -sV（管理员再加 -O）版本识别，解析 XML 合并进报告。"""
    exe = _nmap_available()
    if not exe or not ports:
        return None
    import subprocess as sp
    import xml.etree.ElementTree as ET

    port_list = ",".join(str(p) for p in ports[:200])
    cmd = [exe, "-sV", "--version-light", "-Pn", "-p", port_list, "-oX", "-", ip]
    if _is_admin():
        cmd.insert(1, "-O")
    try:
        proc = sp.run(cmd, capture_output=True, timeout=timeout)
        return _nmap_parse_xml(proc.stdout.decode("utf-8", errors="replace"))
    except Exception:
        return None


def _nmap_parse_xml(text: str) -> Dict[str, Any]:
    """解析 nmap -oX 输出：端口服务/产品/版本与 OS 猜测。"""
    import xml.etree.ElementTree as ET

    root = ET.fromstring(text)
    result: Dict[str, Any] = {"ports": {}, "os": ""}
    for pnode in root.iter("port"):
        try:
            portid = int(pnode.get("portid", "0"))
        except ValueError:
            continue
        svc = pnode.find("service")
        if svc is not None:
            result["ports"][portid] = {
                "service": svc.get("name", "") or "",
                "product": svc.get("product", "") or "",
                "version": svc.get("version", "") or "",
                "extrainfo": svc.get("extrainfo", "") or "",
            }
    osmatch = root.find(".//osmatch")
    if osmatch is not None:
        result["os"] = osmatch.get("name", "") or ""
    return result


# ---------- 暴露面风险规则 ----------

RISK_RULES = [
    {"ports": [23, 2323], "severity": "critical", "type": "telnet",
     "message": "Telnet 开放——明文管理协议，凭据裸传；嵌入式设备常见，僵尸网络最爱"},
    {"ports": [5555], "severity": "critical", "type": "adb",
     "message": "ADB 调试接口暴露（Android）——可被直接控制设备"},
    {"ports": [7547], "severity": "critical", "type": "tr069",
     "message": "TR-069/CWMP 运维接口暴露——Mirai 变种的重点攻击面"},
    {"ports": [8291], "severity": "high", "type": "winbox",
     "message": "MikroTik Winbox 管理端口暴露——CVE-2018-14847 凭据提取的利用面"},
    {"ports": [37215], "severity": "critical", "type": "huawei-upnp",
     "message": "华为设备 UPnP 端口开放——历史 RCE（CVE-2017-17215）利用面"},
    {"ports": [2375], "severity": "high", "type": "docker",
     "message": "Docker API 无认证暴露——等同宿主机 root"},
    {"ports": [5900, 5901], "severity": "high", "type": "vnc",
     "message": "VNC 远程桌面暴露——常无认证或弱口令"},
    {"ports": [6379], "severity": "high", "type": "redis",
     "message": "Redis 暴露——常见误配置为无认证"},
    {"ports": [27017], "severity": "high", "type": "mongodb",
     "message": "MongoDB 暴露"},
    {"ports": [9200], "severity": "high", "type": "elasticsearch",
     "message": "Elasticsearch 暴露"},
    {"ports": [502], "severity": "high", "type": "modbus",
     "message": "Modbus 工控协议暴露——无认证指令通道"},
    {"ports": [21], "severity": "high", "type": "ftp",
     "message": "FTP 开放——明文协议"},
    {"ports": [445, 139], "severity": "medium", "type": "smb",
     "message": "SMB/NetBIOS 暴露——Windows 共享面（永恒之蓝家族的历史重灾区）"},
    {"ports": [3389], "severity": "medium", "type": "rdp",
     "message": "RDP 远程桌面暴露"},
    {"ports": [1433, 3306, 5432], "severity": "medium", "type": "db",
     "message": "数据库端口暴露"},
    {"ports": [1900, 49152], "severity": "low", "type": "upnp",
     "message": "UPnP 服务暴露"},
    {"ports": [9100, 631, 515], "severity": "info", "type": "printer",
     "message": "打印服务端口"},
]


def assess_risks(port_infos: List[Dict[str, Any]], osinfo: Dict[str, Any]) -> List[Dict[str, Any]]:
    """规则化风险评估，返回按严重度排序的发现项。"""
    findings: List[Dict[str, Any]] = []
    open_ports = {p["port"] for p in port_infos}
    for rule in RISK_RULES:
        hit = sorted(open_ports & set(rule["ports"]))
        if hit:
            findings.append({
                "severity": rule["severity"], "type": rule["type"],
                "ports": hit, "message": rule["message"],
            })
    # 派生规则：明文 Web 登录页
    for p in port_infos:
        http = p.get("http") or {}
        if http.get("login_page") and p["port"] not in _TLS_PORTS:
            findings.append({
                "severity": "medium", "type": "http-login",
                "ports": [p["port"]],
                "message": f"端口 {p['port']} 存在 Web 登录页且未走 HTTPS——凭据明文传输",
            })
    if len(open_ports) > 20:
        findings.append({
            "severity": "info", "type": "many-ports", "ports": [],
            "message": f"开放端口多达 {len(open_ports)} 个——攻击面偏大，建议核对必要性",
        })
    if not open_ports:
        findings.append({
            "severity": "info", "type": "no-ports", "ports": [],
            "message": "未发现开放端口（设备静默或被防火墙过滤）",
        })
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: order.get(f["severity"], 9))
    return findings


# ---------- 已知漏洞签名（精选快照，可自行扩充） ----------

VULN_SIGNATURES = [
    # —— 后门与著名 RCE ——
    {"pattern": r"vsftpd\s+2\.3\.4", "cve": "CVE-2011-2523",
     "severity": "critical", "name": "vsftpd 2.3.4 后门",
     "desc": "官方源码服务器被入侵期间植入的后门版本"},
    {"pattern": r"ProFTPD\s+1\.3\.5(?!\d)", "cve": "CVE-2015-3306",
     "severity": "critical", "name": "ProFTPD mod_copy 任意文件写入",
     "desc": "1.3.5 系列的 mod_copy 模块可写任意路径，常被用于投放网页后门"},
    {"pattern": r"Apache/2\.4\.(49|50)", "cve": "CVE-2021-42013",
     "severity": "critical", "name": "Apache 路径穿越/RCE",
     "desc": "2.4.49/2.4.50 的路径穿越（41773 修复不完整演化为 42013），可导致 RCE"},
    {"pattern": r"ThinkPHP[/ ]?5\.[01]\.", "cve": "",
     "severity": "critical", "name": "ThinkPHP 5.x 远程代码执行",
     "desc": "5.0/5.1 系列控制器调用未过滤（无 CVE 编号的著名 RCE）"},
    # —— 命令注入 ——
    {"pattern": r"MiniUPnPd/1\.[0-4](?!\d)", "cve": "CVE-2014-8361",
     "severity": "high", "name": "MiniUPnPd SOAP 命令注入",
     "desc": "1.4 及以下版本的 SOAP 接口可注入命令"},
    {"pattern": r"MiniIGD", "cve": "CVE-2016-10372",
     "severity": "high", "name": "Realtek SDK MiniIGD 命令注入",
     "desc": "UPnP SOAP 远程命令执行，大量路由器受影响"},
    # —— 加密库 ——
    {"pattern": r"OpenSSL\s+1\.0\.1[a-g]?[\s/]", "cve": "CVE-2014-0160",
     "severity": "high", "name": "Heartbleed",
     "desc": "1.0.1～1.0.1g 内存越界读取，可泄露密钥"},
    {"pattern": r"OpenSSL\s+1\.0\.1[a-f]?[\s/]", "cve": "CVE-2014-0224",
     "severity": "high", "name": "OpenSSL CCS 注入",
     "desc": "1.0.1g 之前的 CCS 注入可被降级为中间人"},
    # —— SSH ——
    {"pattern": r"OpenSSH_(5\.[4-9]|6\.|7\.[01])(?!\d)", "cve": "CVE-2016-0777",
     "severity": "medium", "name": "OpenSSH roaming 信息泄露",
     "desc": "5.4～7.1 的 roaming 代码可泄露进程内存"},
    {"pattern": r"OpenSSH_(8\.|9\.[0-5])(?!\d)", "cve": "CVE-2023-48795",
     "severity": "medium", "name": "Terrapin 握手前缀截断",
     "desc": "9.6 之前版本的 SSH 握手前缀截断攻击"},
    # —— 设备家族 ——
    {"pattern": r"App-webs", "cve": "CVE-2017-7921",
     "severity": "high", "name": "海康威视未授权访问（家族）",
     "desc": "App-webs 服务端的海康设备家族存在未授权访问，具体固件版本需核实"},
    {"pattern": r"DS-2(CD|DE|CV|DF)", "cve": "CVE-2017-7921",
     "severity": "medium", "name": "海康威视摄像头（家族）",
     "desc": "该型号家族多个固件受未授权访问影响，具体版本需核实"},
    {"pattern": r"IIS/6\.0", "cve": "CVE-2017-7269",
     "severity": "high", "name": "IIS 6.0 WebDAV 缓冲区溢出",
     "desc": "Windows 2003 的 IIS 6.0 WebDAV 远程代码执行"},
    # —— 停止维护 ——
    {"pattern": r"Boa/0\.9", "cve": "",
     "severity": "medium", "name": "Boa 停止维护",
     "desc": "嵌入式 Web 服务器早已停止维护，路由器/摄像头固件常见，历史问题多"},
    {"pattern": r"mini_httpd", "cve": "",
     "severity": "medium", "name": "mini_httpd 停止维护",
     "desc": "嵌入式 Web 服务器长期无维护，常见于路由器固件"},
    {"pattern": r"PHP/5\.", "cve": "",
     "severity": "low", "name": "PHP 5.x（EOL）",
     "desc": "已停止安全维护的分支"},
    {"pattern": r"PHP/7\.[0-3]\.", "cve": "",
     "severity": "low", "name": "PHP 7.0～7.3（EOL）",
     "desc": "已停止安全维护的分支"},
    {"pattern": r"Apache/2\.2\.", "cve": "",
     "severity": "low", "name": "Apache 2.2（EOL）",
     "desc": "已停止安全维护的分支"},
    {"pattern": r"nginx/0\.|nginx/1\.[0-9]\.", "cve": "",
     "severity": "low", "name": "nginx 旧版本（EOL）",
     "desc": "1.9 及更早分支早已停止维护"},
    {"pattern": r"lighttpd/1\.4\.[0-2]\d", "cve": "",
     "severity": "low", "name": "lighttpd 旧版本",
     "desc": "1.4.2x 及更早版本年代久远，建议核实版本"},
]


def match_vulns(
    port_infos: List[Dict[str, Any]], snmp: Optional[Dict[str, str]] = None
) -> List[Dict[str, Any]]:
    """对端口指纹（banner/Server/X-Powered-By/产品版本）与 SNMP sysDescr
    做签名匹配，按 (cve, name, port) 去重；port=0 表示设备级（SNMP）。"""
    vulns: List[Dict[str, Any]] = []
    seen = set()

    def check(haystack: str, port: int) -> None:
        for sig in VULN_SIGNATURES:
            if re.search(sig["pattern"], haystack, re.I):
                key = (sig["cve"], sig["name"], port)
                if key in seen:
                    continue
                seen.add(key)
                vulns.append({
                    "cve": sig["cve"], "name": sig["name"],
                    "severity": sig["severity"], "desc": sig["desc"],
                    "port": port, "evidence": haystack.strip()[:120],
                })

    for p in port_infos:
        http = p.get("http") or {}
        haystack = " ".join(filter(None, [
            p.get("banner", ""),
            http.get("server", ""),
            http.get("x_powered_by", ""),
            p.get("product", ""),
            p.get("version", ""),
            p.get("extrainfo", ""),
        ]))
        if haystack.strip():
            check(haystack, p["port"])
    if snmp:
        dev_hay = " ".join(filter(None, [
            snmp.get("sysDescr", ""), snmp.get("sysName", ""),
        ]))
        if dev_hay.strip():
            check(dev_hay, 0)
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    vulns.sort(key=lambda v: order.get(v["severity"], 9))
    return vulns


def nmap_hint(ip: str, open_ports: List[int]) -> str:
    ports = ",".join(str(p) for p in open_ports[:20])
    return f"nmap -sV -sC -p {ports or '1-65535'} {ip}   # 在 Kali 中执行"


# ---------- 侦察调度 ----------

class ReconRunner:
    """同一时刻只跑一台设备的深度侦察；支持陌生设备自动触发。"""

    def __init__(self, store):
        self.store = store
        self._lock = threading.Lock()
        self.status: Dict[str, Any] = {"running": False, "mac": None, "stage": "", "started": 0.0}

    def is_running(self) -> bool:
        return bool(self.status.get("running"))

    def run(self, mac: str, ip: str) -> Optional[Dict[str, Any]]:
        """同步执行完整侦察流程（由线程调用），返回报告。"""
        if not self._lock.acquire(blocking=False):
            return None
        t0 = time.time()
        self.status = {"running": True, "mac": mac, "stage": "全端口扫描", "started": t0}
        try:
            ports = full_port_scan(ip)
            self.status["stage"] = "服务指纹"
            port_infos = fingerprint_all(ip, ports)
            self.status["stage"] = "SNMP 探测"
            snmp = snmp_probe(ip)
            nmap_res = None
            if _nmap_available():
                self.status["stage"] = "nmap 版本识别"
                nmap_res = nmap_version_scan(ip, ports)
            if nmap_res:
                for info in port_infos:
                    nm = nmap_res["ports"].get(info["port"])
                    if not nm:
                        continue
                    if nm["service"] and not info["service"]:
                        info["service"] = nm["service"]
                    info["product"] = nm["product"] or info.get("product", "")
                    info["version"] = nm["version"] or info.get("version", "")
                    info["extrainfo"] = nm["extrainfo"] or info.get("extrainfo", "")
            self.status["stage"] = "OS 识别"
            osinfo = os_fingerprint(ip)
            if nmap_res and nmap_res.get("os"):
                osinfo["nmap"] = nmap_res["os"]
                if osinfo.get("guess") in ("", "unknown"):
                    osinfo["guess"] = nmap_res["os"]
            self.status["stage"] = "风险评估"
            findings = assess_risks(port_infos, osinfo)
            vulns = match_vulns(port_infos, snmp)
            dev = self.store.get_device(mac) or {}
            report = {
                "version": 2,
                "ts": time.time(),
                "duration": round(time.time() - t0, 1),
                "mac": mac,
                "ip": ip,
                "engine": "nmap" if nmap_res else "builtin",
                "device": {
                    "name": dev.get("custom_name") or dev.get("hostname") or "",
                    "vendor": dev.get("vendor") or "",
                    "type": dev.get("custom_type") or dev.get("device_type") or "unknown",
                },
                "os": osinfo,
                "snmp": snmp,
                "open_count": len(ports),
                "ports": port_infos,
                "findings": findings,
                "vulns": vulns,
                "skipped_ports": sorted(HIJACKED_PORTS),
                "kali_hint": nmap_hint(ip, ports),
            }
            self.store.save_recon(mac, report)
            self.store.add_event(
                "info", "recon_done",
                f"深度侦察完成：{ip} 开放 {len(ports)} 端口，"
                f"风险发现 {len(findings)} 项，漏洞签名命中 {len(vulns)} 项",
                mac, ip,
            )
            return report
        finally:
            self.status["running"] = False
            self._lock.release()

    def _safe_run(self, mac: str, ip: str) -> None:
        try:
            self.run(mac, ip)
        except Exception:
            pass

    def start(self, mac: str, ip: str) -> bool:
        """异步启动；已有侦察在跑时返回 False。"""
        if self.is_running():
            return False
        threading.Thread(
            target=self._safe_run, args=(mac, ip),
            daemon=True, name="lanscope-recon",
        ).start()
        return True

    def auto_trigger(self, mac: str, ip: Optional[str]) -> None:
        """陌生设备接入时的自动侦察入口（由巡检 new_device 事件调用）。"""
        try:
            if self.store.get_settings().get("recon_auto") != "1":
                return
            if not ip:
                return
            self.start(mac, ip)
        except Exception:
            pass
