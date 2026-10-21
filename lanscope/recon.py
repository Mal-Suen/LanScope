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
        "status": 0, "server": "", "title": "", "login_page": False,
        "body_bytes": 0, "cert": [],
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
            if k.strip().lower() == "server":
                out["server"] = v.strip()[:120]
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
    return fallback


def fingerprint_port(ip: str, port: int, timeout: float = 3.0) -> Dict[str, Any]:
    """识别单个开放端口：服务名、banner、HTTP/HTTPS 信息。"""
    info: Dict[str, Any] = {
        "port": port,
        "service": PORT_NAMES.get(port, ""),
        "banner": "",
        "http": None,
    }
    if port in _HTTP_GUESS or port in _TLS_PORTS:
        http = http_probe(ip, port, use_tls=port in _TLS_PORTS, timeout=timeout)
        if http:
            info["http"] = http
            info["service"] = info["service"] or "https" if port in _TLS_PORTS else (info["service"] or "http")
            return info
    if port in _PREBANNER_PORTS:
        info["banner"] = grab_banner(ip, port, timeout)
        if info["banner"]:
            info["service"] = _service_from_banner(info["banner"], info["service"])
            return info
    # 未知端口：先试 HTTP（嵌入式 Web 常在怪端口），再等 banner
    http = http_probe(ip, port, timeout=2.0)
    if http:
        info["http"] = http
        info["service"] = info["service"] or "http"
    else:
        b = grab_banner(ip, port, timeout=1.5)
        if b:
            info["banner"] = b
            info["service"] = _service_from_banner(b, info["service"])
    return info


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


# ---------- 暴露面风险规则 ----------

RISK_RULES = [
    {"ports": [23, 2323], "severity": "critical", "type": "telnet",
     "message": "Telnet 开放——明文管理协议，凭据裸传；嵌入式设备常见，僵尸网络最爱"},
    {"ports": [5555], "severity": "critical", "type": "adb",
     "message": "ADB 调试接口暴露（Android）——可被直接控制设备"},
    {"ports": [7547], "severity": "critical", "type": "tr069",
     "message": "TR-069/CWMP 运维接口暴露——Mirai 变种的重点攻击面"},
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
    {"pattern": r"vsftpd\s+2\.3\.4", "cve": "CVE-2011-2523",
     "severity": "critical", "name": "vsftpd 2.3.4 后门",
     "desc": "官方源码服务器被入侵期间植入的后门版本"},
    {"pattern": r"MiniUPnPd/1\.[0-4](?!\d)", "cve": "CVE-2014-8361",
     "severity": "high", "name": "MiniUPnPd SOAP 命令注入",
     "desc": "1.4 及以下版本的 SOAP 接口可注入命令"},
    {"pattern": r"MiniIGD", "cve": "CVE-2016-10372",
     "severity": "high", "name": "Realtek SDK MiniIGD 命令注入",
     "desc": "UPnP SOAP 远程命令执行，大量路由器受影响"},
    {"pattern": r"OpenSSL\s+1\.0\.1[a-g]?[\s/]", "cve": "CVE-2014-0160",
     "severity": "high", "name": "Heartbleed",
     "desc": "1.0.1～1.0.1g 内存越界读取，可泄露密钥"},
    {"pattern": r"Boa/0\.9", "cve": "",
     "severity": "medium", "name": "Boa 停止维护",
     "desc": "嵌入式 Web 服务器早已停止维护，路由器/摄像头固件常见，历史问题多"},
    {"pattern": r"PHP/5\.", "cve": "",
     "severity": "low", "name": "PHP 5.x（EOL）",
     "desc": "已停止安全维护的分支"},
    {"pattern": r"Apache/2\.2\.", "cve": "",
     "severity": "low", "name": "Apache 2.2（EOL）",
     "desc": "已停止安全维护的分支"},
]


def match_vulns(port_infos: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """对全部端口的 banner/Server 串做签名匹配，按 (cve, name, port) 去重。"""
    vulns: List[Dict[str, Any]] = []
    seen = set()
    for p in port_infos:
        http = p.get("http") or {}
        haystack = f"{p.get('banner', '')} {http.get('server', '')}"
        for sig in VULN_SIGNATURES:
            if re.search(sig["pattern"], haystack, re.I):
                key = (sig["cve"], sig["name"], p["port"])
                if key in seen:
                    continue
                seen.add(key)
                vulns.append({
                    "cve": sig["cve"], "name": sig["name"],
                    "severity": sig["severity"], "desc": sig["desc"],
                    "port": p["port"], "evidence": haystack.strip()[:120],
                })
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
            self.status["stage"] = "OS 识别"
            osinfo = os_fingerprint(ip)
            self.status["stage"] = "风险评估"
            findings = assess_risks(port_infos, osinfo)
            vulns = match_vulns(port_infos)
            dev = self.store.get_device(mac) or {}
            report = {
                "version": 1,
                "ts": time.time(),
                "duration": round(time.time() - t0, 1),
                "mac": mac,
                "ip": ip,
                "device": {
                    "name": dev.get("custom_name") or dev.get("hostname") or "",
                    "vendor": dev.get("vendor") or "",
                    "type": dev.get("custom_type") or dev.get("device_type") or "unknown",
                },
                "os": osinfo,
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
