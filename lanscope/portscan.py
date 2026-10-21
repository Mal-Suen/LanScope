"""端口扫描与轻量服务识别：标准库 connect 扫描（无需管理员权限），
HTTP 标题与 SSH/FTP banner 抓取。"""
from __future__ import annotations

import re
import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Tuple

# 注：不扫 25/110/143（明文邮件端口）——安全软件的「邮件防护」会在本机
# 用 WFP 重定向这三类连接，对任何目标 IP 都握手成功，产生假阳性
# （实测 iPhone/路由器在这些端口全部「开放」）。
COMMON_PORTS = [
    21, 22, 23, 53, 80, 139, 443, 445,
    502, 554, 587, 993, 995, 1433, 1900, 2323, 3306, 3389,
    5000, 5432, 5555, 5900, 631, 6379, 7547, 8000, 8080, 8081,
    8443, 8888, 9000, 9090, 9100, 10000, 32400, 49152,
]

_HTTP_PORTS = {80, 443, 8000, 8080, 8081, 8443, 8888, 9000, 9090, 10000, 32400, 5000}
_BANNER_PORTS = {21, 22, 23, 587, 993, 995}


def _decode(data: bytes) -> str:
    for enc in ("utf-8", "gbk"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def scan_many(
    hosts: List[str],
    ports: Optional[List[int]] = None,
    timeout: float = 0.7,
    workers: int = 128,
) -> Dict[str, List[int]]:
    """对多台主机的常见端口做 connect 扫描，返回 {ip: [开放端口]}。"""
    ports = ports or COMMON_PORTS
    results: Dict[str, List[int]] = {ip: [] for ip in hosts}
    tasks: List[Tuple[str, int]] = [(ip, p) for ip in hosts for p in ports]
    if not tasks:
        return results

    def probe(t: Tuple[str, int]) -> Optional[Tuple[str, int]]:
        ip, p = t
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            return t if s.connect_ex((ip, p)) == 0 else None
        except OSError:
            return None
        finally:
            try:
                s.close()
            except OSError:
                pass

    with ThreadPoolExecutor(max_workers=workers) as ex:
        for r in ex.map(probe, tasks):
            if r:
                results[r[0]].append(r[1])
    return results


def http_title(ip: str, port: int, timeout: float = 2.5) -> str:
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(
            f"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: LanScope/1.0\r\n\r\n".encode()
        )
        data = b""
        while len(data) < 8192:
            try:
                chunk = s.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
        s.close()
        m = re.search(r"<title[^>]*>(.*?)</title>", _decode(data), re.I | re.S)
        if not m:
            return ""
        return re.sub(r"\s+", " ", m.group(1)).strip()[:80]
    except OSError:
        return ""


def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        s.settimeout(timeout)
        data = s.recv(256)
        s.close()
        return data.decode("utf-8", errors="replace").strip()[:120]
    except OSError:
        return ""


def enrich_services_many(
    open_by_ip: Dict[str, List[int]],
    timeout: float = 2.5,
    workers: int = 48,
) -> Dict[str, Dict[int, str]]:
    """批量抓取服务特征，返回 {ip: {端口: 描述}}。"""
    tasks: List[Tuple[str, int, str]] = []
    for ip, ports in open_by_ip.items():
        for p in ports:
            if p in _HTTP_PORTS:
                tasks.append((ip, p, "http"))
            elif p in _BANNER_PORTS:
                tasks.append((ip, p, "banner"))

    out: Dict[str, Dict[int, str]] = {}

    def one(t: Tuple[str, int, str]):
        ip, p, kind = t
        desc = http_title(ip, p, timeout) if kind == "http" else grab_banner(ip, p, timeout)
        return (ip, p, desc) if desc else None

    with ThreadPoolExecutor(max_workers=workers) as ex:
        for r in ex.map(one, tasks):
            if r:
                out.setdefault(r[0], {})[r[1]] = r[2]
    return out
