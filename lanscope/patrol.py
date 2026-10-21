"""巡检调度：周期全网扫描、统一设备出现入口（巡检＋被动嗅探共用）、
事件生成（新设备／上下线／IP 变更／端口变更）与系统通知。"""
from __future__ import annotations

import os
import subprocess
import threading
import time
from typing import Callable, Dict, List, Optional

from .discover import discover_hosts
from .fingerprint import (
    ensure_oui,
    infer_device_type,
    load_oui,
    lookup_vendor,
    mdns_names,
    netbios_names,
    resolve_rdns,
    ssdp_details,
    ssdp_discover,
)
from .netinfo import NetEnv
from .portscan import enrich_services_many, scan_many
from .store import Store


class Patrol:
    def __init__(self, store: Store, env: NetEnv, on_new_device=None):
        self.store = store
        self.env = env
        self.on_new_device = on_new_device  # 新设备事件回调 (mac, ip)——自动侦察等挂这里
        self.scanning = False
        self.last_scan: Optional[Dict] = None
        self._stop = threading.Event()
        self._scan_lock = threading.Lock()
        self._obs_lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        # 首次扫描（空库）作为基线录入，不产生新设备告警
        self._baseline = self.store.stats()["total"] == 0

    # ---------- 生命周期 ----------

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="lanscope-patrol"
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _interval(self) -> int:
        try:
            return max(60, int(self.store.get_settings().get("patrol_interval", "300")))
        except (TypeError, ValueError):
            return 300

    def _loop(self) -> None:
        while not self._stop.is_set():
            deadline = time.time() + self._interval()
            while time.time() < deadline and not self._stop.is_set():
                time.sleep(min(2.0, max(0.0, deadline - time.time())))
            if self._stop.is_set():
                return
            try:
                self.run_full_scan(trigger="patrol")
            except Exception:
                time.sleep(10)

    # ---------- 统一设备出现入口 ----------

    def _display(self, dev: Dict, hostname: Optional[str] = None) -> str:
        return (
            dev.get("custom_name")
            or (hostname or dev.get("hostname") or "")
            or (dev.get("vendor") or "")
            or dev.get("mac", "")[:8]
        )

    def _observe(
        self,
        mac: str,
        ip: str,
        hostname: Optional[str] = None,
        vendor: Optional[str] = None,
        device_type: Optional[str] = None,
        source: str = "scan",
    ) -> None:
        with self._obs_lock:
            ts = time.time()
            existing = self.store.get_device(mac)
            if existing is None:
                self.store.mark_seen(mac, ip, ts, hostname, vendor, device_type)
                if not self._baseline:
                    name = hostname or vendor or "未知设备"
                    self.store.add_event(
                        "warn",
                        "new_device",
                        f"发现新设备：{name}（{ip}｜{mac}）",
                        mac,
                        ip,
                        ts,
                    )
                    self._notify(f"LanScope：发现新设备 {name}（{ip}）")
                    if self.on_new_device:
                        try:
                            self.on_new_device(mac, ip)
                        except Exception:
                            pass
                return
            was_online = existing["status"] == 1
            old_ip = existing["last_ip"]
            self.store.mark_seen(mac, ip, ts, hostname, vendor, device_type)
            if not was_online:
                self.store.add_event(
                    "info",
                    "device_online",
                    f"设备上线：{self._display(existing, hostname)}（{ip}）",
                    mac,
                    ip,
                    ts,
                )
            elif old_ip and old_ip != ip:
                self.store.add_event(
                    "info",
                    "ip_change",
                    f"设备 {self._display(existing, hostname)} 的 IP 由 {old_ip} 变为 {ip}",
                    mac,
                    ip,
                    ts,
                )

    def handle_alert(
        self,
        severity: str,
        type_: str,
        message: str,
        mac: Optional[str] = None,
        ip: Optional[str] = None,
    ) -> None:
        try:
            self.store.add_event(severity, type_, message, mac, ip)
        except Exception:
            pass
        if severity == "critical":
            self._notify(f"LanScope 告警：{message}")

    def _notify(self, message: str) -> None:
        """系统级弹窗（msg.exe，家庭版可能缺失，静默失败）。"""
        try:
            if self.store.get_settings().get("toast_critical") != "1":
                return
            user = os.environ.get("USERNAME", "*")
            subprocess.run(
                ["msg", user, "/time:30", message],
                capture_output=True,
                timeout=8,
            )
        except Exception:
            pass

    # ---------- 全量扫描 ----------

    def run_full_scan(self, trigger: str = "manual") -> Optional[Dict]:
        if not self._scan_lock.acquire(blocking=False):
            return None
        self.scanning = True
        started = time.time()
        try:
            ensure_oui(background=True)  # 缓存缺失/过期时后台补下载，不阻塞扫描
            run_id = self.store.begin_scan(trigger)
            hosts, method = discover_hosts(self.env)
            ips = [h["ip"] for h in hosts]

            rdns = resolve_rdns(ips)
            mdns = (
                mdns_names(ips, iface=self.env.scapy_iface)
                if self.env.scapy_ok
                else {}
            )
            ssdp_raw = ssdp_discover()
            ssdp = ssdp_details(ssdp_raw)
            nameless = [
                ip
                for ip in ips
                if not (rdns.get(ip) or (mdns.get(ip) or {}).get("name"))
            ]
            nbt = netbios_names(nameless) if nameless else {}

            settings = self.store.get_settings()
            port_results: Dict[str, List[int]] = {}
            services: Dict[str, Dict[int, str]] = {}
            if settings.get("port_scan") == "1":
                port_results = scan_many(ips)
                services = enrich_services_many(
                    {ip: ps for ip, ps in port_results.items() if ps}
                )

            oui = load_oui()

            for h in hosts:
                ip, mac = h["ip"], h["mac"]
                hostname = (
                    rdns.get(ip)
                    or (mdns.get(ip) or {}).get("name")
                    or nbt.get(ip)
                    or (ssdp.get(ip) or {}).get("friendly_name")
                    or ""
                )
                vendor = lookup_vendor(mac, oui)
                mdns_info = mdns.get(ip) or {}
                ssdp_info = ssdp.get(ip) or {}
                ports = port_results.get(ip, [])
                dtype = infer_device_type(
                    vendor=vendor,
                    hostname=hostname,
                    ports=ports,
                    mdns_hints=mdns_info.get("hints"),
                    mdns_name=mdns_info.get("name") or "",
                    ssdp_type=ssdp_info.get("device_type") or "",
                )
                self._observe(
                    mac, ip, hostname or None, vendor or None, dtype, source="scan"
                )
                self.store.add_presence(run_id, mac, ip)
                if services.get(ip):
                    self.store.set_services(mac, services[ip])
                if ports:
                    old_ports = self.store.latest_ports(mac)
                    if set(old_ports) != set(ports):
                        if old_ports:
                            added = sorted(set(ports) - set(old_ports))
                            removed = sorted(set(old_ports) - set(ports))
                            parts = []
                            if added:
                                parts.append("新增 " + "、".join(map(str, added)))
                            if removed:
                                parts.append("关闭 " + "、".join(map(str, removed)))
                            self.store.add_event(
                                "info",
                                "port_change",
                                f"设备 {hostname or mac} 端口变化：{'；'.join(parts)}",
                                mac,
                                ip,
                            )
                        self.store.save_ports(mac, ports)

            # 离线判定：连续 2 轮未出现才判离线，避免瞬时抖动
            seen_macs = {h["mac"] for h in hosts}
            for dev in self.store.list_devices():
                mac = dev["mac"]
                if mac in seen_macs:
                    continue
                missed = self.store.bump_missed(mac)
                if dev["status"] == 1 and missed >= 2:
                    self.store.set_offline(mac, missed)
                    self.store.add_event(
                        "info",
                        "device_offline",
                        f"设备离线：{self._display(dev)}（{dev['last_ip'] or ''}）",
                        mac,
                        dev["last_ip"],
                    )

            online = len(hosts)
            self.store.finish_scan(run_id, online)
            if online > 0:
                self._baseline = False
            self.last_scan = {
                "ts": time.time(),
                "duration": round(time.time() - started, 1),
                "online": online,
                "trigger": trigger,
                "method": method,
            }
            return self.last_scan
        finally:
            self.scanning = False
            self._scan_lock.release()
