"""内置 Web 控制台：静态页面＋REST API。

标准库 http.server 实现，仅绑定 127.0.0.1，不对外网暴露。
"""
from __future__ import annotations

import json
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, unquote, urlparse

from . import APP_NAME, APP_NAME_CN, __version__
from .arpwatch import ArpWatch
from .fingerprint import ensure_oui, oui_status, refresh_oui
from .netinfo import detect_env
from .patrol import Patrol
from .store import Store

WEB_DIR = Path(__file__).resolve().parent / "web"

_TYPE_LABELS = {
    "router": "路由器",
    "pc": "电脑",
    "phone": "手机",
    "tv": "电视/盒子",
    "console": "游戏机",
    "nas": "存储",
    "printer": "打印机",
    "camera": "摄像头",
    "iot": "智能设备",
    "unknown": "未知",
}


def _device_payload(d: Dict[str, Any]) -> Dict[str, Any]:
    services: Dict[str, str] = {}
    if d.get("services"):
        try:
            services = json.loads(d["services"])
        except Exception:
            services = {}
    ports = []
    if d.get("last_ports"):
        try:
            ports = json.loads(d["last_ports"])
        except Exception:
            ports = []
    dtype = d.get("custom_type") or d.get("device_type") or "unknown"
    return {
        "mac": d["mac"],
        "ip": d.get("last_ip") or "",
        "hostname": d.get("hostname") or "",
        "vendor": d.get("vendor") or "",
        "type": dtype,
        "type_label": _TYPE_LABELS.get(dtype, dtype),
        "custom_name": d.get("custom_name") or "",
        "custom_type": d.get("custom_type") or "",
        "notes": d.get("notes") or "",
        "known": bool(d.get("known")),
        "starred": bool(d.get("starred")),
        "online": d.get("status") == 1,
        "first_seen": d.get("first_seen"),
        "last_seen": d.get("last_seen"),
        "services": services,
        "ports": ports,
    }


class LanScopeApp:
    """组装存储、巡检、嗅探与网络环境，向 HTTP 层提供数据与操作。"""

    def __init__(self, db_path=None, port: int = 8765, open_browser: bool = True):
        self.store = Store(db_path)
        self.env = detect_env()
        self.patrol = Patrol(self.store, self.env)
        self.arpwatch = ArpWatch(
            self.env,
            on_observation=self.patrol._observe,
            on_alert=self.patrol.handle_alert,
        )
        self.port = port
        self.open_browser = open_browser
        self._started = False

    def start_background(self) -> None:
        if self._started:
            return
        self._started = True
        ensure_oui(background=True)
        threading.Thread(
            target=self._initial_scan, daemon=True, name="lanscope-init"
        ).start()

    def _initial_scan(self) -> None:
        try:
            self.patrol.run_full_scan("startup")
        except Exception:
            pass
        try:
            if self.store.get_settings().get("sniffer") == "1":
                self.arpwatch.start()
        except Exception:
            pass
        self.patrol.start()

    def shutdown(self) -> None:
        self.patrol.stop()
        self.arpwatch.stop()

    # ---------- API 数据 ----------

    def state_payload(self) -> Dict[str, Any]:
        devices = [_device_payload(d) for d in self.store.list_devices()]
        settings = self.store.get_settings()
        try:
            interval = int(settings.get("patrol_interval", "300") or 300)
        except ValueError:
            interval = 300
        return {
            "app": {"name": APP_NAME, "name_cn": APP_NAME_CN, "version": __version__},
            "network": {
                "ip": self.env.ip,
                "cidr": self.env.cidr,
                "gateway": self.env.gateway,
                "adapter": self.env.adapter,
                "scapy": self.env.scapy_ok,
            },
            "scan": {
                "running": self.patrol.scanning,
                "last": self.patrol.last_scan,
                "last_run": self.store.last_run(),
                "interval": interval,
            },
            "stats": self.store.stats(),
            "devices": devices,
            "events": self.store.list_events(60),
            "settings": settings,
            "oui": oui_status(),
        }

    def device_detail(self, mac: str) -> Dict[str, Any]:
        mac = (mac or "").upper()
        dev = self.store.get_device(mac)
        if not dev:
            return {"error": "设备不存在"}
        return {
            "device": _device_payload(dev),
            "timeline": self.store.timeline(mac, since=time.time() - 48 * 3600),
            "ports": self.store.latest_ports(mac),
            "events": self.store.events_for_device(mac, 40),
        }

    def trigger_scan(self) -> Dict[str, Any]:
        if self.patrol.scanning:
            return {"started": False, "reason": "扫描进行中，请稍候"}
        threading.Thread(
            target=self._safe_scan, kwargs={"trigger": "manual"}, daemon=True
        ).start()
        return {"started": True}

    def _safe_scan(self, trigger: str) -> None:
        try:
            self.patrol.run_full_scan(trigger)
        except Exception:
            pass


class Handler(BaseHTTPRequestHandler):
    app: Optional[LanScopeApp] = None
    server_version = "LanScope/" + __version__

    def log_message(self, fmt, *args) -> None:  # 静默访问日志
        pass

    # ---------- 基础响应 ----------

    def _json(self, obj: Dict[str, Any], status: int = 200) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _static(self, name: str) -> None:
        path = WEB_DIR / name
        if not path.is_file():
            self._json({"error": "not found"}, 404)
            return
        ctype = {
            ".html": "text/html; charset=utf-8",
            ".js": "text/javascript; charset=utf-8",
            ".css": "text/css; charset=utf-8",
            ".svg": "image/svg+xml",
        }.get(path.suffix, "application/octet-stream")
        body = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> Dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0:
            return {}
        try:
            data = json.loads(self.rfile.read(length).decode("utf-8"))
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    # ---------- 路由 ----------

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        app = self.app
        try:
            if path in ("/", "/index.html"):
                self._static("index.html")
            elif path == "/app.js":
                self._static("app.js")
            elif path == "/style.css":
                self._static("style.css")
            elif path == "/api/state":
                self._json(app.state_payload())
            elif path == "/api/devices":
                self._json(
                    {"devices": [_device_payload(d) for d in app.store.list_devices()]}
                )
            elif path.startswith("/api/devices/"):
                self._json(app.device_detail(unquote(path.split("/")[3])))
            elif path == "/api/events":
                qs = parse_qs(parsed.query)
                limit = min(500, max(1, int(qs.get("limit", ["100"])[0])))
                unread = qs.get("unread", ["0"])[0] in ("1", "true")
                self._json({"events": app.store.list_events(limit, unread)})
            elif path == "/api/settings":
                self._json(app.store.get_settings())
            elif path == "/api/oui":
                self._json(oui_status())
            else:
                self._json({"error": "not found"}, 404)
        except Exception as exc:
            self._json({"error": str(exc)}, 500)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        app = self.app
        try:
            if path == "/api/scan":
                result = app.trigger_scan()
                self._json(result, 200 if result.get("started") else 409)
            elif path == "/api/devices/mark-all-known":
                self._json({"marked": app.store.mark_all_known()})
            elif path == "/api/events/read-all":
                app.store.mark_events_read()
                self._json({"ok": True})
            elif path == "/api/oui/refresh":
                ok = refresh_oui()
                self._json({"ok": ok, "status": oui_status()}, 200 if ok else 502)
            elif path == "/api/settings":
                app.store.update_settings(self._read_body())
                self._json(app.store.get_settings())
            else:
                self._json({"error": "not found"}, 404)
        except Exception as exc:
            self._json({"error": str(exc)}, 500)

    def do_PATCH(self) -> None:
        path = urlparse(self.path).path
        try:
            if path.startswith("/api/devices/"):
                mac = unquote(path.split("/")[3])
                ok = self.app.store.update_device(mac, self._read_body())
                self._json({"ok": ok}, 200 if ok else 404)
            else:
                self._json({"error": "not found"}, 404)
        except Exception as exc:
            self._json({"error": str(exc)}, 500)


def run_server(app: LanScopeApp) -> None:
    Handler.app = app
    server = ThreadingHTTPServer(("127.0.0.1", app.port), Handler)
    server.daemon_threads = True
    app.start_background()
    url = f"http://127.0.0.1:{app.port}/"
    print(f"LanScope {__version__}（{APP_NAME_CN}）已启动：{url}")
    print(f"网络环境：{app.env.describe()}")
    print("按 Ctrl+C 停止。")
    if app.open_browser:
        threading.Timer(0.8, webbrowser.open, args=(url,)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n正在停止…")
    finally:
        app.shutdown()
        server.server_close()
