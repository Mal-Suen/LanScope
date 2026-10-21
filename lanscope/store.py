"""SQLite 持久化：设备台账、扫描记录、在场历史、事件、端口快照、设置。"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

DEFAULT_DB = Path(__file__).resolve().parent.parent / "data" / "lanscope.db"

DEFAULT_SETTINGS: Dict[str, str] = {
    "patrol_interval": "300",
    "port_scan": "1",
    "sniffer": "1",
    "toast_critical": "1",
}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS devices(
    mac TEXT PRIMARY KEY,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    last_ip TEXT,
    hostname TEXT,
    vendor TEXT,
    device_type TEXT DEFAULT 'unknown',
    custom_name TEXT,
    custom_type TEXT,
    notes TEXT,
    known INTEGER NOT NULL DEFAULT 0,
    starred INTEGER NOT NULL DEFAULT 0,
    status INTEGER NOT NULL DEFAULT 0,
    missed INTEGER NOT NULL DEFAULT 0,
    services TEXT
);
CREATE TABLE IF NOT EXISTS scan_runs(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started REAL NOT NULL,
    finished REAL,
    online INTEGER,
    trigger TEXT
);
CREATE TABLE IF NOT EXISTS presences(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER,
    mac TEXT NOT NULL,
    ip TEXT,
    ts REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pres_mac ON presences(mac, ts);
CREATE TABLE IF NOT EXISTS events(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    severity TEXT NOT NULL,
    type TEXT NOT NULL,
    mac TEXT,
    ip TEXT,
    message TEXT,
    read INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE TABLE IF NOT EXISTS port_snapshots(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac TEXT NOT NULL,
    ts REAL NOT NULL,
    ports TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS settings(
    key TEXT PRIMARY KEY,
    value TEXT
);
"""


def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
    return {k: row[k] for k in row.keys()}


class Store:
    def __init__(self, path: Optional[Path] = None):
        self.path = Path(path) if path else DEFAULT_DB
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False, timeout=10)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(_SCHEMA)
            cols = [r["name"] for r in self._conn.execute("PRAGMA table_info(devices)")]
            if "services" not in cols:
                self._conn.execute("ALTER TABLE devices ADD COLUMN services TEXT")
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ---------- 设置 ----------

    def get_settings(self) -> Dict[str, str]:
        with self._lock:
            rows = self._conn.execute("SELECT key, value FROM settings").fetchall()
        merged = dict(DEFAULT_SETTINGS)
        merged.update({r["key"]: r["value"] for r in rows})
        return merged

    def set_setting(self, key: str, value: Any) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO settings(key, value) VALUES(?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (str(key), str(value)),
            )
            self._conn.commit()

    def update_settings(self, patch: Dict[str, Any]) -> None:
        for key, value in patch.items():
            if key in DEFAULT_SETTINGS:
                self.set_setting(key, value)

    # ---------- 设备 ----------

    def device_exists(self, mac: str) -> bool:
        with self._lock:
            row = self._conn.execute("SELECT 1 FROM devices WHERE mac=?", (mac,)).fetchone()
        return row is not None

    def mark_seen(
        self,
        mac: str,
        ip: str,
        ts: Optional[float] = None,
        hostname: Optional[str] = None,
        vendor: Optional[str] = None,
        device_type: Optional[str] = None,
    ) -> None:
        ts = ts or time.time()
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO devices(mac, first_seen, last_seen, last_ip, hostname,
                                    vendor, device_type, status, missed)
                VALUES(?,?,?,?,?,?,?,1,0)
                ON CONFLICT(mac) DO UPDATE SET
                    last_seen=excluded.last_seen,
                    last_ip=excluded.last_ip,
                    status=1,
                    missed=0,
                    hostname=COALESCE(NULLIF(excluded.hostname,''), devices.hostname),
                    vendor=COALESCE(NULLIF(excluded.vendor,''), devices.vendor),
                    device_type=CASE
                        WHEN excluded.device_type IS NULL OR excluded.device_type='unknown'
                        THEN devices.device_type ELSE excluded.device_type END
                """,
                (mac, ts, ts, ip, hostname, vendor, device_type),
            )
            self._conn.commit()

    def get_device(self, mac: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._conn.execute("SELECT * FROM devices WHERE mac=?", (mac,)).fetchone()
        return _row_to_dict(row) if row else None

    def list_devices(self) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT d.*, (SELECT ps.ports FROM port_snapshots ps "
                "WHERE ps.mac = d.mac ORDER BY ps.id DESC LIMIT 1) AS last_ports "
                "FROM devices d ORDER BY d.status DESC, d.starred DESC, d.last_seen DESC"
            ).fetchall()
        return [_row_to_dict(r) for r in rows]

    def update_device(self, mac: str, patch: Dict[str, Any]) -> bool:
        allowed = {}
        for key in ("custom_name", "custom_type", "notes"):
            if key in patch:
                allowed[key] = patch[key]
        for key in ("known", "starred"):
            if key in patch:
                allowed[key] = 1 if patch[key] else 0
        if not allowed:
            return False
        sets = ", ".join(f"{k}=?" for k in allowed)
        vals = list(allowed.values()) + [mac]
        with self._lock:
            cur = self._conn.execute(f"UPDATE devices SET {sets} WHERE mac=?", vals)
            self._conn.commit()
        return cur.rowcount > 0

    def mark_all_known(self) -> int:
        with self._lock:
            cur = self._conn.execute("UPDATE devices SET known=1 WHERE known=0")
            self._conn.commit()
        return cur.rowcount

    def set_offline(self, mac: str, missed: int) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE devices SET status=0, missed=? WHERE mac=?", (missed, mac)
            )
            self._conn.commit()

    def bump_missed(self, mac: str) -> int:
        with self._lock:
            self._conn.execute("UPDATE devices SET missed=missed+1 WHERE mac=?", (mac,))
            row = self._conn.execute("SELECT missed FROM devices WHERE mac=?", (mac,)).fetchone()
            self._conn.commit()
        return row["missed"] if row else 0

    # ---------- 扫描与在场 ----------

    def begin_scan(self, trigger: str) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO scan_runs(started, trigger) VALUES(?, ?)",
                (time.time(), trigger),
            )
            self._conn.commit()
        return cur.lastrowid

    def finish_scan(self, run_id: int, online: int) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE scan_runs SET finished=?, online=? WHERE id=?",
                (time.time(), online, run_id),
            )
            self._conn.commit()

    def add_presence(self, run_id: int, mac: str, ip: str, ts: Optional[float] = None) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO presences(run_id, mac, ip, ts) VALUES(?,?,?,?)",
                (run_id, mac, ip, ts or time.time()),
            )
            self._conn.commit()

    def last_run(self) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM scan_runs ORDER BY id DESC LIMIT 1"
            ).fetchone()
        return _row_to_dict(row) if row else None

    def timeline(self, mac: str, since: Optional[float] = None) -> List[Dict[str, Any]]:
        since = since or (time.time() - 48 * 3600)
        with self._lock:
            rows = self._conn.execute(
                "SELECT ts, ip, run_id FROM presences WHERE mac=? AND ts>=? ORDER BY ts",
                (mac, since),
            ).fetchall()
        return [_row_to_dict(r) for r in rows]

    # ---------- 事件 ----------

    def add_event(
        self,
        severity: str,
        type_: str,
        message: str,
        mac: Optional[str] = None,
        ip: Optional[str] = None,
        ts: Optional[float] = None,
    ) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO events(ts, severity, type, mac, ip, message) VALUES(?,?,?,?,?,?)",
                (ts or time.time(), severity, type_, mac, ip, message),
            )
            self._conn.commit()
        return cur.lastrowid

    def list_events(self, limit: int = 100, unread_only: bool = False) -> List[Dict[str, Any]]:
        cond = " WHERE read=0" if unread_only else ""
        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM events{cond} ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [_row_to_dict(r) for r in rows]

    def events_for_device(self, mac: str, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM events WHERE mac=? ORDER BY id DESC LIMIT ?", (mac, limit)
            ).fetchall()
        return [_row_to_dict(r) for r in rows]

    def mark_events_read(self) -> None:
        with self._lock:
            self._conn.execute("UPDATE events SET read=1 WHERE read=0")
            self._conn.commit()

    def unread_count(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) AS c FROM events WHERE read=0").fetchone()
        return row["c"]

    # ---------- 端口 ----------

    def save_ports(self, mac: str, ports: List[int]) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO port_snapshots(mac, ts, ports) VALUES(?,?,?)",
                (mac, time.time(), json.dumps(sorted(ports))),
            )
            self._conn.commit()

    def latest_ports(self, mac: str) -> List[int]:
        with self._lock:
            row = self._conn.execute(
                "SELECT ports FROM port_snapshots WHERE mac=? ORDER BY id DESC LIMIT 1",
                (mac,),
            ).fetchone()
        return json.loads(row["ports"]) if row else []

    def set_services(self, mac: str, services: Dict[Any, Any]) -> None:
        payload = json.dumps(
            {str(k): v for k, v in services.items()}, ensure_ascii=False
        )
        with self._lock:
            self._conn.execute(
                "UPDATE devices SET services=? WHERE mac=?", (payload, mac)
            )
            self._conn.commit()

    # ---------- 统计 ----------

    def stats(self) -> Dict[str, int]:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS total, COALESCE(SUM(status),0) AS online, "
                "COALESCE(SUM(known),0) AS known FROM devices"
            ).fetchone()
            unread = self._conn.execute(
                "SELECT COUNT(*) AS c FROM events WHERE read=0"
            ).fetchone()["c"]
        return {
            "total": row["total"],
            "online": row["online"],
            "known": row["known"],
            "unknown": row["total"] - row["known"],
            "unread": unread,
        }
