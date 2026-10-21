"""存储层全流程测试：设备、事件、端口、扫描记录、时间线、统计、设置。"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lanscope.store import Store

MAC1 = "AA:BB:CC:DD:EE:01"
MAC2 = "AA:BB:CC:DD:EE:02"
MAC3 = "AA:BB:CC:DD:EE:03"


class TestStore(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self._tmp.name) / "test.db")

    def tearDown(self):
        self.store.close()
        self._tmp.cleanup()

    def test_mark_seen_insert_and_update(self):
        self.assertFalse(self.store.device_exists(MAC1))
        self.store.mark_seen(
            MAC1, "192.168.1.10", hostname="box", vendor="Test Vendor",
            device_type="pc",
        )
        dev = self.store.get_device(MAC1)
        self.assertEqual(dev["hostname"], "box")
        self.assertEqual(dev["vendor"], "Test Vendor")
        self.assertEqual(dev["device_type"], "pc")
        self.assertEqual(dev["status"], 1)
        self.assertEqual(dev["missed"], 0)
        first_seen = dev["first_seen"]

        # hostname 传 None 时保留旧值；IP 更新
        self.store.mark_seen(MAC1, "192.168.1.11")
        dev = self.store.get_device(MAC1)
        self.assertEqual(dev["hostname"], "box")
        self.assertEqual(dev["last_ip"], "192.168.1.11")
        self.assertEqual(dev["first_seen"], first_seen)

    def test_device_type_not_downgraded(self):
        self.store.mark_seen(MAC1, "192.168.1.10", device_type="router")
        self.store.mark_seen(MAC1, "192.168.1.10", device_type="unknown")
        self.assertEqual(self.store.get_device(MAC1)["device_type"], "router")

    def test_update_device_and_mark_all_known(self):
        self.store.mark_seen(MAC1, "192.168.1.10")
        ok = self.store.update_device(
            MAC1, {"custom_name": "客厅电视", "known": 1, "starred": 1, "notes": "测试"}
        )
        self.assertTrue(ok)
        dev = self.store.get_device(MAC1)
        self.assertEqual(dev["custom_name"], "客厅电视")
        self.assertEqual(dev["known"], 1)
        self.assertEqual(dev["starred"], 1)
        self.assertEqual(dev["notes"], "测试")

        self.store.mark_seen(MAC2, "192.168.1.12")
        marked = self.store.mark_all_known()
        self.assertGreaterEqual(marked, 1)
        self.assertEqual(self.store.get_device(MAC2)["known"], 1)

    def test_events_flow(self):
        self.store.add_event("warn", "new_device", "发现新设备：X", mac=MAC1,
                             ip="192.168.1.10")
        self.store.add_event("info", "device_online", "上线")
        self.assertEqual(self.store.unread_count(), 2)
        events = self.store.list_events()
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["message"], "上线")  # id 倒序
        self.assertEqual(len(self.store.list_events(unread_only=True)), 2)
        self.store.mark_events_read()
        self.assertEqual(self.store.unread_count(), 0)
        self.assertEqual(len(self.store.list_events(unread_only=True)), 0)

    def test_events_for_device(self):
        self.store.add_event("warn", "new_device", "ev1", mac=MAC1)
        self.store.add_event("info", "device_online", "ev2", mac=MAC1)
        self.store.add_event("info", "device_offline", "other", mac=MAC2)
        evs = self.store.events_for_device(MAC1)
        self.assertEqual(len(evs), 2)

    def test_ports_and_services(self):
        self.store.mark_seen(MAC1, "192.168.1.10")
        self.assertEqual(self.store.latest_ports(MAC1), [])
        self.store.save_ports(MAC1, [80, 443])
        self.assertEqual(self.store.latest_ports(MAC1), [80, 443])
        self.store.save_ports(MAC1, [22])
        self.assertEqual(self.store.latest_ports(MAC1), [22])
        self.store.set_services(MAC1, {80: "HTTP: Test", 22: "SSH-2.0-OpenSSH"})
        dev = self.store.get_device(MAC1)
        self.assertEqual(json.loads(dev["services"])["80"], "HTTP: Test")

    def test_scan_runs_and_timeline(self):
        run_id = self.store.begin_scan("manual")
        self.store.add_presence(run_id, MAC1, "192.168.1.10")
        self.store.finish_scan(run_id, 1)
        last = self.store.last_run()
        self.assertEqual(last["trigger"], "manual")
        self.assertEqual(last["online"], 1)
        tl = self.store.timeline(MAC1)
        self.assertEqual(len(tl), 1)
        self.assertEqual(tl[0]["ip"], "192.168.1.10")

    def test_offline_flow(self):
        self.store.mark_seen(MAC1, "192.168.1.10")
        self.assertEqual(self.store.bump_missed(MAC1), 1)
        self.assertEqual(self.store.bump_missed(MAC1), 2)
        self.store.set_offline(MAC1, 2)
        dev = self.store.get_device(MAC1)
        self.assertEqual(dev["status"], 0)
        self.assertEqual(dev["missed"], 2)
        # 重新出现后 missed 归零、状态在线
        self.store.mark_seen(MAC1, "192.168.1.10")
        dev = self.store.get_device(MAC1)
        self.assertEqual(dev["status"], 1)
        self.assertEqual(dev["missed"], 0)

    def test_stats(self):
        self.store.mark_seen(MAC1, "192.168.1.10")
        self.store.mark_seen(MAC2, "192.168.1.11")
        self.store.update_device(MAC1, {"known": 1})
        s = self.store.stats()
        self.assertEqual(s["total"], 2)
        self.assertEqual(s["online"], 2)
        self.assertEqual(s["known"], 1)
        self.assertEqual(s["unknown"], 1)
        self.assertEqual(s["unread"], 0)

    def test_settings(self):
        s = self.store.get_settings()
        self.assertEqual(s["patrol_interval"], "300")
        self.store.update_settings({"patrol_interval": "120", "bogus": "x"})
        s = self.store.get_settings()
        self.assertEqual(s["patrol_interval"], "120")
        self.assertNotIn("bogus", s)

    def test_list_devices_joins_ports(self):
        self.store.mark_seen(MAC1, "192.168.1.10")
        self.store.mark_seen(MAC2, "192.168.1.11")
        self.store.save_ports(MAC1, [80])
        devices = self.store.list_devices()
        self.assertEqual(len(devices), 2)
        by_mac = {d["mac"]: d for d in devices}
        self.assertEqual(json.loads(by_mac[MAC1]["last_ports"]), [80])
        self.assertIsNone(by_mac[MAC2]["last_ports"])


if __name__ == "__main__":
    unittest.main()
