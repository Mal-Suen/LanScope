"""arp -a 解析测试（中英文夹具、组播过滤、多接口归属）。"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lanscope.discover import parse_arp_table

ARP_ZH = """接口: 192.168.1.20 --- 0x8
  Internet 地址          物理地址              类型
  192.168.1.1            a1-b2-c3-d4-e5-f6     动态
  192.168.1.5            11-22-33-44-55-66     动态
  224.0.0.22             01-00-5e-00-00-16     静态
  239.255.255.250        01-00-5e-7f-ff-fa     静态

接口: 198.18.0.1 --- 0xc
  Internet 地址          物理地址              类型
  198.18.0.2             99-88-77-66-55-44     动态
"""

ARP_EN = """Interface: 192.168.1.20 --- 0x8
  Internet Address      Physical Address      Type
  192.168.1.1            a1-b2-c3-d4-e5-f6     dynamic
  192.168.1.5            11-22-33-44-55-66     dynamic
"""


class TestParseArpTable(unittest.TestCase):
    def test_chinese(self):
        entries = parse_arp_table(ARP_ZH)
        # 组播/广播伪条目被过滤；两个接口共 3 条
        self.assertEqual(len(entries), 3)
        first = entries[0]
        self.assertEqual(first["iface"], "192.168.1.20")
        self.assertEqual(first["ip"], "192.168.1.1")
        self.assertEqual(first["mac"], "A1:B2:C3:D4:E5:F6")
        self.assertEqual(first["type"], "动态")
        self.assertEqual(entries[2]["iface"], "198.18.0.1")
        self.assertEqual(entries[2]["ip"], "198.18.0.2")

    def test_english(self):
        entries = parse_arp_table(ARP_EN)
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0]["type"], "dynamic")
        self.assertEqual(entries[1]["mac"], "11:22:33:44:55:66")


if __name__ == "__main__":
    unittest.main()
