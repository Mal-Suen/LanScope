"""netinfo 解析与网卡选择测试（中英文 ipconfig 夹具）。"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lanscope.netinfo import NetEnv, norm_mac, parse_ipconfig, select_lan_adapter

IPCONFIG_ZH = """Windows IP 配置

主机名 . . . . . . . . . . . . . : DESKTOP-ABC
主 DNS 后缀 . . . . . . . . . . . :

以太网适配器 以太网:

   连接特定的 DNS 后缀 . . . . . . . . :
   描述. . . . . . . . . . . . . . . : Realtek PCIe GBE Family Controller
   物理地址. . . . . . . . . . . . . : 11-22-33-44-55-66
   DHCP 已启用 . . . . . . . . . . . : 是
   自动配置已启用. . . . . . . . . . : 是
   IPv4 地址 . . . . . . . . . . . . : 192.168.1.20(首选)
   子网掩码  . . . . . . . . . . . . : 255.255.255.0
   获得租约的时间 . . . . . . . . . . : 2026年10月21日 8:00:00
   默认网关. . . . . . . . . . . . . : 192.168.1.1
   DHCP 服务器. . . . . . . . . . . : 192.168.1.1
   DNS 服务器 . . . . . . . . . . . : 192.168.1.1
   TCPIP 上的 NetBIOS . . . . . . . : 已启用

以太网适配器 Clash:

   连接特定的 DNS 后缀 . . . . . . . . :
   描述. . . . . . . . . . . . . . . : Clash Virtual Ethernet
   物理地址. . . . . . . . . . . . . : AA-BB-CC-DD-EE-FF
   DHCP 已启用 . . . . . . . . . . . : 否
   自动配置已启用. . . . . . . . . . : 是
   IPv4 地址 . . . . . . . . . . . . : 198.18.0.1(首选)
   子网掩码  . . . . . . . . . . . . : 255.255.255.0
   默认网关. . . . . . . . . . . . . :

以太网适配器 VMware Network Adapter VMnet1:

   连接特定的 DNS 后缀 . . . . . . . . :
   描述. . . . . . . . . . . . . . . : VMware Virtual Ethernet Adapter for VMnet1
   物理地址. . . . . . . . . . . . . : 00-50-56-C0-00-01
   DHCP 已启用 . . . . . . . . . . . : 否
   IPv4 地址 . . . . . . . . . . . . : 192.168.152.1(首选)
   子网掩码  . . . . . . . . . . . . : 255.255.255.0
   默认网关. . . . . . . . . . . . . :
"""

IPCONFIG_EN = """Windows IP Configuration

Host Name . . . . . . . . . . . . . : DESKTOP-ABC

Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . :
   Description . . . . . . . . . . . : Realtek PCIe GBE Family Controller
   Physical Address. . . . . . . . . : 11-22-33-44-55-66
   DHCP Enabled. . . . . . . . . . . : Yes
   Autoconfiguration Enabled . . . . : Yes
   IPv4 Address. . . . . . . . . . . : 192.168.1.20(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.1.1
   DHCP Server . . . . . . . . . . . : 192.168.1.1

Ethernet adapter Clash:

   Description . . . . . . . . . . . : Clash Virtual Ethernet
   Physical Address. . . . . . . . . : AA-BB-CC-DD-EE-FF
   DHCP Enabled. . . . . . . . . . . : No
   IPv4 Address. . . . . . . . . . . : 198.18.0.1(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . :
"""


class TestParseIpconfig(unittest.TestCase):
    def test_parse_chinese(self):
        adapters = parse_ipconfig(IPCONFIG_ZH)
        self.assertEqual(len(adapters), 3)
        eth = adapters[0]
        self.assertEqual(eth.name, "以太网")
        self.assertEqual(eth.ipv4, ["192.168.1.20"])
        self.assertEqual(eth.netmasks, ["255.255.255.0"])
        self.assertEqual(eth.gateway, "192.168.1.1")
        self.assertEqual(eth.mac, "11:22:33:44:55:66")
        # 「DHCP 服务器」行不得覆盖「DHCP 已启用」标志
        self.assertTrue(eth.dhcp)
        self.assertEqual(eth.description, "Realtek PCIe GBE Family Controller")

    def test_parse_english(self):
        adapters = parse_ipconfig(IPCONFIG_EN)
        self.assertEqual(len(adapters), 2)
        eth = adapters[0]
        self.assertEqual(eth.name, "Ethernet")
        self.assertEqual(eth.ipv4, ["192.168.1.20"])
        self.assertEqual(eth.gateway, "192.168.1.1")
        self.assertEqual(eth.mac, "11:22:33:44:55:66")
        self.assertTrue(eth.dhcp)

    def test_select_lan_adapter_skips_tun_and_vmware(self):
        for text in (IPCONFIG_ZH, IPCONFIG_EN):
            best = select_lan_adapter(parse_ipconfig(text))
            self.assertIsNotNone(best)
            self.assertEqual(best.ipv4[0], "192.168.1.20")
            self.assertEqual(best.gateway, "192.168.1.1")


class TestNormMac(unittest.TestCase):
    def test_norm(self):
        self.assertEqual(norm_mac("aa-bb-cc-dd-ee-ff"), "AA:BB:CC:DD:EE:FF")
        self.assertEqual(norm_mac("AA:BB:CC:DD:EE:FF"), "AA:BB:CC:DD:EE:FF")
        self.assertEqual(norm_mac("aabbccddeeff"), "AA:BB:CC:DD:EE:FF")
        self.assertEqual(norm_mac("short"), "")
        self.assertEqual(norm_mac(""), "")


class TestNetEnv(unittest.TestCase):
    def setUp(self):
        self.env = NetEnv(
            ip="192.168.1.20",
            netmask="255.255.255.0",
            gateway="192.168.1.1",
            adapter="以太网",
            mac="11:22:33:44:55:66",
        )

    def test_cidr(self):
        self.assertEqual(self.env.cidr, "192.168.1.0/24")

    def test_hosts(self):
        hosts = self.env.hosts()
        self.assertEqual(len(hosts), 253)  # .1～.254 去掉本机 .20
        self.assertNotIn("192.168.1.20", hosts)
        self.assertNotIn("192.168.1.0", hosts)
        self.assertNotIn("192.168.1.255", hosts)
        self.assertIn("192.168.1.1", hosts)


if __name__ == "__main__":
    unittest.main()
