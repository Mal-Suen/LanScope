"""OUI 解析、厂商查询与设备类型推断规则测试。"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lanscope.fingerprint import infer_device_type, lookup_vendor, parse_oui_text

OUI_SAMPLE = """
00-00-0C   (hex)		Cisco Systems, Inc
AC-DE-48   (hex)		Apple, Inc.
50-C7-BF   (hex)		TP-LINK TECHNOLOGIES CO.,LTD.
24-6F-28   (hex)		Espressif Inc.
this line is not an oui entry
"""


class TestParseOui(unittest.TestCase):
    def test_parse(self):
        mapping = parse_oui_text(OUI_SAMPLE)
        self.assertEqual(len(mapping), 4)
        self.assertEqual(mapping["00000C"], "Cisco Systems, Inc")
        self.assertEqual(mapping["ACDE48"], "Apple, Inc.")
        self.assertEqual(mapping["50C7BF"], "TP-LINK TECHNOLOGIES CO.,LTD.")
        self.assertEqual(mapping["246F28"], "Espressif Inc.")


class TestLookupVendor(unittest.TestCase):
    def test_lookup(self):
        oui = {"ACDE48": "Apple, Inc.", "00000C": "Cisco Systems, Inc"}
        self.assertEqual(lookup_vendor("AC:DE:48:00:11:22", oui), "Apple, Inc.")
        self.assertEqual(lookup_vendor("00:00:0C:11:22:33", oui), "Cisco Systems, Inc")
        self.assertEqual(lookup_vendor("FF:FF:FF:FF:FF:FF", oui), "")


class TestInferDeviceType(unittest.TestCase):
    def test_ssdp_gateway_is_router(self):
        self.assertEqual(
            infer_device_type(ssdp_type="InternetGatewayDevice"), "router"
        )

    def test_ssdp_media_renderer_is_tv(self):
        self.assertEqual(infer_device_type(ssdp_type="MediaRenderer"), "tv")

    def test_printer_ports(self):
        self.assertEqual(infer_device_type(ports=[80, 631, 9100]), "printer")

    def test_camera_port(self):
        self.assertEqual(infer_device_type(ports=[554, 80]), "camera")

    def test_android_hostname_is_phone(self):
        self.assertEqual(infer_device_type(hostname="android-abc123"), "phone")

    def test_mdns_tv_hint(self):
        self.assertEqual(infer_device_type(mdns_hints=["tv"]), "tv")

    def test_mdns_printer_hint(self):
        self.assertEqual(infer_device_type(mdns_hints=["printer"]), "printer")

    def test_router_vendor_with_web_port(self):
        self.assertEqual(
            infer_device_type(vendor="TP-LINK TECHNOLOGIES CO.,LTD.", ports=[80]),
            "router",
        )

    def test_iot_vendor(self):
        self.assertEqual(infer_device_type(vendor="Espressif Inc."), "iot")

    def test_smb_is_pc(self):
        self.assertEqual(infer_device_type(ports=[445, 139]), "pc")

    def test_rdp_is_pc(self):
        self.assertEqual(infer_device_type(ports=[3389]), "pc")

    def test_apple_vendor_is_phone(self):
        self.assertEqual(infer_device_type(vendor="Apple, Inc."), "phone")

    def test_raspberry_name_is_pc(self):
        self.assertEqual(infer_device_type(hostname="raspberrypi"), "pc")

    def test_empty_is_unknown(self):
        self.assertEqual(infer_device_type(), "unknown")


if __name__ == "__main__":
    unittest.main()
