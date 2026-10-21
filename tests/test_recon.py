"""深度侦察纯函数测试：风险规则、漏洞签名匹配、服务推断、侦察存储与自动触发门控。"""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lanscope.recon import (
    ReconRunner,
    _ber_parse,
    _ber_tlv,
    _nmap_parse_xml,
    _oid_encode,
    _service_from_banner,
    _snmp_get_request,
    _snmp_parse_response,
    _SYSDESCR_OID,
    _SYSNAME_OID,
    assess_risks,
    match_vulns,
    nmap_hint,
)
from lanscope.store import Store


def _make_snmp_response(sysdescr: bytes, sysname: bytes) -> bytes:
    """构造 v2c GET 响应夹具（GetResponse PDU＝0xA2）。"""

    def vb(oid: bytes, value: bytes) -> bytes:
        return _ber_tlv(0x30, _ber_tlv(0x06, oid) + _ber_tlv(0x04, value))

    varbinds = (
        vb(_oid_encode(_SYSDESCR_OID), sysdescr)
        + vb(_oid_encode(_SYSNAME_OID), sysname)
    )
    pdu = (
        _ber_tlv(0x02, b"\x01")
        + _ber_tlv(0x02, b"\x00")
        + _ber_tlv(0x02, b"\x00")
        + _ber_tlv(0x30, varbinds)
    )
    msg = _ber_tlv(0x02, b"\x01") + _ber_tlv(0x04, b"public") + _ber_tlv(0xA2, pdu)
    return _ber_tlv(0x30, msg)


def _port_info(port, service="", banner="", http=None):
    return {"port": port, "service": service, "banner": banner, "http": http}


class TestAssessRisks(unittest.TestCase):
    def test_telnet_critical(self):
        findings = assess_risks([_port_info(23, "telnet")], {})
        self.assertEqual(findings[0]["severity"], "critical")
        self.assertEqual(findings[0]["type"], "telnet")
        self.assertEqual(findings[0]["ports"], [23])

    def test_severity_ordering(self):
        infos = [_port_info(23), _port_info(5555), _port_info(3389)]
        severities = [f["severity"] for f in assess_risks(infos, {})]
        self.assertEqual(severities, ["critical", "critical", "medium"])

    def test_http_login_plain_medium(self):
        infos = [_port_info(80, "http", http={"login_page": True, "status": 200})]
        findings = assess_risks(infos, {})
        self.assertTrue(any(
            f["type"] == "http-login" and f["severity"] == "medium"
            for f in findings
        ))

    def test_https_login_not_flagged(self):
        infos = [_port_info(443, "https", http={"login_page": True, "status": 200})]
        findings = assess_risks(infos, {})
        self.assertFalse(any(f["type"] == "http-login" for f in findings))

    def test_no_ports_info_finding(self):
        findings = assess_risks([], {})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["type"], "no-ports")

    def test_many_ports_note(self):
        infos = [_port_info(p) for p in range(30000, 30025)]
        findings = assess_risks(infos, {})
        self.assertTrue(any(f["type"] == "many-ports" for f in findings))


class TestMatchVulns(unittest.TestCase):
    def test_vsftpd_backdoor(self):
        vulns = match_vulns([_port_info(21, "ftp", banner="vsftpd 2.3.4")])
        self.assertEqual(len(vulns), 1)
        self.assertEqual(vulns[0]["cve"], "CVE-2011-2523")
        self.assertEqual(vulns[0]["severity"], "critical")
        self.assertEqual(vulns[0]["port"], 21)

    def test_miniupnpd_version_gate(self):
        hit = match_vulns([_port_info(1900, banner="MiniUPnPd/1.4")])
        self.assertEqual(len(hit), 1)
        miss = match_vulns([_port_info(1900, banner="MiniUPnPd/1.42")])
        self.assertEqual(miss, [])

    def test_http_server_header_matched(self):
        vulns = match_vulns(
            [_port_info(80, "http", http={"server": "Apache/2.2.22 (Unix)"})]
        )
        self.assertTrue(any("Apache 2.2" in v["name"] for v in vulns))

    def test_dedup_same_port(self):
        infos = [_port_info(21, banner="vsftpd 2.3.4")]
        vulns = match_vulns(infos + infos)
        self.assertEqual(len(vulns), 1)

    def test_clean_device_no_vulns(self):
        vulns = match_vulns([_port_info(22, "ssh", banner="SSH-2.0-OpenSSH_9.6")])
        self.assertEqual(vulns, [])


class TestServiceFromBanner(unittest.TestCase):
    def test_ssh(self):
        self.assertEqual(_service_from_banner("SSH-2.0-OpenSSH_9.6", ""), "ssh")

    def test_ftp_greeting(self):
        self.assertEqual(_service_from_banner("220 Microsoft FTP Service", ""), "ftp")

    def test_fallback_kept(self):
        self.assertEqual(_service_from_banner("unknown greeting", "custom"), "custom")


class TestNmapHint(unittest.TestCase):
    def test_hint_contains_ports(self):
        hint = nmap_hint("192.168.1.1", [53, 80, 443])
        self.assertIn("nmap -sV -sC -p 53,80,443 192.168.1.1", hint)

    def test_hint_empty_ports_full_range(self):
        hint = nmap_hint("192.168.1.1", [])
        self.assertIn("1-65535", hint)


class TestSnmpCodec(unittest.TestCase):
    def test_oid_encode(self):
        self.assertEqual(
            _oid_encode("1.3.6.1.2.1.1.1.0"),
            b"\x2b\x06\x01\x02\x01\x01\x01\x00",
        )

    def test_get_request_parsable(self):
        pkt = _snmp_get_request(["1.3.6.1.2.1.1.1.0"], "public")
        parsed = _ber_parse(pkt)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed[0], 0x30)  # 顶层 SEQUENCE

    def test_parse_response(self):
        resp = _make_snmp_response(b"Linux XiaoQiang 2.6.36", b"XiaoQiang")
        out = _snmp_parse_response(resp)
        self.assertEqual(out["sysDescr"], "Linux XiaoQiang 2.6.36")
        self.assertEqual(out["sysName"], "XiaoQiang")

    def test_parse_garbage_returns_empty(self):
        self.assertEqual(_snmp_parse_response(b"\x00\x01zz"), {})


_NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
<host>
<ports>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="lighttpd" version="1.4.35" extrainfo="Xiaomi"/></port>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="dropbear" version="2019.78"/></port>
</ports>
<os><osmatch name="Linux 2.6.32 - 2.6.39" accuracy="98"/></os>
</host>
</nmaprun>"""


class TestNmapParse(unittest.TestCase):
    def test_parse_xml(self):
        result = _nmap_parse_xml(_NMAP_XML)
        self.assertEqual(result["ports"][80]["product"], "lighttpd")
        self.assertEqual(result["ports"][80]["version"], "1.4.35")
        self.assertEqual(result["ports"][80]["extrainfo"], "Xiaomi")
        self.assertEqual(result["ports"][22]["service"], "ssh")
        self.assertEqual(result["os"], "Linux 2.6.32 - 2.6.39")


class TestNewVulnSignatures(unittest.TestCase):
    def test_apache_2450_traversal(self):
        vulns = match_vulns(
            [_port_info(80, "http", http={"server": "Apache/2.4.50 (Unix)"})]
        )
        self.assertTrue(any(v["cve"] == "CVE-2021-42013" for v in vulns))

    def test_proftpd_mod_copy_version_gate(self):
        hit = match_vulns([_port_info(21, "ftp", banner="ProFTPD 1.3.5 Server")])
        self.assertTrue(any(v["cve"] == "CVE-2015-3306" for v in hit))
        miss = match_vulns([_port_info(21, "ftp", banner="ProFTPD 1.3.6 Server")])
        self.assertEqual(miss, [])

    def test_thinkphp_x_powered_by(self):
        vulns = match_vulns(
            [_port_info(8080, "http", http={"x_powered_by": "ThinkPHP 5.1.39LTS"})]
        )
        self.assertTrue(any("ThinkPHP" in v["name"] for v in vulns))

    def test_terrapin_version_gate(self):
        hit = match_vulns([_port_info(22, "ssh", banner="SSH-2.0-OpenSSH_9.5")])
        self.assertTrue(any(v["cve"] == "CVE-2023-48795" for v in hit))
        miss = match_vulns([_port_info(22, "ssh", banner="SSH-2.0-OpenSSH_9.6p1")])
        self.assertFalse(any(v["cve"] == "CVE-2023-48795" for v in miss))

    def test_hikvision_appwebs(self):
        vulns = match_vulns([_port_info(80, "http", http={"server": "App-webs/"})])
        self.assertTrue(any(v["cve"] == "CVE-2017-7921" for v in vulns))

    def test_snmp_device_level_match(self):
        vulns = match_vulns(
            [], snmp={"sysDescr": "DS-2CD2143G0-IW V5.3.0", "sysName": "Camera"}
        )
        self.assertEqual(len(vulns), 1)
        self.assertEqual(vulns[0]["port"], 0)
        self.assertTrue(vulns[0]["name"].startswith("海康"))


class TestReconStoreAndRunner(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self._tmp.name) / "test.db")

    def tearDown(self):
        self.store.close()
        self._tmp.cleanup()

    def test_save_and_latest_recon(self):
        mac = "AA:BB:CC:DD:EE:01"
        self.assertIsNone(self.store.latest_recon(mac))
        report = {
            "ts": 123.0, "mac": mac, "ip": "192.168.1.10",
            "open_count": 2, "findings": [], "vulns": [],
        }
        self.store.save_recon(mac, report)
        loaded = self.store.latest_recon(mac)
        self.assertEqual(loaded["ip"], "192.168.1.10")
        self.assertEqual(loaded["open_count"], 2)
        self.store.save_recon(mac, {**report, "open_count": 5})
        self.assertEqual(self.store.latest_recon(mac)["open_count"], 5)

    def test_auto_trigger_setting_gate(self):
        runner = ReconRunner(self.store)
        calls = []
        runner.start = lambda mac, ip: calls.append((mac, ip)) or True
        runner.auto_trigger("AA:BB:CC:DD:EE:02", "192.168.1.11")
        self.assertEqual(calls, [])  # 默认关闭
        self.store.set_setting("recon_auto", "1")
        runner.auto_trigger("AA:BB:CC:DD:EE:02", "192.168.1.11")
        self.assertEqual(calls, [("AA:BB:CC:DD:EE:02", "192.168.1.11")])
        runner.auto_trigger("AA:BB:CC:DD:EE:02", None)  # 无 IP 不触发
        self.assertEqual(len(calls), 1)


if __name__ == "__main__":
    unittest.main()
