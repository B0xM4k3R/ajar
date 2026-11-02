"""Network-tampering trio: rogue DHCP, DNS sanity, and internet health."""
import struct
import unittest
import xml.etree.ElementTree as ET

import helpers  # sets up the import path and a throwaway database
from aj import netcheck as nc
from aj import score as aj_score
from helpers import dev

DHCP_TWO = """<nmaprun><prescript>
<script id="broadcast-dhcp-discover">
 <table><elem key="Server Identifier">192.168.1.254</elem><elem key="Router">192.168.1.254</elem>
   <elem key="Domain Name Server">192.168.1.254</elem></table>
 <table><elem key="Server Identifier">192.168.1.66</elem><elem key="Router">192.168.1.66</elem>
   <elem key="Domain Name Server">192.168.1.66</elem></table>
</script></prescript></nmaprun>"""

DHCP_ONE = """<nmaprun><prescript><script id="broadcast-dhcp-discover">
 <table><elem key="Server Identifier">192.168.1.254</elem><elem key="Router">192.168.1.254</elem>
   <elem key="Domain Name Server">1.1.1.1</elem></table>
</script></prescript></nmaprun>"""


def dns_response(qid, ip):
    """A minimal DNS A-record response for example.com -> ip."""
    header = struct.pack(">HHHHHH", qid, 0x8180, 1, 1, 0, 0)
    q = b"\x07example\x03com\x00" + struct.pack(">HH", 1, 1)
    ans = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + bytes(int(x) for x in ip.split("."))
    return header + q + ans


class Dhcp(unittest.TestCase):
    def test_two_servers_is_rogue(self):
        offers = nc.parse_dhcp(ET.fromstring(DHCP_TWO))
        self.assertEqual(len(offers), 2)
        f = nc.assess_dhcp(offers, "192.168.1.254")
        self.assertEqual(f[0][:2], ("rogue_dhcp", "high"))
        self.assertIn("192.168.1.66", f[0][2])

    def test_one_server_that_is_the_router_is_clean(self):
        self.assertEqual(nc.assess_dhcp(nc.parse_dhcp(ET.fromstring(DHCP_ONE)), "192.168.1.254"), [])

    def test_wrong_gateway_offered_is_high(self):
        offers = [{"server": "192.168.1.9", "routers": ["192.168.1.9"], "dns": []}]
        f = nc.assess_dhcp(offers, "192.168.1.254")
        ids = [i for i, _, _ in f]
        self.assertIn("dhcp_gateway", ids)


class Dns(unittest.TestCase):
    def test_parse_a_records(self):
        self.assertEqual(nc.a_records(dns_response(1, "93.184.216.34")), ["93.184.216.34"])

    def test_public_domain_to_private_ip_is_hijack(self):
        results = {"192.168.1.254": {"example.com": ["192.168.1.5"], "www.cloudflare.com": ["104.16.0.1"]}}
        f = nc.assess_dns(results, "192.168.1.254")
        self.assertEqual(f[0][:2], ("dns_hijack", "high"))

    def test_clean_dns_is_quiet(self):
        results = {"192.168.1.254": {"example.com": ["93.184.216.34"]}}
        self.assertEqual(nc.assess_dns(results, "192.168.1.254", known_good={"192.168.1.254"}), [])

    def test_unexpected_resolver_is_info(self):
        results = {"192.168.1.9": {"example.com": ["93.184.216.34"]}}
        f = nc.assess_dns(results, "192.168.1.254", known_good=nc.PUBLIC_RESOLVERS | {"192.168.1.254"})
        self.assertEqual(f[0][:2], ("dns_unexpected", "info"))

    def test_build_query_roundtrips_the_name(self):
        q = nc.build_dns_query("dns.google")
        self.assertIn(b"\x03dns\x06google\x00", q)


class Health(unittest.TestCase):
    def test_cause_attribution(self):
        self.assertIsNone(nc.cause({"net": True, "gw": True}))
        self.assertIn("provider", nc.cause({"net": False, "gw": True}))
        self.assertIn("router", nc.cause({"net": False, "gw": False}))

    def test_events_on_transitions(self):
        down = nc.health_events({"net": True, "gw": True}, {"net": False, "gw": True}, "Home")
        self.assertEqual(down[0][:2], ("internet_down", "medium"))
        self.assertIn("provider", down[0][2])
        up = nc.health_events({"net": False, "gw": True}, {"net": True, "gw": True}, "Home")
        self.assertEqual(up[0][:2], ("internet_up", "info"))
        self.assertEqual(nc.health_events(None, {"net": True, "gw": True}, "Home"), [])

    def test_summary_uptime_and_last_outage(self):
        now = 1_000_000
        samples = ([{"t": now - 7000 + i * 600, "gw": True, "net": True, "lat": 20} for i in range(10)]
                   + [{"t": now - 1000, "gw": True, "net": False, "lat": None},
                      {"t": now - 400, "gw": True, "net": False, "lat": None},
                      {"t": now, "gw": True, "net": True, "lat": 25}])
        s = nc.health_summary(samples, now)
        self.assertEqual(s["status"], "up")
        self.assertTrue(80 < s["uptime_7d"] < 90)  # 11 of 13 samples up
        self.assertIsNotNone(s["last_outage"])
        self.assertFalse(s["last_outage"]["ongoing"])
        self.assertIn("provider", s["last_outage"]["cause"])

    def test_empty_summary(self):
        self.assertEqual(nc.health_summary([])["status"], "unknown")


class Scoring(unittest.TestCase):
    def test_rogue_dhcp_scores_and_fails_check(self):
        result = {"findings": [{"id": "rogue_dhcp", "level": "high", "text": "Two DHCP servers."},
                               {"id": "dns_unexpected", "level": "info", "text": "Pi-hole maybe."}]}
        r = aj_score.security_report([dev("192.168.1.2")], None, netcheck=result)
        pts = {i["id"]: i["points"] for i in r["issues"]}
        self.assertEqual(pts.get("rogue_dhcp"), 30)
        self.assertNotIn("dns_unexpected", pts)              # info -> advisory
        self.assertTrue(any("Pi-hole" in o for o in r["optional"]))
        check = next(c for c in r["checks"] if "rogue DHCP" in c["label"])
        self.assertEqual(check["status"], "fail")

    def test_check_unknown_until_run(self):
        r = aj_score.security_report([dev("192.168.1.2")], None)
        self.assertEqual(next(c for c in r["checks"] if "rogue DHCP" in c["label"])["status"], "unknown")


if __name__ == "__main__":
    unittest.main(verbosity=2)
