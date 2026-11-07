import unittest
import xml.etree.ElementTree as ET
from unittest import mock

import helpers  # noqa: F401
from aj import audit as aj_audit
from aj import config, discovery, ipv6
from aj.db import db, set_net_setting

LINUX = """2001:db8::1 dev eth0 lladdr aa:bb:cc:00:00:01 router REACHABLE
2001:db8::5 dev eth0 lladdr aa:bb:cc:00:00:05 STALE
fd12:3456::5 dev eth0 lladdr aa:bb:cc:00:00:05 REACHABLE
fe80::1 dev eth0 lladdr aa:bb:cc:00:00:01 router STALE
ff02::1 dev eth0 lladdr 33:33:00:00:00:01 NOARP
2001:db8::99 dev eth0 FAILED
2001:db8::77 dev eth0 lladdr aa:bb:cc:00:00:77 FAILED
"""
MACOS = """Neighbor                        Linklayer Address  Netif Expire    St Flgs Prbs
2001:db8::5                     a:bb:cc:0:0:5      en0   23h59m3s  S
fe80::1%en0                     aa:bb:cc:0:0:1     en0   permanent R
2001:db8::9                     (incomplete)       en0   expired   N
"""
WINDOWS = """Interface 12: Wi-Fi

Internet Address                              Physical Address   Type
--------------------------------------------  -----------------  -----------
2001:db8::5                                   aa-bb-cc-00-00-05  Reachable
fe80::1                                       aa-bb-cc-00-00-01  Stale
ff02::2                                       33-33-00-00-00-02  Permanent
2001:db8::6                                   aa-bb-cc-00-00-06  Unreachable
"""


def xml_for(ips):
    return ET.fromstring("<nmaprun>" + "".join(
        f"<host><status state='up'/><address addr='{ip}' addrtype='ipv4'/></host>" for ip in ips) + "</nmaprun>")


class ExtraSubnets(unittest.TestCase):
    OWN = ("192.168.1.2", "aa:00:00:00:00:02")

    def test_adds_hosts_tracked_by_ip_and_never_duplicates(self):
        found = [("aa:00:00:00:00:05", "192.168.1.5", "pc", "Dell", False)]
        run = lambda args, timeout=0: xml_for(["10.0.5.20", "10.0.5.21", "192.168.1.5"])
        got = discovery.add_extra_subnets(found, ["10.0.5.0/24"], *self.OWN, nmap=run)
        self.assertEqual([f[0] for f in got], ["aa:00:00:00:00:05", "ip:10.0.5.20", "ip:10.0.5.21"])

    def test_nothing_listed_means_no_scan(self):
        self.assertEqual(discovery.add_extra_subnets([("m", "1.1.1.1", None, None, False)], [], *self.OWN,
                                                     nmap=lambda *a, **k: self.fail("scanned")), [("m", "1.1.1.1", None, None, False)])

    def test_full_scan_includes_extra_networks_and_keeps_them_separate_from_arp_rechecks(self):
        net = "nextra"
        set_net_setting(net, "extra_subnets", ["10.0.5.0/24"])
        c = db(); c.execute("DELETE FROM devices"); c.execute("DELETE FROM networks"); c.execute("DELETE FROM events"); c.commit(); c.close()
        calls = []

        def run(args, timeout=0):
            calls.append(args)
            if "10.0.5.0/24" in args:
                return xml_for(["10.0.5.20"])
            if args[0] == "-sn" and "-PR" in args:   # an ARP re-check: must never be asked about the routed network
                self.assertNotIn("10.0.5.20", args)
                return xml_for([])
            h = ("<nmaprun><host><status state='up'/><address addr='192.168.1.1' addrtype='ipv4'/>"
                 "<address addr='aa:00:00:00:00:01' addrtype='mac' vendor='Netgear'/></host>"
                 "<host><status state='up'/><address addr='192.168.1.5' addrtype='ipv4'/>"
                 "<address addr='aa:00:00:00:00:05' addrtype='mac' vendor='Dell'/></host></nmaprun>")
            return ET.fromstring(h)
        with mock.patch.object(discovery, "net_info", lambda: ("192.168.1.1", "192.168.1.0/24", "192.168.1.2", "aa:00:00:00:00:02")), \
                mock.patch.object(discovery, "run_nmap", run), mock.patch.object(discovery, "current_net", lambda: net), \
                mock.patch.object(discovery.socket, "gethostbyaddr", side_effect=OSError), \
                mock.patch.object(discovery, "mdns_scan", lambda *a, **k: {}):
            discovery.scan()
            discovery.scan()  # twice: the second must not try to ARP the routed device
        c = db(); macs = {r["mac"] for r in c.execute("SELECT mac FROM devices")}; c.close()
        self.assertIn("ip:10.0.5.20", macs)
        self.assertIn("aa:00:00:00:00:05", macs)
        self.assertTrue(any("10.0.5.0/24" in a for a in calls))


if __name__ == "__main__":
    unittest.main()
