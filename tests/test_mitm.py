import unittest
from aj import mitm

MAC_OS = """? (192.168.1.1) at a4:b1:c1:12:34:56 on en0 ifscope [ethernet]
? (192.168.1.5) at 0:1a:2b:3c:4d:5e on en0 ifscope [ethernet]
? (192.168.1.9) at (incomplete) on en0 ifscope [ethernet]
? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]
"""
WINDOWS = """Interface: 192.168.1.20 --- 0x9
  Internet Address      Physical Address      Type
  192.168.1.1           a4-b1-c1-12-34-56     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
"""
GW, GW_MAC = "192.168.1.1", "a4:b1:c1:12:34:56"


def ids(findings):
    return sorted((f["id"], f["level"]) for f in findings)


class TestParse(unittest.TestCase):
    def test_parses_macos_arp(self):
        t = mitm.parse_arp_output(MAC_OS)
        self.assertEqual(t["192.168.1.1"], GW_MAC)
        self.assertEqual(t["192.168.1.5"], "00:1a:2b:3c:4d:5e")  # leading zero restored
        self.assertNotIn("192.168.1.9", t)  # incomplete entry skipped

    def test_parses_windows_arp(self):
        self.assertEqual(mitm.parse_arp_output(WINDOWS)["192.168.1.1"], GW_MAC)

    def test_only_the_scanned_subnet(self):
        t = {"192.168.1.5": "aa:aa:aa:aa:aa:01", "172.17.0.2": "aa:aa:aa:aa:aa:02", "bad": "x"}
        self.assertEqual(mitm.in_subnet(t, "192.168.1.0/24"), {"192.168.1.5": "aa:aa:aa:aa:aa:01"})
        self.assertEqual(len(mitm.in_subnet(t, None)), 3)


class TestAnalyze(unittest.TestCase):
    def test_normal_network_is_quiet(self):
        t = {GW: GW_MAC, "192.168.1.5": "00:1a:2b:3c:4d:5e", "192.168.1.6": "00:1a:2b:3c:4d:5f"}
        self.assertEqual(mitm.analyze(t, GW, GW_MAC), [])

    def test_router_mac_changed_is_the_real_warning(self):
        t = {GW: "de:ad:be:ef:00:01", "192.168.1.66": "de:ad:be:ef:00:01", "192.168.1.5": "00:1a:2b:3c:4d:5e"}
        f = mitm.analyze(t, GW, GW_MAC)
        self.assertEqual(ids(f), [("arp_spoof", "high")])  # one finding, not a second duplicate-MAC one
        self.assertEqual(f[0]["ips"], [GW, "192.168.1.66"])
        self.assertIn(GW_MAC, f[0]["text"])

    def test_multi_address_host_is_only_information(self):
        # a NAS / Docker host / VM host answering for two addresses: used to be a HIGH "attack"
        t = {GW: GW_MAC, "192.168.1.20": "00:11:22:33:44:55", "192.168.1.21": "00:11:22:33:44:55"}
        self.assertEqual(ids(mitm.analyze(t, GW, GW_MAC)), [("arp_shared_mac", "info")])

    def test_router_with_second_address_and_known_mac_is_information(self):
        t = {GW: GW_MAC, "192.168.1.2": GW_MAC}
        self.assertEqual(ids(mitm.analyze(t, GW, GW_MAC)), [("arp_shared_mac", "info")])

    def test_router_sharing_mac_without_a_record_is_worth_a_look(self):
        t = {GW: GW_MAC, "192.168.1.2": GW_MAC}
        self.assertEqual(ids(mitm.analyze(t, GW, None)), [("arp_shared_gateway", "medium")])

    def test_no_record_and_no_duplicates_is_quiet(self):
        self.assertEqual(mitm.analyze({GW: GW_MAC}, GW, None), [])

    def test_broadcast_and_multicast_ignored(self):
        t = {"192.168.1.255": "ff:ff:ff:ff:ff:ff", "192.168.1.254": "ff:ff:ff:ff:ff:ff",
             "224.0.0.251": "01:00:5e:00:00:fb", "224.0.0.252": "01:00:5e:00:00:fc"}
        self.assertEqual(mitm.analyze(t, GW, GW_MAC), [])

    def test_unpadded_recorded_mac_still_matches(self):
        t = {GW: "00:1a:2b:3c:4d:5e"}
        self.assertEqual(mitm.analyze(t, GW, "0:1a:2b:3c:4d:5e"), [])


if __name__ == "__main__":
    unittest.main()
