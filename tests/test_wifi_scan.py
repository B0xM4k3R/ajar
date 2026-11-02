"""WiFi scanners: parsing nmcli, iw, netsh and system_profiler output."""
import unittest

import helpers  # sets up the import path and a throwaway database
from helpers import NMCLI, IW, NETSH, NETSH_IFACE, SP
from aj import wifi_scan as aj_wifi_scan


class Parsers(unittest.TestCase):
    def test_terse_split(self):
        self.assertEqual(aj_wifi_scan.split_terse(r"a\:b:c\\d:"), ["a:b", "c\\d", ""])

    def test_nmcli(self):
        aps = aj_wifi_scan.parse_nmcli(NMCLI, aj_wifi_scan.NMCLI_FIELDS)
        self.assertEqual(len(aps), 6)
        home = aps[0]
        self.assertEqual((home["bssid"], home["ssid"], home["band"], home["ch"], home["width"], home["in_use"]),
                         ("aa:bb:cc:00:00:01", "HomeNet", "2.4", 6, 20, True))
        self.assertEqual(home["dbm"], -61)
        self.assertEqual(aps[1]["sec"]["label"], "WPA2/WPA3")
        self.assertEqual(aps[1]["sec"]["grade"], "good")
        self.assertEqual(aps[2]["ssid"], "Neighbor:5G")
        self.assertEqual(aps[2]["sec"]["grade"], "weak")
        self.assertTrue(aps[3]["sec"]["open"])
        self.assertEqual(aps[4]["ssid"], "")

    def test_nmcli_without_bandwidth(self):
        text = "\n".join(l.rsplit(":", 1)[0] for l in NMCLI.strip().splitlines())
        aps = aj_wifi_scan.parse_nmcli(text, aj_wifi_scan.NMCLI_FIELDS[:-1])
        self.assertEqual(len(aps), 6)
        self.assertIsNone(aps[0]["width"])

    def test_iw(self):
        aps = aj_wifi_scan.parse_iw(IW)
        self.assertEqual(len(aps), 5)
        home, nb, free, old, six = aps
        self.assertTrue(home["in_use"])
        self.assertEqual((home["ch"], home["width"], home["sec2"], home["dbm"]), (6, 40, 10, -48))
        self.assertEqual(home["sec"]["label"], "WPA2/WPA3")
        self.assertTrue(home["sec"]["wps"])
        self.assertEqual(home["info"]["model"], "RAX40")
        self.assertEqual((nb["band"], nb["ch"], nb["width"]), ("5", 149, 80))
        self.assertEqual(nb["sec"]["grade"], "weak")
        self.assertTrue(nb["sec"]["tkip"])
        self.assertTrue(free["sec"]["open"])
        self.assertTrue(old["sec"]["wep"])
        self.assertEqual((six["band"], six["ch"], six["sec"]["label"]), ("6", 33, "WPA3"))

    def test_netsh(self):
        aps = aj_wifi_scan.parse_netsh(NETSH)
        self.assertEqual(len(aps), 4)
        self.assertEqual((aps[0]["band"], aps[0]["ch"], aps[0]["dbm"]), ("5", 36, -54))
        self.assertEqual(aps[1]["band"], "2.4")
        self.assertEqual(aps[2]["band"], "2.4")  # no Band line: worked out from the channel
        self.assertEqual(aps[2]["sec"]["grade"], "bad")
        self.assertEqual((aps[3]["band"], aps[3]["sec"]["label"]), ("6", "Open, no password"))
        me = aj_wifi_scan.parse_netsh_iface(NETSH_IFACE)
        self.assertEqual(me["BSSID"], "aa:bb:cc:00:00:02")
        self.assertEqual(me["State"], "connected")

    def test_system_profiler(self):
        aps = aj_wifi_scan.parse_system_profiler(SP)
        self.assertEqual(len(aps), 3)
        self.assertTrue(aps[0]["in_use"])
        self.assertEqual((aps[0]["band"], aps[0]["ch"], aps[0]["width"], aps[0]["dbm"]), ("5", 36, 80, -52))
        self.assertEqual(aps[0]["sec"]["label"], "WPA2/WPA3")
        self.assertEqual(aps[1]["sec"]["grade"], "weak")
        self.assertEqual((aps[2]["band"], aps[2]["dbm"]), ("2.4", -100))
        self.assertTrue(aps[2]["sec"]["open"])


class WindowsConnected(unittest.TestCase):
    def test_ap_bssid_label(self):
        aps = aj_wifi_scan.parse_netsh(NETSH)
        aj_wifi_scan.mark_connected_windows(aps, aj_wifi_scan.parse_netsh_iface(NETSH_IFACE.replace("    BSSID  ", " AP BSSID  ")))
        self.assertEqual([a["bssid"] for a in aps if a["in_use"]], ["aa:bb:cc:00:00:02"])
        self.assertEqual(aps[0]["info"]["rate"], "1201 Mbps")

    def test_fallback_to_name_and_channel(self):
        aps = aj_wifi_scan.parse_netsh(NETSH)
        me = aj_wifi_scan.parse_netsh_iface(NETSH_IFACE.replace("aa:bb:cc:00:00:02", "aa:bb:cc:00:00:99"))
        aj_wifi_scan.mark_connected_windows(aps, me)
        self.assertEqual([a["ch"] for a in aps if a["in_use"]], [36])

    def test_not_connected(self):
        aps = aj_wifi_scan.parse_netsh(NETSH)
        aj_wifi_scan.mark_connected_windows(aps, {"State": "disconnected"})
        self.assertFalse(any(a["in_use"] for a in aps))

    def test_scan_trigger_is_safe_off_windows(self):
        self.assertFalse(aj_wifi_scan.windows_trigger_scan(wait=0))


if __name__ == "__main__":
    unittest.main(verbosity=2)
