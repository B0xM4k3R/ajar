"""WiFi analysis: channel picks, findings, and identifying networks."""
import unittest

import helpers  # sets up the import path and a throwaway database
from helpers import IW, NETSH, ap
from aj import wifi_scan as aj_wifi_scan
from aj import wifi_analyze as aj_wifi_analyze


class Identify(unittest.TestCase):
    def nets(self, aps, mine=()):
        r = aj_wifi_analyze.analyze({"scanned": 0, "source": "test", "aps": aps}, list(mine), [])
        return r, {n["ssid"] or n["key"]: n for n in r["nets"]}

    def test_kinds(self):
        aps = [ap("DIRECT-6D-HP ENVY Photo 7100", "2.4", 2, -77), ap("xfinitywifi", "5", 36, -89, label="open"),
               ap("Dana's iPhone", "2.4", 6, -70), ap("HP-Setup>4a-OfficeJet 3830", "2.4", 1, -60, label="open"),
               ap("ESP_3A1F22", "2.4", 1, -75, label="open"), ap("4162 Sydney", "2.4", 10, -78)]
        r, n = self.nets(aps)
        self.assertEqual(n["DIRECT-6D-HP ENVY Photo 7100"]["kind"], "direct")
        self.assertEqual(n["DIRECT-6D-HP ENVY Photo 7100"]["device"], "HP ENVY Photo 7100")
        self.assertEqual(n["xfinitywifi"]["kind"], "public")
        self.assertEqual(n["Dana's iPhone"]["kind"], "phone")
        self.assertEqual(n["HP-Setup>4a-OfficeJet 3830"]["kind"], "setup")
        self.assertEqual(n["ESP_3A1F22"]["kind"], "setup")
        self.assertIsNone(n["4162 Sydney"]["kind"])
        self.assertEqual(r["around"], {"direct": 1, "public": 1, "phone": 1, "setup": 2})
        self.assertEqual(r["weak_nearby"], 2)  # the open setup networks; the public hotspot is explained instead

    def test_hidden_mesh_link_is_yours(self):
        aps = [ap("Home", "5", 52, -65, in_use=True, bssid="a4:2b:b0:11:22:34"),
               ap("Home", "5", 100, -70, bssid="a4:2b:b0:11:22:35"),
               ap("", "5", 100, -69, bssid="a6:2b:b0:11:22:36"),
               ap("Sydney", "5", 153, -80, bssid="10:20:30:40:50:60"),
               ap("", "5", 157, -89, bssid="12:20:30:40:50:61")]
        r, n = self.nets(aps)
        hid = [x for x in r["nets"] if not x["ssid"]]
        mesh = next(x for x in hid if x["aps"][0]["ch"] == 100)
        nb = next(x for x in hid if x["aps"][0]["ch"] == 157)
        self.assertEqual((mesh["kind"], mesh["related"]), ("backhaul", "Home"))
        self.assertEqual((nb["kind"], nb["related"]), ("hidden", "Sydney"))
        self.assertEqual(r["nets"][1]["key"], mesh["key"])  # listed right after yours
        b = r["bands"][0]
        self.assertEqual(b["networks"], 2)  # Sydney and its hidden twin, not your mesh link

    def test_generation(self):
        aps = aj_wifi_scan.parse_netsh(NETSH)
        self.assertEqual([aj_wifi_analyze.wifi_gen(a) for a in aps], ["WiFi 6", "WiFi 6", "WiFi 4", ""])
        iw = aj_wifi_scan.parse_iw(IW.replace("\tHT operation:", "\tHE capabilities:\n\tHT operation:", 1))
        self.assertEqual(aj_wifi_analyze.wifi_gen(iw[0]), "WiFi 6")
        a = ap("x", "6", 37, -60)
        a["info"]["radio"] = "802.11ax"
        self.assertEqual(aj_wifi_analyze.wifi_gen(a), "WiFi 6E")


class Analysis(unittest.TestCase):
    def run_analyze(self, aps, mine=()):
        return aj_wifi_analyze.analyze({"scanned": 0, "source": "test", "aps": aps}, list(mine), [])

    def test_spans(self):
        self.assertEqual(aj_wifi_analyze.span(ap("x", "5", 44, -60, 80)), (36, 48))
        self.assertEqual(aj_wifi_analyze.span(ap("x", "5", 104, -60, 160)), (100, 128))
        self.assertEqual(aj_wifi_analyze.span(ap("x", "5", 157, -60, 40)), (157, 161))

    def test_best_24_channel(self):
        aps = [ap("Home", "2.4", 6, -45, in_use=True),
               ap("A", "2.4", 6, -50), ap("B", "2.4", 6, -55), ap("C", "2.4", 7, -60),
               ap("D", "2.4", 11, -65), ap("E", "2.4", 1, -88)]
        r = self.run_analyze(aps)
        b = r["bands"][0]
        self.assertEqual(b["best"]["label"], "1")
        self.assertEqual(b["current"]["label"], "6")
        self.assertTrue(b["suggest"])
        self.assertEqual(r["conn"]["ssid"], "Home")
        self.assertTrue(r["conn"]["mine"])

    def test_no_suggestion_when_already_best(self):
        aps = [ap("Home", "2.4", 1, -45, in_use=True), ap("A", "2.4", 6, -50), ap("B", "2.4", 11, -60)]
        b = self.run_analyze(aps)["bands"][0]
        self.assertEqual(b["best"]["label"], "1")
        self.assertFalse(b["suggest"])

    def test_far_weak_neighbor_is_not_worth_a_move(self):
        aps = [ap("Home", "2.4", 6, -58, in_use=True), ap("A", "2.4", 10, -77), ap("B", "2.4", 11, -84)]
        b = self.run_analyze(aps)["bands"][0]
        self.assertFalse(b["suggest"])
        self.assertEqual(b["current"]["count"], 0)

    def test_faint_signals_do_not_flip_the_pick(self):
        base = [ap("Home", "5", 52, -65, None, in_use=True), ap("Home", "5", 100, -70, None)]
        one = self.run_analyze(base + [ap("xfinitywifi", "5", 36, -89, label="open")])["bands"][0]
        two = self.run_analyze(base + [ap("Sydney", "5", 153, -86)])["bands"][0]
        self.assertEqual(one["best"]["label"], "36-48")
        self.assertEqual(two["best"]["label"], "36-48")

    def test_keeps_current_when_equally_quiet(self):
        aps = [ap("Home", "2.4", 6, -58, in_use=True), ap("A", "2.4", 1, -88)]
        b = self.run_analyze(aps)["bands"][0]
        self.assertEqual(b["best"]["label"], "6")
        self.assertFalse(b["suggest"])

    def test_5ghz_prefers_quiet_non_dfs(self):
        aps = [ap("Home", "5", 36, -50, 80, in_use=True), ap("A", "5", 40, -55, 80), ap("B", "5", 44, -60, 80)]
        b = self.run_analyze(aps)["bands"][0]
        self.assertEqual(b["width"], 80)
        self.assertEqual(b["best"]["label"], "149-161")
        self.assertTrue(b["suggest"])

    def test_5ghz_avoids_dfs_unless_much_quieter(self):
        aps = [ap("Home", "5", 36, -50, 80, in_use=True), ap("A", "5", 149, -80, 80)]
        b = self.run_analyze(aps)["bands"][0]
        self.assertEqual(b["best"]["label"], "36-48")  # quiet normal block beats empty DFS block
        aps = [ap("Home", "5", 36, -50, 80, in_use=True), ap("A", "5", 40, -50, 80), ap("B", "5", 153, -55, 80)]
        b = self.run_analyze(aps)["bands"][0]
        self.assertTrue(b["best"]["dfs"])  # both normal blocks are busy, so DFS wins

    def test_6ghz_wpa3_is_not_a_mismatch(self):
        aps = [ap("Home", "2.4", 1, -50, in_use=True), ap("Home", "5", 36, -55, 80),
               ap("Home", "6", 37, -60, 160, label="wpa3")]
        f = self.run_analyze(aps)["findings"]
        self.assertFalse(any("name uses" in x["text"] for x in f))
        self.assertTrue(any("WPA2 is fine" in x["text"] for x in f))

    def test_weaker_band_flagged_stronger_not(self):
        aps = [ap("Home", "2.4", 1, -50, in_use=True), ap("Home", "5", 36, -55, 80, label="wpa3"),
               ap("Home", "5", 149, -60, 80, label="wpa3")]
        f = self.run_analyze(aps)["findings"]
        self.assertTrue(any("name uses WPA2 instead of WPA2/WPA3" in x["text"] for x in f))
        aps = [ap("Home", "2.4", 1, -50, in_use=True), ap("Home", "2.4", 6, -60),
               ap("Home", "5", 36, -55, 80, label="wpa3")]
        f = self.run_analyze(aps)["findings"]
        self.assertFalse(any("name uses" in x["text"] for x in f))

    def test_findings(self):
        aps = [ap("Home", "2.4", 3, -80, 40, label="open", in_use=True),
               ap("Home", "5", 36, -60, 80, label="open")]
        f = self.run_analyze(aps)["findings"]
        texts = " ".join(x["text"] for x in f)
        self.assertEqual(f[0]["level"], "high")
        self.assertIn("no password", texts)
        self.assertIn("channel 3", texts)
        self.assertIn("40 MHz", texts)
        self.assertIn("weak", texts)

    def test_evil_twin(self):
        aps = [ap("Home", "5", 36, -50, 80, label="wpa3", in_use=True),
               ap("Home", "2.4", 6, -55, label="wpa3"),
               ap("Home", "2.4", 11, -40, label="open", bssid="de:ad:be:ef:00:01")]
        f = self.run_analyze(aps)["findings"]
        self.assertTrue(any(x["level"] == "high" and "copy of your network" in x["text"] for x in f))

    def test_mine_marking_and_neighbors(self):
        aps = [ap("Home", "2.4", 1, -50), ap("Cafe", "2.4", 6, -70, label="open")]
        r = self.run_analyze(aps)
        self.assertFalse(r["mine_known"])
        self.assertEqual(r["findings"], [])
        r = self.run_analyze(aps, mine=["Home"])
        self.assertTrue(r["nets"][0]["mine"])
        self.assertEqual(r["weak_nearby"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
