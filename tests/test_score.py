"""The security score: points, fixes, checks, coverage and history."""
import unittest

import helpers  # sets up the import path and a throwaway database
from helpers import ap, dev
from aj import db as aj_db
from aj import audit as aj_audit
from aj import wifi_analyze as aj_wifi_analyze
from aj import score as aj_score


class Score(unittest.TestCase):
    def wifi(self, aps, mine=("Home",)):
        return aj_wifi_analyze.analyze({"scanned": 0, "source": "nmcli", "aps": aps}, list(mine), [])

    def setUp(self):
        aj_db.set_net_setting("home", "score_history", [])

    def test_clean_network_scores_100(self):
        r = aj_score.security_report([dev("192.168.1.2"), dev("192.168.1.3", ports=[443])],
                              self.wifi([ap("Home", "5", 36, -50, 80, label="wpa3")]))
        self.assertEqual((r["score"], r["grade"], r["partial"]), (100, "A", False))
        status = {c["label"]: c["status"] for c in r["checks"]}
        self.assertEqual(status["WPS is off"], "unknown")  # nmcli can't see WPS
        self.assertEqual(status["Telnet is off everywhere"], "pass")

    def test_points_and_order(self):
        r = aj_score.security_report([dev("192.168.1.2", ports=[23]), dev("192.168.1.3", ports=[3389])],
                              self.wifi([ap("Home", "2.4", 6, -50, label="open")]))
        self.assertEqual(r["score"], 100 - 30 - 15 - 6)
        self.assertEqual(r["grade"], "F")
        self.assertEqual([i["id"] for i in r["issues"]], ["wifi_open", "telnet", "rdp"])
        self.assertEqual(r["issues"][1]["title"], "Turn off Telnet on dev2")
        self.assertEqual(r["lost"], {"wifi": 30, "devices": 21, "internet": 0})

    def test_performance_tips_do_not_cost_points(self):
        r = aj_score.security_report([dev("192.168.1.2")], self.wifi([ap("Home", "2.4", 3, -80, 40, in_use=True)]))
        self.assertEqual(r["score"], 100)
        self.assertTrue(any("WPA2 is fine" in o for o in r["optional"]))

    def test_shares_name_the_share(self):
        r = aj_score.security_report([dev("192.168.1.9", ports=[445], shares=[("Photos", "read/write")])], None)
        self.assertEqual(r["issues"][0]["title"], "Lock the share 'Photos' on dev9")
        self.assertEqual(r["score"], 85)

    def test_unapproved_is_capped(self):
        devs = [dev(f"192.168.1.{i}", approved=0) for i in range(2, 12)]
        r = aj_score.security_report(devs, None)
        self.assertEqual(r["issues"][0]["points"], 12)
        self.assertIn("10 devices", r["issues"][0]["problem"])

    def test_sleeping_devices_still_count_old_ones_do_not(self):
        devs = [dev("192.168.1.2", ports=[23], online=0, seen_days_ago=2),
                dev("192.168.1.3", ports=[23], online=0, seen_days_ago=30)]
        r = aj_score.security_report(devs, None)
        self.assertEqual(len(r["issues"]), 1)

    def test_partial_and_unknown(self):
        r = aj_score.security_report([dict(dev("192.168.1.2"), audit=None)], None)
        self.assertTrue(r["partial"])
        self.assertTrue(r["unscored"])  # nothing checked yet: no score shown, not a fake 100
        self.assertEqual(len(r["missing"]), 2)
        device_only = {"Every device is approved", "Smart-home devices kept apart from computers"}
        self.assertTrue(all(c["status"] == "unknown" for c in r["checks"] if c["label"] not in device_only))

    def test_wifi_not_marked_mine_is_not_scored(self):
        r = aj_score.security_report([dev("192.168.1.2")], self.wifi([ap("Cafe", "2.4", 6, -60, label="open")], mine=()))
        self.assertEqual(r["score"], 100)
        self.assertIn("your WiFi network (tap This is mine on the WiFi tab)", r["missing"])

    def test_smart_home_findings(self):
        f = {x["id"]: x for x in aj_audit.assess({"ports": [{"port": p, "name": str(p)} for p in (2323, 5555, 1883, 9999, 31337, 443)]})}
        self.assertEqual(f["telnet"]["level"], "high")
        self.assertIn("2323", f["telnet"]["text"])
        self.assertEqual(f["adb"]["level"], "high")
        self.assertEqual((f["mqtt"]["level"], f["kasa"]["level"]), ("medium", "medium"))
        self.assertIn("31337", f["other_ports"]["text"])
        self.assertNotIn("443", f["other_ports"]["text"])

    def test_smart_home_shares_network_with_computers(self):
        ring = dict(dev("192.168.1.40"), kind="iot", name="Ring doorbell")
        litter = dict(dev("192.168.1.41"), kind="iot", name="Litter box")
        pc = dict(dev("192.168.1.10"), kind="personal")
        r = aj_score.security_report([ring, litter, pc], None)
        mixed = next(i for i in r["issues"] if i["id"] == "iot_mixed")
        self.assertEqual(mixed["points"], 6)
        self.assertIn("Ring doorbell, Litter box", mixed["problem"])
        self.assertTrue(any("two-step verification" in o for o in r["optional"]))
        r = aj_score.security_report([ring, litter], None)  # only smart devices here: nothing to separate them from
        self.assertFalse(any(i["id"] == "iot_mixed" for i in r["issues"]))

    def test_tvs_count_as_smart_home(self):
        tv = dict(dev("192.168.1.68", ports=[8001, 8080]), kind="personal", name="Samsung Living Room")
        tv["audit"]["info"] = {"model": "UN55AU8000FXZA", "size_in": 55}
        phone = dict(dev("192.168.1.101"), kind="personal", name="iPhone 16 Pro Max")
        r = aj_score.security_report([tv, phone], None)
        mixed = next(i for i in r["issues"] if i["id"] == "iot_mixed")
        self.assertIn("Samsung Living Room", mixed["problem"])
        self.assertTrue(aj_audit.is_tv(tv["audit"]))
        self.assertFalse(aj_audit.is_tv(phone["audit"]))

    def test_floor_and_history(self):
        devs = [dev(f"192.168.1.{i}", ports=[23, 21, 5900]) for i in range(2, 6)]
        r = aj_score.security_report(devs, None, net="home")
        self.assertEqual(r["score"], 0)
        self.assertTrue(all(i["points"] > 0 for i in r["issues"]))
        r2 = aj_score.security_report(devs[:1], None, net="home")
        self.assertEqual([h[1] for h in r2["history"]], [0, 100 - 15 - 6 - 8])
        self.assertEqual(aj_score.security_report(devs, None)["history"], [])  # no network: no history kept


if __name__ == "__main__":
    unittest.main(verbosity=2)
