"""Separate history per network, and the Changes timeline."""
import os
import sqlite3
import tempfile
import time
import unittest

import helpers  # sets up the import path and a throwaway database
from helpers import ap
from aj import audit as aj_audit
from aj import config as aj_config
from aj import db as aj_db
from aj import discovery as aj_discovery
from aj import events as aj_events
from aj import networks as aj_networks
from aj import score as aj_score
from aj import wifi_analyze as aj_wifi

HOME_GW = "a4:2b:b0:00:00:01"
HOME = [(HOME_GW, "192.168.1.254", "dsldevice", "Humax", False),
        ("5c:47:5e:2a:16:da", "192.168.1.65", "Ring-2a16da", "Ring", False),
        ("78:1c:3c:e9:7c:88", "192.168.1.93", "Litter-Robot4", "Espressif", False),
        ("d0:c2:4e:df:e4:c0", "192.168.1.68", None, "Samsung", False),
        ("c8:5e:a9:5d:94:f4", "192.168.1.80", "B0x", "This device", True)]
AWAY = [("10:20:30:40:50:01", "192.168.0.1", None, "Netgear", False),
        ("10:20:30:40:50:22", "192.168.0.22", None, "Apple", False),
        ("c8:5e:a9:5d:94:f4", "192.168.0.80", "B0x", "This device", True)]


class Fresh(unittest.TestCase):
    """Each test gets its own empty database and a fresh session."""
    def setUp(self):
        self.saved_db = aj_config.DB
        aj_config.DB = os.path.join(tempfile.mkdtemp(), "t.db")
        aj_db.init_db()
        aj_config.state.pop("net", None)
        aj_config.wifi["raw"] = None

    def tearDown(self):
        aj_config.DB = self.saved_db
        aj_config.state.pop("net", None)

    def scan(self, found, gw, subnet, now=None):
        net, baseline = aj_networks.resolve(found, gw, subnet, now=now)
        aj_discovery.save(found, gw, net, baseline, now=now)
        return net, baseline

    def events(self, net, presence=True):
        return [(e["kind"], e["level"]) for e in reversed(aj_events.recent(net, presence=presence))]

    def devices(self, net):
        c = aj_db.db()
        rows = {r["mac"]: dict(r) for r in c.execute("SELECT * FROM devices WHERE net=?", (net,))}
        c.close()
        return rows


class Networks(Fresh):
    def test_first_scan_is_a_quiet_baseline(self):
        net, baseline = self.scan(HOME, "192.168.1.254", "192.168.1.0/24")
        self.assertTrue(baseline)
        self.assertEqual(self.events(net), [("first_scan", "info")])
        self.assertEqual(len(self.devices(net)), 5)

    def test_taking_it_somewhere_else_keeps_history_apart(self):
        home, _ = self.scan(HOME, "192.168.1.254", "192.168.1.0/24")
        away, baseline = self.scan(AWAY, "192.168.0.1", "192.168.0.0/24")
        self.assertNotEqual(home, away)
        self.assertTrue(baseline)
        self.assertEqual(len(self.devices(home)), 5)
        self.assertEqual(len(self.devices(away)), 3)
        self.assertNotIn(("new_device", "medium"), self.events(away))  # its devices aren't "new" to you
        back, baseline = self.scan(HOME, "192.168.1.254", "192.168.1.0/24")
        self.assertEqual((back, baseline), (home, False))
        self.assertEqual(aj_networks.current_net(), home)

    def test_router_replaced_or_impersonated_keeps_history(self):
        home, _ = self.scan(HOME, "192.168.1.254", "192.168.1.0/24")
        swapped = [("de:ad:be:ef:00:01",) + HOME[0][1:]] + HOME[1:]
        net, baseline = self.scan(swapped, "192.168.1.254", "192.168.1.0/24")
        self.assertEqual((net, baseline), (home, False))
        changed = [e for e in aj_events.recent(home) if e["kind"] == "router_changed"]
        self.assertEqual(changed[0]["level"], "high")
        self.assertIn("de:ad:be:ef:00:01", changed[0]["text"])

    def test_same_address_range_elsewhere_is_a_different_network(self):
        home, _ = self.scan(HOME, "192.168.1.254", "192.168.1.0/24")
        other = [("aa:aa:aa:aa:aa:01", "192.168.1.254", None, "Arris", False),
                 ("aa:aa:aa:aa:aa:02", "192.168.1.20", None, "Apple", False)]
        net, baseline = self.scan(other, "192.168.1.254", "192.168.1.0/24")
        self.assertNotEqual(net, home)
        self.assertTrue(baseline)

    def test_rename(self):
        home, _ = self.scan(HOME, "192.168.1.254", "192.168.1.0/24")
        self.assertTrue(aj_networks.rename_network(home, "  Home  "))
        self.assertFalse(aj_networks.rename_network(home, "   "))
        self.assertEqual(aj_networks.all_networks()[0]["name"], "Home")


class Upgrade(Fresh):
    def old_database(self):
        """A database from before networks existed: devices keyed by MAC, settings global."""
        c = sqlite3.connect(aj_config.DB)
        c.execute("DROP TABLE devices")
        c.execute("""CREATE TABLE devices (mac TEXT PRIMARY KEY, ip TEXT, hostname TEXT, vendor TEXT, kind TEXT,
                     first_seen REAL, last_seen REAL, approved INTEGER DEFAULT 0, online INTEGER DEFAULT 0,
                     name TEXT, audit TEXT)""")
        for mac, ip, host, vendor, _ in HOME:
            c.execute("INSERT INTO devices (mac, ip, hostname, vendor, approved, name) VALUES (?,?,?,?,1,?)",
                      (mac, ip, host, vendor, "Front door" if host == "Ring-2a16da" else None))
        c.execute("INSERT INTO settings VALUES ('my_ssids', ?)", ('["No Internet Connection"]',))
        c.commit()
        c.close()
        aj_db.init_db()

    def test_home_adopts_existing_history(self):
        self.old_database()
        net, baseline = self.scan(HOME, "192.168.1.254", "192.168.1.0/24")
        self.assertFalse(baseline)
        devs = self.devices(net)
        self.assertEqual(devs["5c:47:5e:2a:16:da"]["name"], "Front door")  # your names survive
        self.assertTrue(all(d["approved"] for d in devs.values()))         # and your approvals
        self.assertEqual(aj_db.net_setting(net, "my_ssids"), ["No Internet Connection"])
        self.assertIsNone(aj_db.get_setting("my_ssids"))
        self.assertIn(("adopted", "info"), self.events(net))

    def test_first_scan_somewhere_else_does_not_steal_it(self):
        self.old_database()
        away, baseline = self.scan(AWAY, "192.168.0.1", "192.168.0.0/24")
        self.assertTrue(baseline)
        self.assertEqual(len(self.devices(aj_db.LEGACY)), 5)  # still waiting for home
        home, baseline = self.scan(HOME, "192.168.1.254", "192.168.1.0/24")
        self.assertFalse(baseline)
        self.assertEqual(self.devices(home)["5c:47:5e:2a:16:da"]["name"], "Front door")


class DeviceChanges(Fresh):
    def test_new_device_leaving_returning_and_moving(self):
        t = time.time() - 7200
        home, _ = self.scan(HOME, "192.168.1.254", "192.168.1.0/24", now=t)
        newcomer = ("02:11:22:33:44:55", "192.168.1.150", None, None, False)
        self.scan(HOME + [newcomer], "192.168.1.254", "192.168.1.0/24", now=t + 60)
        self.scan(HOME[:2] + HOME[3:] + [newcomer], "192.168.1.254", "192.168.1.0/24", now=t + 120)  # robot leaves
        moved = [("78:1c:3c:e9:7c:88", "192.168.1.94", "Litter-Robot4", "Espressif", False)]
        self.scan(HOME[:2] + HOME[3:] + moved + [newcomer], "192.168.1.254", "192.168.1.0/24", now=t + 3600)
        kinds = self.events(home)
        self.assertEqual(kinds, [("first_scan", "info"), ("new_device", "medium"), ("gone", "presence"),
                                 ("back", "presence"), ("ip_changed", "info")])
        self.assertNotIn("presence", {lvl for _, lvl in self.events(home, presence=False)})
        joined = next(e for e in aj_events.recent(home) if e["kind"] == "new_device")["text"]
        self.assertIn("an unknown device (192.168.1.150, private address)", joined)

    def test_timeline_is_in_time_order(self):
        aj_events.record("home", "x", "info", "later", at=200)
        aj_events.record("home", "x", "info", "earlier", at=100)
        self.assertEqual([e["text"] for e in aj_events.recent("home")], ["later", "earlier"])


class ServiceChanges(unittest.TestCase):
    def ports(self, *ps, depth="common"):
        a = {"ports": [{"port": p, "name": str(p)} for p in ps], "shares": [], "nfs": [], "depth": depth}
        a["findings"] = aj_audit.assess(a)
        return a

    def test_first_check_is_baseline(self):
        self.assertEqual(aj_audit.audit_changes(None, self.ports(23), "Cam"), [])

    def test_problem_appears_and_is_fixed(self):
        ch = aj_audit.audit_changes(self.ports(80), self.ports(80, 23), "Garage camera")
        self.assertIn(("problem_new", "high"), [(k, l) for k, l, _ in ch])
        self.assertTrue(any("Garage camera: Telnet" in t for _, _, t in ch))
        ch = aj_audit.audit_changes(self.ports(80, 23), self.ports(80), "Garage camera")
        self.assertEqual([(k, l) for k, l, _ in ch], [("problem_fixed", "info"), ("ports_closed", "info")])

    def test_unusual_port_is_medium_expected_one_is_info(self):
        self.assertEqual(aj_audit.audit_changes(self.ports(80), self.ports(80, 31337), "TV")[0][:2],
                         ("ports_opened", "medium"))
        self.assertEqual(aj_audit.audit_changes(self.ports(80), self.ports(80, 443), "TV")[0][:2],
                         ("ports_opened", "info"))

    def test_first_deep_check_does_not_report_every_port_as_new(self):
        ch = aj_audit.audit_changes(self.ports(8001, 8080), self.ports(8001, 8080, 7678, 9197, depth="deep"), "TV")
        self.assertEqual(ch, [])


class WifiChanges(Fresh):
    def test_lookalike_appears_then_goes(self):
        mine = [ap("Home", "5", 36, -50, 80, label="wpa3", in_use=True, bssid="a4:2b:b0:11:22:34")]
        fake = ap("Home", "2.4", 11, -40, label="open", bssid="de:ad:be:ef:00:01")

        def run(aps):
            res = aj_wifi.analyze({"scanned": 0, "source": "t", "aps": aps}, ["Home"], [])
            return aj_wifi.wifi_changes("home", res)
        self.assertEqual(run(mine), [])                       # baseline
        new = run(mine + [fake])
        self.assertEqual(new[0][:2], ("wifi_problem_new", "high"))
        fake["dbm"] = -60
        self.assertEqual(run(mine + [fake]), [])              # same fake, weaker signal: not news
        self.assertEqual(run(mine)[0][:2], ("wifi_problem_fixed", "info"))


class ScoreChanges(Fresh):
    def test_score_drop_is_recorded_rise_too(self):
        clean = [helpers.dev("192.168.1.2")]
        wifi = aj_wifi.analyze({"scanned": 0, "source": "t", "aps": [ap("Home", "5", 36, -50, 80)]}, ["Home"], [])
        aj_score.security_report(clean, wifi, net="home")
        aj_score.security_report([helpers.dev("192.168.1.2", ports=[23])], wifi, net="home")
        aj_score.security_report(clean, wifi, net="home")
        ev = [(e["kind"], e["level"], e["text"]) for e in reversed(aj_events.recent("home"))]
        self.assertEqual([e[:2] for e in ev], [("score", "medium"), ("score", "info")])
        self.assertIn("fell from 100 to 85", ev[0][2])

    def test_partial_scores_are_not_compared(self):
        aj_score.security_report([dict(helpers.dev("192.168.1.2"), audit=None)], None, net="home")
        aj_score.security_report([helpers.dev("192.168.1.2", ports=[23])], None, net="home")
        self.assertEqual(aj_events.recent("home"), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
