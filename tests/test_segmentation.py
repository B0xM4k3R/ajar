import unittest
import xml.etree.ElementTree as ET
from unittest import mock

import helpers  # noqa: F401
from aj import score, segmentation, subnets
from aj.db import db, net_setting, set_net_setting

NET = "nseg"


def hosts_xml(ips):
    return ET.fromstring("<nmaprun>" + "".join(
        f"<host><status state='up'/><address addr='{ip}' addrtype='ipv4'/></host>" for ip in ips) + "</nmaprun>")


class Subnets(unittest.TestCase):
    def test_accepts_private_ranges_and_normalizes(self):
        kept, rejected = subnets.clean(["192.168.1.7/24", "10.0.5.0/25"], "192.168.50.0/24")
        self.assertEqual(kept, ["192.168.1.0/24", "10.0.5.0/25"])
        self.assertEqual(rejected, [])

    def test_text_box_input_and_junk(self):
        kept, rejected = subnets.clean("192.168.1.0/24, 10.1.0.0/24 nonsense", None)
        self.assertEqual(kept, ["192.168.1.0/24", "10.1.0.0/24"])
        self.assertEqual([r[0] for r in rejected], ["nonsense"])

    def test_refuses_public_huge_loopback_ipv6_and_own_network(self):
        cases = {"8.8.8.0/24": "private", "10.0.0.0/8": "too large", "192.168.0.0/16": "too large", "127.0.0.0/24": "private",
                 "169.254.0.0/24": "private", "2001:db8::/64": "IPv4", "192.168.50.0/24": "already", "0.0.0.0/0": "private"}
        for text, why in cases.items():
            kept, rejected = subnets.clean([text], "192.168.50.0/24")
            self.assertEqual(kept, [], text)
            self.assertIn(why, rejected[0][1], text)

    def test_only_the_three_private_ranges_count(self):
        """Not 0.0.0.0/x, 100.64/10, 192.0.0.x or 172.32/12: ipaddress's is_private disagrees about these
        between Python versions, and 0.0.0.0/24 used to be accepted as 'private'."""
        for ok in ("10.9.8.0/24", "172.16.0.0/24", "172.31.255.0/24", "192.168.200.0/24"):
            self.assertEqual(subnets.clean([ok], None)[0], [ok], ok)
        for bad in ("0.0.0.0/24", "100.64.0.0/24", "172.15.255.0/24", "172.32.0.0/24", "192.0.0.0/24", "192.169.0.0/24",
                    "198.51.100.0/24", "224.0.0.0/24", "255.255.255.0/24"):
            kept, rejected = subnets.clean([bad], None)
            self.assertEqual(kept, [], bad)
            self.assertIn("private", rejected[0][1], bad)

    def test_limit_overlap_and_duplicates(self):
        kept, rejected = subnets.clean([f"10.0.{i}.0/24" for i in range(6)], None, limit=3)
        self.assertEqual(len(kept), 3)
        self.assertEqual(len(rejected), 3)
        kept, rejected = subnets.clean(["10.0.0.0/24", "10.0.0.0/24", "10.0.0.128/25"], None)
        self.assertEqual(kept, ["10.0.0.0/24"])
        self.assertEqual(len(rejected), 2)


class Evaluate(unittest.TestCase):
    def test_hosts_answering_is_a_high_finding(self):
        f = segmentation.evaluate(["192.168.1.0/24"], {"192.168.1.0/24": ["192.168.1.1", "192.168.1.20", "192.168.1.31"]})
        self.assertEqual([(x["id"], x["level"]) for x in f], [("no_isolation", "high")])
        self.assertEqual(f[0]["ips"], ["192.168.1.20", "192.168.1.31"])  # the router isn't counted as a breach
        self.assertIn("2 devices", f[0]["text"])

    def test_only_the_router_answering_is_fine(self):
        f = segmentation.evaluate(["192.168.1.0/24"], {"192.168.1.0/24": ["192.168.1.1"]})
        self.assertEqual([(x["id"], x["level"]) for x in f], [("isolation_router_only", "info")])

    def test_nothing_answering_is_clean(self):
        self.assertEqual(segmentation.evaluate(["192.168.1.0/24"], {"192.168.1.0/24": []}), [])


class Run(unittest.TestCase):
    def setUp(self):
        c = db(); c.execute("DELETE FROM events"); c.commit(); c.close()
        set_net_setting(NET, "segmentation", None)
        set_net_setting(NET, "segmentation_targets", ["192.168.1.0/24"])
        self.calls = []

    def nmap(self, ips):
        def run(args, timeout=0):
            self.calls.append(args)
            return hosts_xml(ips)
        return run

    def events(self):
        c = db(); rows = [dict(r) for r in c.execute("SELECT kind, level FROM events WHERE net=? ORDER BY id", (NET,))]; c.close()
        return rows

    def test_nothing_configured_means_nothing_probed(self):
        set_net_setting(NET, "segmentation_targets", [])
        self.assertIsNone(segmentation.run(NET, "192.168.50.0/24", nmap=self.nmap([])))
        self.assertEqual(self.calls, [])

    def test_probes_only_the_listed_networks_and_stores_the_result(self):
        r = segmentation.run(NET, "192.168.50.0/24", nmap=self.nmap(["192.168.1.20", "192.168.1.1"]), now=1e9)
        args = self.calls[0]
        self.assertIn("192.168.1.0/24", args)
        self.assertEqual([a for a in args if "/" in a], ["192.168.1.0/24"])
        self.assertNotIn("-sS", args)  # a plain host sweep, no port scanning
        self.assertEqual(r["reachable"], {"192.168.1.0/24": ["192.168.1.20", "192.168.1.1"]})
        self.assertEqual(net_setting(NET, "segmentation")["at"], 1e9)

    def test_events_on_breach_and_when_fixed_but_not_repeated(self):
        run = lambda ips: segmentation.run(NET, "192.168.50.0/24", nmap=self.nmap(ips))
        run(["192.168.1.20"]); run(["192.168.1.20"])
        self.assertEqual(self.events(), [{"kind": "isolation_failed", "level": "high"}])  # once, not every scan
        run([])
        self.assertEqual(self.events()[-1], {"kind": "problem_fixed", "level": "info"})

    def test_a_target_equal_to_our_own_network_is_ignored(self):
        self.assertIsNone(segmentation.run(NET, "192.168.1.0/24", nmap=self.nmap(["192.168.1.9"])))
        self.assertEqual(self.calls, [])


class InTheScore(unittest.TestCase):
    DEV = {"mac": "aa:00:00:00:00:01", "ip": "192.168.50.5", "online": 1, "approved": 1, "kind": "personal",
           "audit": {"ports": [], "shares": [], "info": {}}}

    def test_breach_costs_points_and_fails_its_check(self):
        seg = {"at": 1, "findings": segmentation.evaluate(["x"], {"x": ["192.168.1.20"]})}
        r = score.security_report([dict(self.DEV)], None, segmentation=seg)
        self.assertEqual(r["score"], 100 - score.SCORE_POINTS["no_isolation"])
        chk = next(c for c in r["checks"] if "other networks" in c["label"])
        self.assertEqual(chk["status"], "fail")

    def test_clean_result_passes_and_missing_result_is_unknown(self):
        clean = score.security_report([dict(self.DEV)], None, segmentation={"at": 1, "findings": []})
        none = score.security_report([dict(self.DEV)], None)
        label = lambda r: next(c["status"] for c in r["checks"] if "other networks" in c["label"])
        self.assertEqual((label(clean), label(none)), ("pass", "unknown"))

    def test_router_only_is_an_advisory_not_a_problem(self):
        seg = {"at": 1, "findings": segmentation.evaluate(["x"], {"x": ["192.168.1.1"]})}
        r = score.security_report([dict(self.DEV)], None, segmentation=seg)
        self.assertEqual(r["score"], 100)
        self.assertTrue(any("router answered" in t for t in r["optional"]))


if __name__ == "__main__":
    unittest.main()


class ScanCycleHook(unittest.TestCase):
    """The isolation check runs at the end of a deep scan, only when networks are listed."""

    def setUp(self):
        from aj import config, jobs
        self.jobs, self.config = jobs, config
        self.saved = {k: config.state.get(k) for k in ("net", "steps", "step", "subnet", "audit_note", "error", "gateway")}
        config.state.update(net=NET, steps=["a", "b"], subnet="192.168.50.0/24", audit_note=None, error=None, gateway="192.168.50.1")
        self.ran = []
        self.patches = [mock.patch.object(jobs, "scan", lambda: None), mock.patch.object(jobs, "file_wifi", lambda r: None),
                        mock.patch.object(jobs.netcheck, "record_health", lambda *a: None),
                        mock.patch.object(jobs, "audit", lambda full=False: {}),
                        mock.patch.object(jobs.exposure, "run", lambda *a: None),
                        mock.patch.object(jobs.alerts, "dispatch", lambda *a: None),
                        mock.patch.object(jobs, "net_name", lambda n: "Home")]
        [p.start() for p in self.patches]

    def tearDown(self):
        [p.stop() for p in self.patches]
        self.config.state.update(self.saved)

    def test_runs_after_the_audit_when_targets_are_listed(self):
        set_net_setting(NET, "segmentation_targets", ["192.168.1.0/24"])
        with mock.patch.object(self.jobs.segmentation, "run", lambda net, subnet: self.ran.append((net, subnet))):
            self.jobs.scan_cycle(deep=True)
        self.assertEqual(self.ran, [(NET, "192.168.50.0/24")])
        self.assertEqual(self.config.state["steps"][-1], "Check isolation from other networks")
        self.assertEqual(self.config.state["step"], 2)
        self.assertIsNone(self.config.state["error"])

    def test_not_run_when_nothing_is_listed_or_on_a_quick_scan(self):
        set_net_setting(NET, "segmentation_targets", [])
        with mock.patch.object(self.jobs.segmentation, "run", lambda *a: self.ran.append(a)):
            self.jobs.scan_cycle(deep=True)
            set_net_setting(NET, "segmentation_targets", ["192.168.1.0/24"])
            self.jobs.scan_cycle(deep=False)
        self.assertEqual(self.ran, [])
        self.assertEqual(self.config.state["steps"], ["a", "b"])

    def test_a_failing_check_is_noted_and_does_not_break_the_scan(self):
        set_net_setting(NET, "segmentation_targets", ["192.168.1.0/24"])
        def boom(*a): raise RuntimeError("nmap exploded")
        with mock.patch.object(self.jobs.segmentation, "run", boom):
            self.jobs.scan_cycle(deep=True)
        self.assertIn("Isolation check: nmap exploded", self.config.state["audit_note"])
        self.assertIsNone(self.config.state["error"])
