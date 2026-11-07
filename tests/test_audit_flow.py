"""audit() end to end, with the scanners faked: CVE results are cached for a week, probing runs in
parallel, a failing device doesn't stop the others, and Stop is honored."""
import json
import threading
import time
import unittest
import xml.etree.ElementTree as ET
from unittest import mock

import helpers  # noqa: F401
from aj import audit as aj_audit
from aj import config
from aj.db import db

NET = "ntest"
OWN = "192.168.1.2"
DEVICES = {"192.168.1.5": "aa:00:00:00:00:05", "192.168.1.6": "aa:00:00:00:00:06", "192.168.1.7": "aa:00:00:00:00:07"}
OPEN = {"192.168.1.5": [80], "192.168.1.6": [22], "192.168.1.7": [80]}

VULNERS = """<table key="cpe:/a:apache:http_server"><table><elem key="id">CVE-2021-41773</elem>
<elem key="type">cve</elem><elem key="cvss">9.8</elem></table></table>"""


def host_xml(ip, ports, vulners=False):
    ps = "".join(f'<port protocol="tcp" portid="{p}"><state state="open"/><service name="x"/>'
                 + (f'<script id="vulners" output="x">{VULNERS}</script>' if vulners and ip == "192.168.1.5" else "")
                 + "</port>" for p in ports)
    return f'<host><status state="up"/><address addr="{ip}" addrtype="ipv4"/><ports>{ps}</ports></host>'


class Flow(unittest.TestCase):
    def setUp(self):
        c = db()
        c.execute("DELETE FROM devices"); c.execute("DELETE FROM events")
        for ip, mac in DEVICES.items():
            c.execute("""INSERT INTO devices (net, mac, ip, vendor, kind, first_seen, last_seen, approved, online)
                         VALUES (?,?,?,?,?,?,?,1,1)""", (NET, mac, ip, "Apple", "personal", 1, time.time()))
        c.commit(); c.close()
        keys = ("net", "own_ip", "stop_requested", "gateway", "subnet", "audit_note", "phase")
        self.saved_state = {k: config.state.get(k) for k in keys}
        config.state.update(net=NET, own_ip=OWN, stop_requested=False, gateway="192.168.1.1", subnet="192.168.1.0/24")
        self.calls = []          # every nmap run: its argument list
        self.vulners_works = True
        self.probe_delay = 0.0
        self.probe_fail = set()
        self.in_probe, self.max_in_probe = 0, 0
        self.lock = threading.Lock()

        def nmap(args, timeout=180):
            self.calls.append(list(args))
            targets = [a for a in args if a.startswith("192.168.")]
            if "vulners" in args:
                return ET.fromstring("<nmaprun>" + "".join(host_xml(ip, OPEN[ip], self.vulners_works) for ip in targets) + "</nmaprun>")
            if "--open" in args:
                return ET.fromstring("<nmaprun>" + "".join(host_xml(ip, OPEN[ip]) for ip in targets) + "</nmaprun>")
            return ET.fromstring("<nmaprun></nmaprun>")

        def probe(ip, ports, try_snmp=False):
            with self.lock:
                self.in_probe += 1; self.max_in_probe = max(self.max_in_probe, self.in_probe)
            try:
                time.sleep(self.probe_delay)
                if ip in self.probe_fail:
                    raise RuntimeError("device exploded")
                return {80: {"http": {"title": "Admin", "server": "x"}}}
            finally:
                with self.lock:
                    self.in_probe -= 1

        self.patches = [
            mock.patch.object(aj_audit, "run_nmap", nmap),
            mock.patch.object(aj_audit, "is_admin", lambda: False),
            mock.patch.object(aj_audit, "ssdp_scan", lambda own: {}),
            mock.patch.object(aj_audit, "mdns_scan", lambda own, ips: {}),
            mock.patch.object(aj_audit.netcheck, "run", lambda *a, **k: None),
            mock.patch.object(aj_audit.kev, "get_ids", lambda *a, **k: set()),  # never touch the internet in tests
            mock.patch.object(aj_audit.mitmlib, "check_arp", lambda *a, **k: []),
            mock.patch.object(aj_audit.probelib, "probe_device", probe),
            mock.patch.object(aj_audit.weakauth, "check_web", lambda ip, ports: {"auth": "basic", "plain": True}),
            mock.patch.object(aj_audit.weakauth, "probe_rtsp", lambda ip, port: None),
        ]
        [p.start() for p in self.patches]

    def tearDown(self):
        [p.stop() for p in self.patches]
        config.state.update(self.saved_state)  # don't leak "stop requested" etc. into other tests

    def audits(self):
        c = db()
        out = {r["ip"]: json.loads(r["audit"]) for r in c.execute("SELECT ip, audit FROM devices WHERE net=?", (NET,))}
        c.close()
        return out

    def vulners_runs(self):
        return [c for c in self.calls if "vulners" in c]

    def test_first_audit_checks_every_open_port_and_stamps_hosts(self):
        aj_audit.audit()
        a = self.audits()
        self.assertEqual(a["192.168.1.5"]["cves"], [{"id": "CVE-2021-41773", "cvss": 9.8, "port": 80, "maybe_patched": False, "kev": False}])
        self.assertTrue(all(a[ip].get("cve_at") for ip in DEVICES))
        run = self.vulners_runs()
        self.assertEqual(len(run), 1)
        self.assertEqual(run[0][run[0].index("-p") + 1], "22,80")  # exactly the ports found open, not a fixed list

    def test_second_audit_reuses_cached_cves(self):
        aj_audit.audit()
        self.calls.clear()
        aj_audit.audit()
        self.assertEqual(self.vulners_runs(), [])  # nothing re-scanned
        a = self.audits()
        self.assertEqual(a["192.168.1.5"]["cves"][0]["id"], "CVE-2021-41773")  # but the result is still there
        self.assertTrue(a["192.168.1.5"]["findings"])  # and still turns into a finding
        self.assertTrue(any(f["id"] == "cve_critical" for f in a["192.168.1.5"]["findings"]))

    def test_full_audit_ignores_the_cache(self):
        aj_audit.audit()
        self.calls.clear()
        aj_audit.audit(full=True)
        self.assertEqual(len(self.vulners_runs()), 1)

    def test_changed_ports_invalidate_the_cache_for_that_host_only(self):
        aj_audit.audit()
        self.calls.clear()
        OPEN["192.168.1.6"] = [22, 8000]
        try:
            aj_audit.audit()
        finally:
            OPEN["192.168.1.6"] = [22]
        run = self.vulners_runs()
        self.assertEqual(len(run), 1)
        self.assertEqual([a for a in run[0] if a.startswith("192.168.")], ["192.168.1.6"])

    def test_expired_cache_is_rescanned(self):
        aj_audit.audit()
        c = db()
        for r in c.execute("SELECT mac, audit FROM devices WHERE net=?", (NET,)).fetchall():
            a = json.loads(r["audit"]); a["cve_at"] -= aj_audit.REUSE_FOR + 60
            c.execute("UPDATE devices SET audit=? WHERE net=? AND mac=?", (json.dumps(a), NET, r["mac"]))
        c.commit(); c.close()
        self.calls.clear()
        aj_audit.audit()
        self.assertEqual(len(self.vulners_runs()), 1)

    def test_nothing_stamped_when_vulners_produced_no_output(self):
        self.vulners_works = False  # e.g. the script couldn't reach its database
        aj_audit.audit()
        self.assertFalse(any(a.get("cve_at") for a in self.audits().values()))
        self.calls.clear()
        aj_audit.audit()
        self.assertEqual(len(self.vulners_runs()), 1)  # so it tries again next time

    def test_probes_run_in_parallel(self):
        self.probe_delay = 0.3
        t0 = time.time()
        aj_audit.audit()
        took = time.time() - t0
        self.assertGreaterEqual(self.max_in_probe, 3)  # all three devices at once
        self.assertLess(took, 0.3 * 3)                 # not one after another
        self.assertIn("probes", self.audits()["192.168.1.5"])

    def test_one_failing_device_is_noted_and_others_still_probed(self):
        self.probe_fail = {"192.168.1.6"}
        aj_audit.audit()
        a = self.audits()
        self.assertIn("probes", a["192.168.1.5"])
        self.assertNotIn("probes", a["192.168.1.6"])
        self.assertIn("1 device(s) could not be probed", config.state["audit_note"])

    def test_stop_skips_remaining_work(self):
        started = []
        def stopping_probe(ip, ports, try_snmp=False):
            started.append(ip); config.state["stop_requested"] = True; return {}
        with mock.patch.object(aj_audit.probelib, "probe_device", stopping_probe):
            with self.assertRaises(RuntimeError):
                aj_audit.audit()
        self.assertTrue(config.state["stop_requested"])


class OwnDevice(Flow):
    def test_this_computer_reports_its_own_os_and_nmap_never_guesses_it(self):
        c = db()
        c.execute("""INSERT INTO devices (net, mac, ip, vendor, kind, first_seen, last_seen, approved, online)
                     VALUES (?,?,?,?,?,?,?,1,1)""", (NET, "aa:00:00:00:00:02", OWN, None, "this device", 1, time.time()))
        c.commit(); c.close()
        OPEN[OWN] = [8080]
        try:
            with mock.patch.object(aj_audit, "is_admin", lambda: True), \
                    mock.patch.object(aj_audit, "own_os", lambda: {"name": "Linux 6.1.0", "accuracy": 100, "source": "this computer"}):
                aj_audit.audit()
        finally:
            OPEN.pop(OWN, None)
        self.assertEqual(self.audits()[OWN]["os"], {"name": "Linux 6.1.0", "accuracy": 100, "source": "this computer"})
        for call in self.calls:
            if "-O" in call:
                self.assertNotIn(OWN, call)  # the OS scan skipped this computer


class CveSwitch(Flow):
    def test_lookup_off_skips_the_check_keeps_old_results_and_says_so(self):
        from aj import prefs
        aj_audit.audit()                      # a first audit, lookups on: finds the CVE
        self.calls.clear()
        prefs.save_prefs({"cve_lookup": False})
        try:
            aj_audit.audit(full=True)         # even a full audit must not go online
        finally:
            prefs.save_prefs({"cve_lookup": True})
        self.assertEqual(self.vulners_runs(), [])
        self.assertEqual(self.audits()["192.168.1.5"]["cves"][0]["id"], "CVE-2021-41773")  # not wiped
        self.assertIn("CVE lookups are turned off", config.state["audit_note"])


class Helpers(unittest.TestCase):
    def test_run_parallel_collects_errors_and_respects_stop(self):
        seen = []
        errs = aj_audit.run_parallel(lambda x: (seen.append(x), 1 / (x - 2))[1], [1, 2, 3])
        self.assertEqual(sorted(seen), [1, 2, 3])
        self.assertEqual([i for i, _ in errs], [2])
        seen.clear()
        self.assertEqual(aj_audit.run_parallel(seen.append, [1, 2, 3], stop=lambda: True), [])
        self.assertEqual(seen, [])
        self.assertEqual(aj_audit.run_parallel(seen.append, []), [])


if __name__ == "__main__":
    unittest.main()
