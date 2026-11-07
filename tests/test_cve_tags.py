import time
import unittest
import xml.etree.ElementTree as ET

import helpers  # noqa: F401
from aj import audit as aj_audit
from aj import cve, kev, prefs, score

SSH = {"product": "OpenSSH", "version": "8.2p1 Ubuntu 4ubuntu0.5", "extrainfo": "Ubuntu Linux; protocol 2.0", "ostype": "Linux"}
APACHE = {"product": "Apache httpd", "version": "2.4.49", "extrainfo": "(Unix)"}


def vulners_port(portid, service_attrs, ids_scores):
    rows = "".join(f'<table><elem key="id">{i}</elem><elem key="type">cve</elem><elem key="cvss">{s}</elem></table>' for i, s in ids_scores)
    attrs = " ".join(f'{k}="{v}"' for k, v in service_attrs.items())
    return (f'<port protocol="tcp" portid="{portid}"><state state="open"/><service name="x" {attrs}/>'
            f'<script id="vulners" output="x"><table key="cpe">{rows}</table></script></port>')


class Distro(unittest.TestCase):
    def test_detects_distribution_packages(self):
        self.assertEqual(cve.distro_of(SSH), "Ubuntu")
        self.assertEqual(cve.distro_of({"product": "Apache httpd", "version": "2.4.41", "extrainfo": "(Debian)"}), "Debian")
        self.assertIsNone(cve.distro_of(APACHE))
        self.assertIsNone(cve.distro_of({}))
        self.assertIsNone(cve.distro_of(None))

    def test_merge_dedupes_and_is_only_patched_if_every_port_is(self):
        merged = cve.merge([(22, [{"id": "CVE-1", "cvss": 7.0}, {"id": "CVE-2", "cvss": 9.8}], "Ubuntu"),
                            (80, [{"id": "CVE-1", "cvss": 7.5}], None)])
        by = {c["id"]: c for c in merged}
        self.assertEqual(len(merged), 2)
        self.assertEqual(merged[0]["id"], "CVE-2")                      # highest first
        self.assertEqual((by["CVE-1"]["cvss"], by["CVE-1"]["maybe_patched"]), (7.5, False))  # seen on a non-distro port too
        self.assertTrue(by["CVE-2"]["maybe_patched"])
        self.assertEqual(by["CVE-2"]["vendor"], "Ubuntu")
        self.assertNotIn("vendor", by["CVE-1"])

    def test_effective_score(self):
        self.assertEqual(cve.effective_cvss({"cvss": 9.8}), 9.8)
        self.assertAlmostEqual(cve.effective_cvss({"cvss": 9.8, "maybe_patched": True}), 7.8)
        self.assertEqual(cve.effective_cvss({"cvss": 5.0, "kev": True}), 9.0)  # exploited counts in full
        self.assertEqual(cve.effective_cvss({"cvss": 9.8, "kev": True, "maybe_patched": True}), 9.8)


class Findings(unittest.TestCase):
    def ids(self, cves):
        a = {"ports": [{"port": 22, "name": "SSH"}], "shares": [], "info": {}, "cves": cves}
        return {f["id"]: f for f in aj_audit.assess(a)}

    def test_plain_critical_is_unchanged(self):
        self.assertIn("cve_critical", self.ids([{"id": "CVE-1", "cvss": 9.8}]))

    def test_distro_critical_is_one_band_lower_and_explained(self):
        f = self.ids([{"id": "CVE-1", "cvss": 9.8, "maybe_patched": True, "vendor": "Ubuntu"}])
        self.assertNotIn("cve_critical", f)
        self.assertEqual(f["cve_high"]["level"], "medium")
        self.assertIn("Ubuntu", f["cve_maybe_patched"]["text"])
        self.assertEqual(f["cve_maybe_patched"]["level"], "info")

    def test_distro_high_drops_out_but_is_still_mentioned(self):
        f = self.ids([{"id": "CVE-1", "cvss": 7.5, "maybe_patched": True}])
        self.assertNotIn("cve_high", f)
        self.assertIn("cve_maybe_patched", f)

    def test_actively_exploited_wins_over_everything(self):
        f = self.ids([{"id": "CVE-9", "cvss": 6.0, "kev": True, "maybe_patched": True}])
        self.assertEqual(f["cve_kev"]["level"], "high")
        self.assertIn("CVE-9", f["cve_kev"]["text"])
        self.assertNotIn("cve_maybe_patched", f)

    def test_old_saved_results_without_the_new_fields_still_work(self):
        self.assertIn("cve_critical", self.ids([{"id": "CVE-1", "cvss": 9.1}]))


class Scan(unittest.TestCase):
    def run_scan(self, res, prev=None, kev_ids=None, now=None):
        xml = ("<nmaprun><host><address addr='192.168.1.5' addrtype='ipv4'/><ports>"
               + vulners_port(22, SSH, [("CVE-2020-1", 9.8), ("CVE-2020-2", 7.2)])
               + vulners_port(80, APACHE, [("CVE-2021-41773", 9.8), ("CVE-2020-2", 7.2)])
               + "</ports></host></nmaprun>")
        return aj_audit.cve_scan(res, prev or {}, "192.168.1.2", now or time.time(), nmap=lambda a, t=0: ET.fromstring(xml), kev_ids=kev_ids)

    def test_tags_each_cve_with_port_distro_and_kev(self):
        res = {"192.168.1.5": {"ports": [{"port": 22}, {"port": 80}]}}
        self.run_scan(res, kev_ids={"CVE-2021-41773"})
        by = {c["id"]: c for c in res["192.168.1.5"]["cves"]}
        self.assertEqual((by["CVE-2020-1"]["port"], by["CVE-2020-1"]["maybe_patched"]), (22, True))
        self.assertEqual((by["CVE-2021-41773"]["port"], by["CVE-2021-41773"]["maybe_patched"]), (80, False))
        self.assertFalse(by["CVE-2020-2"]["maybe_patched"])  # on both an Ubuntu and a non-distro port
        self.assertTrue(by["CVE-2021-41773"]["kev"])
        self.assertFalse(by["CVE-2020-1"]["kev"])

    def test_reused_results_are_retagged_when_the_exploited_list_changes(self):
        now = time.time()
        prev = {"192.168.1.5": {"ports": [{"port": 22}], "cve_at": now - 60,
                                "cves": [{"id": "CVE-2020-1", "cvss": 9.8, "port": 22, "maybe_patched": False, "kev": False}]}}
        res = {"192.168.1.5": {"ports": [{"port": 22}]}}
        checked, reused = self.run_scan(res, prev, kev_ids={"CVE-2020-1"}, now=now)
        self.assertEqual((checked, reused), (0, 1))
        self.assertTrue(res["192.168.1.5"]["cves"][0]["kev"])


class Kev(unittest.TestCase):
    DOC = {"vulnerabilities": [{"cveID": "CVE-2021-41773"}, {"cveID": "cve-2020-1 "}, {"cveID": "junk"}, "x"]}

    def setUp(self):
        from aj.db import set_setting
        set_setting(kev.KEY, None)

    def test_parse(self):
        self.assertEqual(kev.parse(self.DOC), {"CVE-2021-41773", "CVE-2020-1"})
        self.assertEqual(kev.parse({}), set())
        self.assertEqual(kev.parse(None), set())

    def test_downloads_once_then_uses_the_saved_copy(self):
        calls = []
        fetch = lambda: calls.append(1) or self.DOC
        now = 1e9
        self.assertEqual(kev.get_ids(now, fetch=fetch), {"CVE-2021-41773", "CVE-2020-1"})
        self.assertEqual(kev.get_ids(now + 3600, fetch=fetch), {"CVE-2021-41773", "CVE-2020-1"})
        self.assertEqual(len(calls), 1)
        kev.get_ids(now + kev.MAX_AGE + 1, fetch=fetch)  # stale: fetched again
        self.assertEqual(len(calls), 2)

    def test_offline_keeps_the_saved_copy_and_never_raises(self):
        kev.get_ids(1e9, fetch=lambda: self.DOC)
        def down(): raise OSError("no internet")
        self.assertEqual(len(kev.get_ids(1e9 + kev.MAX_AGE + 5, fetch=down)), 2)
        self.assertEqual(kev.get_ids(1e9, refresh=False, fetch=down), {"CVE-2021-41773", "CVE-2020-1"})

    def test_an_empty_download_does_not_wipe_the_list(self):
        kev.get_ids(1e9, fetch=lambda: self.DOC)
        self.assertEqual(len(kev.get_ids(1e9 + kev.MAX_AGE + 5, fetch=lambda: {"vulnerabilities": []})), 2)


class Switch(unittest.TestCase):
    def test_prefs_default_on_and_persist(self):
        self.assertTrue(prefs.get_prefs()["cve_lookup"])
        self.assertFalse(prefs.save_prefs({"cve_lookup": False, "evil": 1})["cve_lookup"])
        self.assertNotIn("evil", prefs.get_prefs())
        prefs.save_prefs({"cve_lookup": True})

    def test_score_says_unknown_instead_of_pass_when_lookups_are_off(self):
        dev = {"mac": "aa:00:00:00:00:01", "ip": "192.168.1.5", "online": 1, "approved": 1, "kind": "personal",
               "audit": {"ports": [], "shares": [], "info": {}}}
        for lookup, want in ((True, "pass"), (False, "unknown")):
            r = score.security_report([dict(dev)], None, cve_lookup=lookup)
            kev_check = next(c for c in r["checks"] if "actively exploiting" in c["label"])
            self.assertEqual(kev_check["status"], want)

    def test_kev_finding_is_scored(self):
        dev = {"mac": "aa:00:00:00:00:01", "ip": "192.168.1.5", "online": 1, "approved": 1, "kind": "personal",
               "audit": {"ports": [], "shares": [], "info": {}, "cves": [{"id": "CVE-2021-41773", "cvss": 7.5, "kev": True}]}}
        r = score.security_report([dev], None)
        self.assertIn("cve_kev", {i["id"] for i in r["issues"]})
        self.assertEqual(r["score"], 100 - score.SCORE_POINTS["cve_kev"])


if __name__ == "__main__":
    unittest.main()
