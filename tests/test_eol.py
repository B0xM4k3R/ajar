import time
import unittest
import xml.etree.ElementTree as ET

import helpers  # noqa: F401
from aj import audit as aj_audit
from aj import eol, score

NOW = time.mktime(time.strptime("2026-11-04", "%Y-%m-%d"))


def names(texts, now=NOW):
    return [h["name"] for h in eol.find(texts, now)]


class Find(unittest.TestCase):
    def test_old_windows(self):
        self.assertEqual(names(["Microsoft Windows 7 SP1"]), ["Windows 7"])
        self.assertEqual(names(["Microsoft Windows Server 2008 R2"]), ["Windows Server 2008"])
        self.assertEqual(names(["Microsoft Windows XP SP3"]), ["Windows XP"])
        self.assertIn("Windows 8.1", names(["Microsoft Windows 8.1 Update 1"]))

    def test_windows_range_guesses_that_include_a_current_version_are_not_flagged(self):
        self.assertEqual(names(["Microsoft Windows 7 or Windows 10 1607"]), [])
        self.assertEqual(names(["Microsoft Windows Server 2008 or Server 2019"]), [])
        self.assertEqual(names(["Microsoft Windows 10 21H2"]), [])
        self.assertEqual(names(["Microsoft Windows 11"]), [])

    def test_banners(self):
        self.assertEqual(names(["Apache/2.2.22 (Debian)", "PHP/5.4.45"]), ["Apache 2.2", "PHP 5"])
        self.assertEqual(names(["Microsoft-IIS/7.5"]), ["Microsoft IIS 7"])
        self.assertEqual(names(["lighttpd/1.4.55 OpenSSL/1.0.2k"]), ["OpenSSL 1.0"])
        self.assertEqual(names(["SimpleHTTP/0.6 Python/2.7.18"]), ["Python 2"])

    def test_current_software_is_never_flagged(self):
        for t in ("Apache/2.4.58 (Ubuntu)", "PHP/8.3.1", "nginx/1.25.3", "OpenSSL/3.0.13", "Microsoft-IIS/10.0",
                  "OpenSSH_9.6p1", "Linux 5.15 - 6.1", "Python/3.12.1"):
            self.assertEqual(names([t]), [], t)

    def test_no_prefix_confusion(self):
        self.assertEqual(names(["Apache/2.20.1"]), [])        # not 2.2
        self.assertEqual(names(["PHP/5"]), [])                # needs a minor version
        self.assertEqual(names(["PHP/7.40.1"]), [])           # 7.40 is not 7.4
        self.assertEqual(names(["Windows 71"]), [])

    def test_only_after_the_date_has_passed(self):
        before = time.mktime(time.strptime("2022-06-01", "%Y-%m-%d"))
        self.assertEqual(names(["PHP/7.4.3"], before), [])            # still supported then
        self.assertEqual(names(["PHP/7.4.3"], NOW), ["PHP 7"])

    def test_each_name_once_and_description(self):
        hits = eol.find(["Apache/2.2.15", "Apache/2.2.22"], NOW)
        self.assertEqual(len(hits), 1)
        self.assertEqual(eol.describe(hits), "Apache 2.2 (support ended December 2017)")

    def test_every_rule_has_a_valid_date_and_pattern(self):
        import re
        for name, rx, ended, cancel in eol.RULES:
            time.strptime(ended, "%Y-%m-%d"); re.compile(rx); cancel and re.compile(cancel)

    def test_texts_for_collects_from_every_source(self):
        a = {"os": {"name": "Microsoft Windows 7"}, "versions": {"80": "Apache httpd 2.2.22 (Debian)"},
             "probes": {"80": {"http": {"server": "Apache", "powered_by": "PHP/5.3.3"}}, "22": {"ssh": {"software": "OpenSSH_5.3", "banner": "SSH-2.0-OpenSSH_5.3"}}}}
        self.assertEqual({h["name"] for h in eol.find(eol.texts_for(a), NOW)}, {"Apache 2.2", "PHP 5"})  # the OS guess is handled apart
        self.assertEqual(eol.texts_for(None), [])
        self.assertEqual(eol.texts_for({"probes": {"1": {"banner": None}}}), [])


class OsGuess(unittest.TestCase):
    """nmap's operating-system guess is a hint, not proof. 'Linux 2.6.32' is a frequent coarse match
    for kernels many years newer, and it flagged a modern Debian machine as ten years out of date."""
    ids = staticmethod(lambda a: {f["id"]: f for f in aj_audit.assess({"ports": [], "shares": [], "info": {}, **a})})

    def test_nmap_saying_linux_2_6_is_never_taken_as_evidence(self):
        f = self.ids({"os": {"name": "Linux 2.6.32", "accuracy": 97}})
        self.assertNotIn("eol_software", f)
        self.assertNotIn("eol_os_guess", f)

    def test_the_computer_reporting_it_itself_is_believed(self):
        f = self.ids({"os": {"name": "Linux 2.6.32-754.el6.x86_64", "accuracy": 100, "source": "this computer"}})
        self.assertIn("eol_software", f)
        self.assertIn("Linux 2.6", f["eol_software"]["text"])

    def test_a_windows_guess_is_information_only(self):
        f = self.ids({"os": {"name": "Microsoft Windows 7 SP1", "accuracy": 96}})
        self.assertNotIn("eol_software", f)
        self.assertEqual(f["eol_os_guess"]["level"], "info")
        self.assertIn("can be wrong", f["eol_os_guess"]["text"])
        dev = {"mac": "aa:00:00:00:00:01", "ip": "192.168.1.5", "online": 1, "approved": 1, "kind": "other",
               "audit": {"ports": [], "shares": [], "info": {}, "os": {"name": "Microsoft Windows 7 SP1", "accuracy": 96}}}
        self.assertEqual(score.security_report([dev], None)["score"], 100)  # costs nothing

    def test_a_banner_is_still_solid_evidence(self):
        f = self.ids({"os": {"name": "Linux 5.4", "accuracy": 90}, "versions": {"80": "Apache httpd 2.2.22"}})
        self.assertIn("eol_software", f)
        self.assertNotIn("eol_os_guess", f)

    def test_a_guess_agreeing_with_a_banner_is_not_reported_twice(self):
        f = self.ids({"os": {"name": "Microsoft Windows Server 2008 R2", "accuracy": 95},
                      "probes": {"80": {"http": {"server": "Microsoft-IIS/7.5"}}}})
        self.assertIn("eol_software", f)
        self.assertNotIn("eol_os_guess", f)

    def test_own_os_comes_from_the_system(self):
        import platform
        from unittest import mock
        with mock.patch.object(platform, "system", lambda: "Linux"), mock.patch.object(platform, "release", lambda: "6.1.0-18-amd64"):
            self.assertEqual(aj_audit.own_os(), {"name": "Linux 6.1.0-18-amd64", "accuracy": 100, "source": "this computer"})
        self.assertEqual(self.ids({"os": aj_audit.own_os()}).keys() & {"eol_software", "eol_os_guess"}, set())


class Findings(unittest.TestCase):
    def test_assess_and_score(self):
        a = {"ports": [], "shares": [], "info": {}, "probes": {"80": {"http": {"server": "Apache/2.2.15 (CentOS)", "powered_by": ""}}}}
        f = {x["id"]: x for x in aj_audit.assess(a)}
        self.assertEqual(f["eol_software"]["level"], "medium")
        self.assertIn("Apache 2.2", f["eol_software"]["text"])
        dev = {"mac": "aa:00:00:00:00:01", "ip": "192.168.1.5", "name": "NAS", "online": 1, "approved": 1, "kind": "other", "audit": a}
        r = score.security_report([dev], None)
        self.assertEqual(r["score"], 100 - score.SCORE_POINTS["eol_software"])
        self.assertIn("Replace or update", next(i for i in r["issues"] if i["id"] == "eol_software")["title"])

    def test_cve_scan_records_the_versions_nmap_saw_and_reuses_them(self):
        xml = ("<nmaprun><host><address addr='192.168.1.5' addrtype='ipv4'/><ports>"
               "<port protocol='tcp' portid='80'><state state='open'/><service name='http' product='Apache httpd' version='2.2.22' extrainfo='(Debian)'/>"
               "<script id='vulners' output='x'><table key='c'/></script></port></ports></host></nmaprun>")
        res = {"192.168.1.5": {"ports": [{"port": 80}]}}
        now = time.time()
        aj_audit.cve_scan(res, {}, "192.168.1.2", now, nmap=lambda a, t=0: ET.fromstring(xml))
        self.assertEqual(res["192.168.1.5"]["versions"], {"80": "Apache httpd 2.2.22 (Debian)"})
        prev, res2 = res, {"192.168.1.5": {"ports": [{"port": 80}]}}
        aj_audit.cve_scan(res2, prev, "192.168.1.2", now + 60, nmap=lambda a, t=0: self.fail("should reuse"))
        self.assertEqual(res2["192.168.1.5"]["versions"], {"80": "Apache httpd 2.2.22 (Debian)"})
        self.assertEqual(names(eol.texts_for(res2["192.168.1.5"]), NOW), ["Apache 2.2"])


if __name__ == "__main__":
    unittest.main()
