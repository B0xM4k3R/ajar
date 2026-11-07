"""Runs the real dashboard script (web/app.js) under Node with a stub DOM, fed with what the real
server returns, to catch the kind of mistake a syntax check can't: a typo in a template, a missing
field, a button that never gets drawn, or unescaped text from the network."""
import base64
import http.client
import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
import unittest

import helpers  # noqa: F401
from aj import accept, auth as authlib, config
from aj import web as aj_web
from aj.db import db

NET = "nui"
HERE = os.path.dirname(os.path.abspath(__file__))
CAM = "aa:00:00:00:00:01"
EVIL = '<img src=x onerror=alert(1)>'
AUDIT = {
    "ports": [{"port": 23, "name": "Telnet"}, {"port": 22, "name": "SSH"}],
    "shares": [], "info": {}, "ipv6": ["2606:4700::1111"], "probes": {"22": {"ssh": {"software": "OpenSSH_8.2"}}},
    "cves": [{"id": "CVE-2021-41773", "cvss": 7.5, "port": 80, "maybe_patched": False, "kev": True},
             {"id": "CVE-2020-15778", "cvss": 7.8, "port": 22, "maybe_patched": True, "vendor": "Ubuntu", "kev": False}],
    "findings": [{"level": "high", "id": "telnet", "text": "Telnet is open."},
                 {"level": "high", "id": "cve_kev", "text": "Attackers are known to be exploiting: CVE-2021-41773."}],
    "depth": "common", "scanned": time.time(),
}


@unittest.skipUnless(shutil.which("node"), "needs Node.js")
class UiSmoke(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        c = db()
        for t in ("devices", "networks", "events"):
            c.execute(f"DELETE FROM {t}")
        c.execute("INSERT INTO networks (id, name, gateway_mac, gateway_ip, subnet, first_seen, last_seen) VALUES (?,?,?,?,?,?,?)",
                  (NET, "Home", "aa:aa:aa:aa:aa:aa", "192.168.1.1", "192.168.1.0/24", 1, 1))
        c.execute("INSERT INTO devices (net, mac, ip, name, vendor, kind, first_seen, last_seen, approved, online, audit) VALUES (?,?,?,?,?,?,?,?,1,1,?)",
                  (NET, CAM, "192.168.1.20", EVIL, "Wyze", "iot", 1, time.time(), json.dumps(AUDIT)))
        c.execute("INSERT INTO devices (net, mac, ip, name, vendor, kind, first_seen, last_seen, approved, online) VALUES (?,?,?,?,?,?,?,?,0,1)",
                  (NET, "aa:00:00:00:00:02", "192.168.1.21", "New thing", "Acme", "other", 1, time.time()))  # unapproved: makes that issue exist
        c.commit(); c.close()
        cls.was_net = config.state.get("net")
        config.state["net"] = NET  # the network being watched now (accept/undo buttons are hidden on saved networks)
        accept.accept(NET, "net", "unapproved", "I know this one <script>alert(2)</script>")
        accept.accept(NET, CAM, "telnet", "camera is on its own VLAN")
        cls.saved = dict(authlib.auth)
        authlib.auth.update(hash=authlib.hash_pw("admin-password"), viewer=authlib.hash_pw("viewer-password"))
        cls.server = aj_web.Server(("127.0.0.1", 0), aj_web.Handler)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.tmp = tempfile.mkdtemp()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close(); config.state["net"] = cls.was_net
        authlib.auth.update(cls.saved); authlib.forget_all()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def served(self, pw):
        authlib.fails.clear()
        h = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=20)
        h.request("GET", f"/api/state?slim=1&net={NET}&expand={CAM.replace(':', '%3A')}",
                  headers={"Host": "localhost", "Authorization": "Basic " + base64.b64encode(f"u:{pw}".encode()).decode()})
        r = h.getresponse(); body = r.read(); h.close()
        self.assertEqual(r.status, 200)
        return body

    def draw(self, pw):
        path = os.path.join(self.tmp, "state.json")
        with open(path, "wb") as f:
            f.write(self.served(pw))
        out = subprocess.run(["node", os.path.join(HERE, "ui_smoke.js"), path, CAM], capture_output=True, text=True, timeout=60)
        self.assertEqual(out.returncode, 0, out.stderr)
        res = json.loads(out.stdout)
        self.assertEqual(res["errors"], [], "\n".join(res["errors"]))
        return res

    def test_admin_dashboard(self):
        r = self.draw("admin-password")
        self.assertFalse(r["bodyClasses"].get("viewer"))
        s = r["settings"]
        for want in ("Scheduled scans", "Look up known vulnerabilities online", "Other networks", "View-only access",
                     "Webhook", "data-api=\"schedule\"", "data-ch=\"webhook\""):
            self.assertIn(want, s)
        self.assertNotIn("/api/export", s)  # exports live in the Report tab now
        sec = r["security"]
        self.assertIn("Accepted risks", sec)
        self.assertIn(f'data-unaccept="net|unapproved"', sec)
        self.assertIn("camera is on its own VLAN", sec)

    def test_expanded_device_shows_the_new_details(self):
        lst = self.draw("admin-password")["list"]
        for want in ("Attackers are using this now", "May already be patched by Ubuntu", "port 22",
                     "IPv6 addresses", "2606:4700::1111"):
            self.assertIn(want, lst)
        self.assertIn(f'data-unaccept="{CAM}|telnet"', lst)                  # accepted: offers Undo
        self.assertIn(f'data-accept="{CAM}|cve_kev"', lst)                   # not accepted: offers Accept
        self.assertIn("Accepted", lst)

    def test_nothing_from_the_network_is_drawn_as_html(self):
        r = self.draw("admin-password")
        for html in (r["list"], r["security"], r["settings"]):
            self.assertNotIn("<img src=x", html)
            self.assertNotIn("<script>alert", html)
        self.assertIn("&lt;img src=x", r["list"])
        self.assertIn("&lt;script&gt;alert(2)", r["security"])

    def test_no_inline_handlers_are_ever_drawn(self):
        import re
        r = self.draw("admin-password")
        for html in (r["list"], r["security"], r["settings"]):
            self.assertIsNone(re.search(r"<[^>]*\son(click|change|input|submit|load|error)\s*=", html))  # inside a real tag; the CSP would block them

    def test_report_tab_has_the_download_and_the_exports(self):
        r = self.draw("admin-password")
        for want in ("Download audit report", 'data-report="1"', "/api/export?format=csv", "/api/export", "Download everything (JSON)"):
            self.assertIn(want, r["report"])
        self.assertNotIn("Download audit report", r["security"])   # moved out of the Security tab

    def test_viewers_get_the_report_tab_too(self):
        self.assertIn("Download audit report", self.draw("viewer-password")["report"])

    def test_map_nodes_are_clickable_and_open_the_device(self):
        r = self.draw("admin-password")
        self.assertIn(f'class="hit" data-mac="{CAM}"', r["map"])
        self.assertIn('role="button"', r["map"])
        self.assertEqual(r["afterClick"], {"expanded": True, "devicesHidden": False, "securityHidden": True})

    def test_viewer_sees_view_only_mode_and_no_settings(self):
        r = self.draw("viewer-password")
        self.assertTrue(r["bodyClasses"].get("viewer"))
        self.assertEqual(r["roleBadge"], "View only")
        self.assertIn("only available with the main password", r["settings"])
        self.assertNotIn("data-api", r["settings"])
        self.assertIn("Accepted risks", r["security"])  # they can still read everything


if __name__ == "__main__":
    unittest.main()
