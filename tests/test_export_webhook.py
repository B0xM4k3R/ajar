import csv
import hashlib
import hmac
import http.client
import io
import json
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

import helpers  # noqa: F401
from aj import alerts, export
from aj import web as aj_web
from aj.db import db, set_net_setting, set_setting
from aj.events import record

NET = "nexp"


class Receiver(BaseHTTPRequestHandler):
    got = []
    status = 200

    def log_message(self, *a): pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        Receiver.got.append((dict(self.headers), body))
        self.send_response(Receiver.status); self.send_header("Content-Length", "0"); self.end_headers()


class Webhook(unittest.TestCase):
    def setUp(self):
        Receiver.got, Receiver.status = [], 200
        self.srv = HTTPServer(("127.0.0.1", 0), Receiver)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}/hook"
        c = db(); c.execute("DELETE FROM events"); c.commit(); c.close()
        set_net_setting(NET, "alert_seen_webhook", 0)
        set_setting("alerts", None)

    def tearDown(self):
        self.srv.shutdown(); self.srv.server_close(); set_setting("alerts", None)

    def cfg(self, **over):
        cfg = alerts.default_config()
        cfg["webhook"].update(enabled=True, url=self.url, secret="s3cret", **over)
        return cfg

    def test_signed_json_with_the_events(self):
        record(NET, "new_device", "high", "New device joined: Mystery box (192.168.1.77).", "aa:bb:cc:dd:ee:ff")
        self.assertEqual(alerts.dispatch(NET, "Home", self.cfg()), {"webhook": 1})
        headers, body = Receiver.got[0]
        want = "sha256=" + hmac.new(b"s3cret", body, hashlib.sha256).hexdigest()
        self.assertEqual(headers["X-Ajar-Signature"], want)
        doc = json.loads(body)
        self.assertEqual((doc["source"], doc["network"], doc["priority"]), ("ajar", "Home", "high"))
        self.assertEqual(doc["events"][0]["kind"], "new_device")
        self.assertEqual(doc["events"][0]["mac"], "aa:bb:cc:dd:ee:ff")

    def test_no_secret_means_no_signature(self):
        cfg = self.cfg(); cfg["webhook"]["secret"] = ""
        alerts.send_webhook(cfg["webhook"], "t", "b")
        self.assertNotIn("X-Ajar-Signature", Receiver.got[0][0])

    def test_not_sent_twice_and_retried_after_a_failure(self):
        record(NET, "new_device", "high", "Something new.", None)
        Receiver.status = 500
        self.assertEqual(alerts.dispatch(NET, "Home", self.cfg()), {})          # failed: keep it for next time
        Receiver.status = 200
        self.assertEqual(alerts.dispatch(NET, "Home", self.cfg()), {"webhook": 1})
        self.assertEqual(alerts.dispatch(NET, "Home", self.cfg()), {})          # and never again
        self.assertEqual(len(Receiver.got), 2)

    def test_level_respected(self):
        record(NET, "x", "medium", "A medium thing.", None)
        self.assertEqual(alerts.dispatch(NET, "Home", self.cfg(min_level="high")), {})
        self.assertEqual(alerts.dispatch(NET, "Home", self.cfg(min_level="medium")), {})  # already marked seen above
        self.assertEqual(Receiver.got, [])

    def test_only_http_urls_are_accepted(self):
        for bad in ("", "file:///etc/passwd", "ftp://x/y", "javascript:alert(1)", "gopher://x"):
            with self.assertRaises(ValueError):
                alerts.send_webhook({"url": bad}, "t", "b")
        cfg = alerts.default_config(); cfg["webhook"]["url"] = "file:///etc/passwd"
        self.assertEqual(alerts.save_config(cfg)["webhook"]["url"], "")  # and never saved

    def test_secret_is_never_sent_to_the_dashboard_and_blank_keeps_it(self):
        cfg = self.cfg(); alerts.save_config(cfg)
        pub = alerts.public_config()["webhook"]
        self.assertEqual((pub["secret"], pub["has_secret"]), ("", True))
        h = aj_web.Handler.__new__(aj_web.Handler)
        h.save_alerts({"webhook": {"secret": "", "min_level": "medium"}})   # the form leaves the secret blank
        saved = alerts.get_config()["webhook"]
        self.assertEqual((saved["secret"], saved["min_level"]), ("s3cret", "medium"))

    def test_test_button(self):
        alerts.save_config(self.cfg())
        ok, msg = alerts.send_test("webhook")
        self.assertTrue(ok, msg)
        self.assertEqual(json.loads(Receiver.got[0][1])["title"], "Test alert")


class Exports(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        c = db()
        c.execute("DELETE FROM devices"); c.execute("DELETE FROM networks"); c.execute("DELETE FROM events")
        c.execute("INSERT INTO networks (id, name, gateway_mac, gateway_ip, subnet, first_seen, last_seen) VALUES (?,?,?,?,?,?,?)",
                  (NET, "Home: Main/WiFi", "aa:aa:aa:aa:aa:aa", "192.168.1.1", "192.168.1.0/24", 1, 1))
        rows = [("aa:00:00:00:00:01", "192.168.1.20", "Garage camera", "Wyze", "iot",
                 {"ports": [{"port": 23, "name": "Telnet"}, {"port": 80, "name": "HTTP"}], "shares": [], "info": {},
                  "findings": [{"level": "high", "id": "telnet", "text": "t"}, {"level": "info", "id": "other_ports", "text": "o"}],
                  "cves": [{"id": "CVE-2021-1", "cvss": 9.8}]}),
                ("aa:00:00:00:00:02", "192.168.1.21", '=HYPERLINK("http://evil","click")', "Acme", "other", None),
                ("ip:192.168.1.22", "192.168.1.22", "+cmd|calc", None, "other", None)]
        for mac, ip, name, vendor, kind, audit in rows:
            c.execute("INSERT INTO devices (net, mac, ip, name, vendor, kind, first_seen, last_seen, approved, online, audit) VALUES (?,?,?,?,?,?,?,?,1,1,?)",
                      (NET, mac, ip, name, vendor, kind, 1_700_000_000, 1_700_000_500, json.dumps(audit) if audit else None))
        c.commit(); c.close()
        record(NET, "new_device", "high", "New device joined.", "aa:00:00:00:00:02")
        record(NET, "gone", "presence", "Something went offline.", None)
        cls.server = aj_web.Server(("127.0.0.1", 0), aj_web.Handler)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close()

    def get(self, path):
        h = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=20)
        h.request("GET", path, headers={"Host": "localhost"})
        r = h.getresponse(); body = r.read(); h.close()
        return r, body

    def test_csv(self):
        r, body = self.get(f"/api/export?format=csv&net={NET}")
        self.assertIn("attachment", r.getheader("Content-Disposition"))
        self.assertIn("ajar-Home-Main-WiFi-", r.getheader("Content-Disposition"))  # filename made safe
        self.assertTrue(r.getheader("Content-Type").startswith("text/csv"))
        rows = list(csv.reader(io.StringIO(body.decode("utf-8-sig"))))
        self.assertEqual(rows[0], export.CSV_COLUMNS)
        by_ip = {row[1]: dict(zip(export.CSV_COLUMNS, row)) for row in rows[1:]}
        cam = by_ip["192.168.1.20"]
        self.assertEqual((cam["open_ports"], cam["problems"], cam["worst_problem"], cam["cves"]), ("23;80", "1", "high", "CVE-2021-1"))
        self.assertEqual(cam["first_seen"], "2023-11-14T22:13:20Z")
        self.assertEqual(by_ip["192.168.1.22"]["mac"], "")  # tracked-by-IP placeholder isn't a MAC

    def test_csv_formula_injection_is_defused(self):
        _, body = self.get(f"/api/export?format=csv&net={NET}")
        names = [r[0] for r in csv.reader(io.StringIO(body.decode("utf-8-sig")))][1:]
        self.assertIn("'=HYPERLINK(\"http://evil\",\"click\")", names)
        self.assertIn("'+cmd|calc", names)
        self.assertFalse(any(n[:1] in "=+-@" for n in names))
        self.assertEqual(export.csv_safe("-5"), "'-5")
        self.assertEqual(export.csv_safe("Garage camera"), "Garage camera")
        self.assertEqual(export.csv_safe(None), "")

    def test_json(self):
        r, body = self.get(f"/api/export?net={NET}")
        self.assertIn(".json", r.getheader("Content-Disposition"))
        doc = json.loads(body)
        self.assertEqual(doc["schema"], "ajar-export/1")
        self.assertEqual(doc["network"]["name"], "Home: Main/WiFi")
        self.assertEqual(len(doc["devices"]), 3)
        self.assertIn("score", doc["security"])
        self.assertEqual([e["kind"] for e in doc["events"]], ["new_device"])  # presence chatter left out
        self.assertNotIn("alerts", doc)                                      # no settings, no secrets
        self.assertNotIn("state", doc)

    def test_export_needs_the_password_like_everything_else(self):
        from aj import auth
        saved = dict(auth.auth); auth.auth["hash"] = auth.hash_pw("pw")
        try:
            r, _ = self.get(f"/api/export?net={NET}")
            self.assertEqual(r.status, 401)
        finally:
            auth.auth.update(saved)


if __name__ == "__main__":
    unittest.main()
