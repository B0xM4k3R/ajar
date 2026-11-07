"""The 5-second refresh sends a compact snapshot; detail only for devices that are open."""
import gzip
import http.client
import json
import threading
import time
import unittest

import helpers  # noqa: F401
from aj import web as aj_web
from aj.db import db

NET = "nslim"


def big_audit(n=40):
    return {
        "ports": [{"port": 80, "name": "Web (HTTP)"}, {"port": 23, "name": "Telnet"}],
        "shares": [{"name": "Public", "type": "disk", "access": "read", "exposed": {"sensitive": False, "categories": {}},
                    "files": [{"name": f"file{i}.txt", "dir": False, "size": 1234} for i in range(n)]}],
        "ftp_files": [{"name": f"ftp{i}.bin", "dir": False} for i in range(n)],
        "probes": {"80": {"http": {"title": "Router admin", "server": "x" * 200, "generator": "y" * 200},
                          "tls": {"issuer": "z" * 300, "san": ["a.example"] * 40}}},
        "cves": [{"id": "CVE-2021-1", "cvss": 9.8}], "findings": [{"level": "high", "id": "telnet", "text": "Telnet is open.", "what": ""}],
        "info": {"name": "Cam"}, "depth": "common", "scanned": time.time(), "kind": "iot",
    }


class Slim(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        c = db()
        c.execute("DELETE FROM devices"); c.execute("DELETE FROM networks")
        c.execute("INSERT INTO networks (id, name, gateway_mac, gateway_ip, subnet, first_seen, last_seen) VALUES (?,?,?,?,?,?,?)",
                  (NET, "Test", "aa:aa:aa:aa:aa:aa", "192.168.9.1", "192.168.9.0/24", 1, 1))
        for i in range(12):
            c.execute("""INSERT INTO devices (net, mac, ip, vendor, kind, first_seen, last_seen, approved, online, audit)
                         VALUES (?,?,?,?,?,?,?,1,1,?)""",
                      (NET, f"aa:00:00:00:00:{i:02x}", f"192.168.9.{10 + i}", "Acme", "iot", 1, time.time(), json.dumps(big_audit())))
        c.commit(); c.close()
        cls.mac = "aa:00:00:00:00:03"

    def dev(self, snap, mac):
        return next(d for d in snap["devices"] if d["mac"] == mac)

    def test_slim_drops_bulk_but_keeps_what_the_row_needs(self):
        a = self.dev(aj_web.snapshot(NET, expand=set()), self.mac)["audit"]
        self.assertNotIn("probes", a)
        self.assertNotIn("ftp_files", a)
        self.assertNotIn("files", a["shares"][0])
        for kept in ("ports", "findings", "cves", "info", "depth", "scanned"):
            self.assertIn(kept, a)
        self.assertEqual(a["shares"][0]["name"], "Public")
        self.assertEqual(a["shares"][0]["access"], "read")

    def test_expanded_device_gets_everything(self):
        snap = aj_web.snapshot(NET, expand={self.mac})
        full = self.dev(snap, self.mac)["audit"]
        self.assertIn("probes", full)
        self.assertEqual(len(full["shares"][0]["files"]), 40)
        self.assertEqual(len(full["ftp_files"]), 40)
        self.assertNotIn("probes", self.dev(snap, "aa:00:00:00:00:04")["audit"])  # but only that one

    def test_no_expand_argument_means_full_for_reports(self):
        self.assertIn("probes", self.dev(aj_web.snapshot(NET), self.mac)["audit"])

    def test_score_does_not_depend_on_slimming(self):
        full, slim = aj_web.snapshot(NET), aj_web.snapshot(NET, expand=set())
        self.assertEqual(full["security"]["score"], slim["security"]["score"])
        self.assertEqual(len(full["security"]["issues"]), len(slim["security"]["issues"]))
        self.assertTrue(full["security"]["issues"])  # the Telnet findings are being scored at all

    def test_payload_is_much_smaller(self):
        full = len(json.dumps(aj_web.snapshot(NET)))
        slim = len(json.dumps(aj_web.snapshot(NET, expand=set())))
        self.assertLess(slim, full * 0.4, (slim, full))

    def test_http_api_slim_expand_and_gzip(self):
        server = aj_web.Server(("127.0.0.1", 0), aj_web.Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()

        def get(path, **hdr):
            c = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=20)
            c.request("GET", path, headers={"Host": "localhost", **hdr})
            r = c.getresponse(); body = r.read(); c.close()
            return r, body
        try:
            r, body = get(f"/api/state?net={NET}")  # an older client: no slim flag, full data
            self.assertIn("probes", self.dev(json.loads(body), self.mac)["audit"])
            self.assertIsNone(r.getheader("Content-Encoding"))

            r, body = get(f"/api/state?slim=1&net={NET}&expand=" + self.mac.replace(":", "%3A"), **{"Accept-Encoding": "gzip"})
            self.assertEqual(r.getheader("Content-Encoding"), "gzip")
            snap = json.loads(gzip.decompress(body))
            self.assertIn("probes", self.dev(snap, self.mac)["audit"])
            self.assertNotIn("probes", self.dev(snap, "aa:00:00:00:00:04")["audit"])
            self.assertLess(len(body), 8000)  # 12 devices, compressed

            r, body = get(f"/api/state?slim=1&net={NET}")  # no gzip asked for: plain JSON
            self.assertIsNone(r.getheader("Content-Encoding"))
            json.loads(body)
        finally:
            server.shutdown(); server.server_close()


if __name__ == "__main__":
    unittest.main()
