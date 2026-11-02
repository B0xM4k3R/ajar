"""Exposed and unencrypted logins: classifiers, a live HTTP probe, SMBv1, and scoring."""
import os
import tempfile
import threading
import unittest
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import helpers  # sets up the import path and a throwaway database
from helpers import dev
from aj import audit as aj_audit
from aj import score as aj_score
from aj import weakauth as aj_weak

SMB_PROTO_V1 = ET.fromstring('<script id="smb-protocols" output="&#10;  dialects:&#10;    NT LM 0.12 (SMBv1)&#10;    2.0.2"/>')
SMB_PROTO_SAFE = ET.fromstring('<script id="smb-protocols" output="&#10;  dialects:&#10;    2.0.2&#10;    3.1.1"/>')


class Classifiers(unittest.TestCase):
    def test_http_auth_states(self):
        self.assertEqual(aj_weak.classify_http(401, 'Basic realm="x"', "", "http")["auth"], "basic")
        self.assertEqual(aj_weak.classify_http(200, None, "<form><input type=password></form>", "http")["auth"], "login_form")
        self.assertEqual(aj_weak.classify_http(200, None, "<h1>Camera Control</h1>live view", "http")["auth"], "open")
        self.assertEqual(aj_weak.classify_http(302, None, "", "https")["auth"], "login_form")
        self.assertTrue(aj_weak.classify_http(200, None, "x", "http")["plain"])
        self.assertFalse(aj_weak.classify_http(200, None, "x", "https")["plain"])

    def test_rtsp(self):
        self.assertTrue(aj_weak.rtsp_open_noauth("RTSP/1.0 200 OK\r\nCSeq: 1\r\n"))
        self.assertFalse(aj_weak.rtsp_open_noauth("RTSP/1.0 401 Unauthorized\r\n"))
        self.assertFalse(aj_weak.rtsp_open_noauth("garbage"))

    def test_smb1(self):
        self.assertTrue(aj_weak.smb1_enabled(SMB_PROTO_V1))
        self.assertFalse(aj_weak.smb1_enabled(SMB_PROTO_SAFE))


class Probe(unittest.TestCase):
    """A live HTTP probe against a local server returning crafted responses."""
    class H(BaseHTTPRequestHandler):
        mode = "open"
        def log_message(self, *a): pass
        def do_GET(self):
            if self.mode == "basic":
                self.send_response(401); self.send_header("WWW-Authenticate", 'Basic realm="cam"')
                self.end_headers(); self.wfile.write(b"no")
            elif self.mode == "login":
                self.send_response(200); self.end_headers()
                self.wfile.write(b"<html><title>Router Login</title><input type=password></html>")
            else:
                self.send_response(200); self.end_headers()
                self.wfile.write(b"<html><h1>Live View</h1></html>")

    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), cls.H)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close()

    def test_probe_reads_each_state(self):
        self.H.mode = "open"
        self.assertEqual(aj_weak.probe_http("127.0.0.1", self.port)["auth"], "open")
        self.H.mode = "basic"
        self.assertEqual(aj_weak.probe_http("127.0.0.1", self.port)["auth"], "basic")
        self.H.mode = "login"
        self.assertEqual(aj_weak.probe_http("127.0.0.1", self.port)["auth"], "login_form")

    def test_nothing_listening(self):
        self.assertIsNone(aj_weak.probe_http("127.0.0.1", 1))


def audit_dict(kind=None, ports=(), smb1=False, web=None, rtsp=None):
    a = {"ports": [{"port": p, "name": str(p)} for p in ports], "shares": [], "nfs": [], "kind": kind}
    if smb1: a["smb1"] = True
    if web is not None: a["web"] = web
    if rtsp is not None: a["rtsp"] = rtsp
    a["findings"] = aj_audit.assess(a)
    return a


class Findings(unittest.TestCase):
    def ids(self, a):
        return {f["id"]: f for f in a["findings"]}

    def test_open_admin_and_default_reminder(self):
        a = audit_dict(kind="router", ports=[80], web={"auth": "open", "plain": True})
        f = self.ids(a)
        self.assertEqual(f["admin_open"]["level"], "high")
        self.assertEqual(f["default_risk"]["level"], "info")

    def test_protected_login_on_http_is_plaintext_warning_not_open(self):
        a = audit_dict(kind="printer", ports=[80], web={"auth": "login_form", "plain": True})
        f = self.ids(a)
        self.assertNotIn("admin_open", f)
        self.assertIn("http_login_plain", f)
        self.assertEqual(f["default_risk"]["level"], "info")

    def test_https_login_is_not_plaintext(self):
        a = audit_dict(kind="router", ports=[443], web={"auth": "basic", "plain": False})
        self.assertNotIn("http_login_plain", self.ids(a))

    def test_open_stream_and_smb1(self):
        self.assertEqual(self.ids(audit_dict(kind="iot", ports=[554], rtsp={"open": True}))["camera_open"]["level"], "high")
        self.assertIn("smb1", self.ids(audit_dict(ports=[445], smb1=True)))

    def test_computer_with_a_login_is_not_default_risk(self):
        a = audit_dict(kind="personal", ports=[80], web={"auth": "login_form", "plain": True})
        self.assertNotIn("default_risk", self.ids(a))  # only camera/router/printer/iot classes
        self.assertNotIn("http_login_plain", self.ids(a))


class Scoring(unittest.TestCase):
    def dev(self, a):
        d = dev("192.168.1.50"); d["audit"] = a; return d

    def test_hard_signals_score_default_is_advisory(self):
        a = audit_dict(kind="iot", ports=[554, 445], rtsp={"open": True}, smb1=True,
                       web={"auth": "login_form", "plain": True})
        r = aj_score.security_report([self.dev(a)], None)
        pts = {i["id"]: i["points"] for i in r["issues"]}
        self.assertEqual(pts.get("camera_open"), 30)
        self.assertEqual(pts.get("smb1"), 15)
        self.assertEqual(pts.get("http_login_plain"), 6)
        self.assertNotIn("default_risk", pts)  # advisory, no points
        self.assertTrue(any("Check the password" in o for o in r["optional"]))
        labels = {c["label"]: c["status"] for c in r["checks"]}
        self.assertEqual(labels["No old SMBv1 file sharing"], "fail")
        self.assertEqual(labels["No logins open or sent in the clear"], "fail")


if __name__ == "__main__":
    unittest.main(verbosity=2)
