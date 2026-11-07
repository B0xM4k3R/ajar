"""The dashboard server: HTTPS with a self-signed certificate, and plain-HTTP redirects."""
import http.client
import os
import shutil
import ssl
import tempfile
import threading
import unittest

import helpers  # sets up the import path and a throwaway database
from aj import config as aj_config
from aj import certs as aj_certs
from aj import web as aj_web


@unittest.skipUnless(shutil.which("openssl"), "needs openssl")
class Https(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        d = tempfile.mkdtemp()
        cls.saved = aj_config.CERT_FILE, aj_config.KEY_FILE
        aj_config.CERT_FILE, aj_config.KEY_FILE = os.path.join(d, "t.crt"), os.path.join(d, "t.key")
        cls.made = aj_certs.ensure_cert("192.168.1.80")
        cls.server = aj_web.Server(("127.0.0.1", 0), aj_web.Handler)
        cls.server.ssl_ctx = aj_certs.server_context()
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        aj_config.CERT_FILE, aj_config.KEY_FILE = cls.saved

    def test_certificate_made_once(self):
        self.assertEqual(self.made, (True, "created"))
        self.assertEqual(aj_certs.ensure_cert(), (True, "existing"))
        fp = aj_certs.fingerprint()
        self.assertEqual(len(fp.split(":")), 32)

    def test_certificate_covers_local_names(self):
        ctx = ssl.create_default_context(cafile=aj_config.CERT_FILE)
        conn = http.client.HTTPSConnection("localhost", self.port, context=ctx, timeout=5)
        conn.request("GET", "/api/state")  # passes only if the cert is valid for "localhost"
        self.assertEqual(conn.getresponse().status, 200)

    def test_plain_http_is_redirected_before_any_password(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("POST", "/api/scan", headers={"Authorization": "Basic secret"})
        r = conn.getresponse()
        self.assertEqual(r.status, 308)
        self.assertEqual(r.getheader("Location"), f"https://127.0.0.1:{self.port}/api/scan")

    def test_https_serves_the_dashboard(self):
        ctx = ssl._create_unverified_context()
        for path, ctype in (("/", "text/html"), ("/app.js", "text/javascript"), ("/app.css", "text/css")):
            conn = http.client.HTTPSConnection("127.0.0.1", self.port, context=ctx, timeout=5)
            conn.request("GET", path)
            r = conn.getresponse()
            self.assertEqual((r.status, r.getheader("Content-Type").split(";")[0]), (200, ctype))


if __name__ == "__main__":
    unittest.main(verbosity=2)


class ReportEndpoint(unittest.TestCase):
    """GET /api/report once crashed with UnboundLocalError: a function-local `import re`
    in do_GET made `re` a local name for the whole method."""

    def test_report_downloads(self):
        aj_web.db  # helpers has already pointed the database at a throwaway file
        from aj.db import init_db
        init_db()
        server = aj_web.Server(("127.0.0.1", 0), aj_web.Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=20)
            conn.request("GET", "/api/report", headers={"Host": "localhost"})
            r = conn.getresponse()
            body = r.read()
            self.assertEqual(r.status, 200, body[:200])
            self.assertIn("attachment", r.getheader("Content-Disposition", ""))
        finally:
            server.shutdown()
            server.server_close()


class Headers(unittest.TestCase):
    def test_csp_blocks_inline_script_and_dashboard_has_none(self):
        """The CSP only allows scripts from app.js, so the dashboard must not rely on inline
        handlers (onclick=...), which the browser would silently refuse."""
        import re as _re
        server = aj_web.Server(("127.0.0.1", 0), aj_web.Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=10)
            conn.request("GET", "/index.html", headers={"Host": "localhost"})
            r = conn.getresponse(); r.read()
            csp = r.getheader("Content-Security-Policy", "")
            self.assertIn("script-src 'self'", csp)
            self.assertNotIn("script-src 'self' 'unsafe-inline'", csp)
        finally:
            server.shutdown(); server.server_close()
        web = os.path.join(aj_config.HERE, "web")
        for name in ("app.js", "index.html"):
            with open(os.path.join(web, name), encoding="utf-8") as f:
                text = f.read()
            self.assertIsNone(_re.search(r"\son(click|change|input|submit|load|error)\s*=", text), name)
            self.assertNotIn("javascript:", text)


@unittest.skipUnless(shutil.which("openssl"), "needs openssl")
class CertRenewal(unittest.TestCase):
    def test_expiring_certificate_is_replaced(self):
        import subprocess
        d = tempfile.mkdtemp()
        saved = aj_config.CERT_FILE, aj_config.KEY_FILE
        aj_config.CERT_FILE, aj_config.KEY_FILE = os.path.join(d, "t.crt"), os.path.join(d, "t.key")
        try:
            subprocess.run([shutil.which("openssl"), "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                            "-keyout", aj_config.KEY_FILE, "-out", aj_config.CERT_FILE, "-subj", "/CN=old"],
                           check=True, capture_output=True)
            self.assertTrue(aj_certs.cert_expiring())
            self.assertEqual(aj_certs.ensure_cert(), (True, "created"))  # replaced
            self.assertFalse(aj_certs.cert_expiring())
            self.assertEqual(aj_certs.ensure_cert(), (True, "existing"))  # and left alone afterwards
        finally:
            aj_config.CERT_FILE, aj_config.KEY_FILE = saved
