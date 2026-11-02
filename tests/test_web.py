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
