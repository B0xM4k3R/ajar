import base64
import http.client
import json
import os
import stat
import tempfile
import threading
import unittest
from unittest import mock

import helpers  # noqa: F401
from aj import alerts, auth as authlib, config
from aj import web as aj_web


def basic(pw):
    return "Basic " + base64.b64encode(f"u:{pw}".encode()).decode()


class Roles(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.saved = dict(authlib.auth)
        cls.dir = tempfile.mkdtemp()
        cls.patch = mock.patch.object(config, "VIEWER_FILE", os.path.join(cls.dir, "ajar.viewer"))
        cls.patch.start()
        authlib.auth["hash"] = authlib.hash_pw("admin-password")
        authlib.auth["viewer"] = None
        cls.server = aj_web.Server(("127.0.0.1", 0), aj_web.Handler)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close(); cls.patch.stop()
        authlib.auth.update(cls.saved); authlib.forget_all()

    def setUp(self):
        authlib.fails.clear(); authlib.good_auth.clear()
        authlib.clear_viewer()

    def call(self, method, path, pw="admin-password", body=None):
        h = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=30)
        hdr = {"Host": "localhost", "X-Ajar": "1", "Content-Type": "application/json"}
        if pw is not None:
            hdr["Authorization"] = basic(pw)
        h.request(method, path, json.dumps(body) if body is not None else None, hdr)
        r = h.getresponse(); data = r.read(); h.close()
        try:
            return r.status, json.loads(data)
        except ValueError:
            return r.status, data

    def enable(self, pw="viewer-password"):
        self.assertEqual(self.call("POST", "/api/viewer", body={"password": pw})[0], 200)

    def test_viewer_off_by_default_and_wrong_password_rejected(self):
        self.assertEqual(self.call("GET", "/api/state", "viewer-password")[0], 401)
        st, snap = self.call("GET", "/api/state")
        self.assertEqual((st, snap["role"], snap["viewer_enabled"]), (200, "admin", False))

    def test_viewer_can_look_but_not_touch(self):
        self.enable()
        st, snap = self.call("GET", "/api/state", "viewer-password")
        self.assertEqual((st, snap["role"]), (200, "viewer"))
        self.assertNotIn("alerts", snap)                       # tokens, SMTP passwords, webhook URLs
        self.assertNotIn("net_settings", snap)
        self.assertNotIn("viewer_enabled", snap)
        for path in ("/api/events", "/api/report"):
            self.assertEqual(self.call("GET", path, "viewer-password")[0], 200, path)
        for path, body in (("/api/scan", {}), ("/api/audit", {}), ("/api/stop", {}), ("/api/approve?mac=x", {}),
                           ("/api/settings", {"allow_default_cred_checks": True}), ("/api/alerts", {"ntfy": {"enabled": True}}),
                           ("/api/schedule", {"enabled": True}), ("/api/prefs", {"cve_lookup": False}),
                           ("/api/viewer", {"password": "another-password"}), ("/api/rename?mac=x", {"name": "x"})):
            st, resp = self.call("POST", path, "viewer-password", body)
            self.assertEqual(st, 403, path)
            self.assertIn("view-only", resp["error"])

    def test_viewer_cannot_read_other_api_paths(self):
        self.enable()
        self.assertEqual(self.call("GET", "/api/anything-else", "viewer-password")[0], 403)
        self.assertEqual(self.call("GET", "/api/anything-else")[0], 404)  # while the admin just gets "not found"
        self.assertEqual(self.call("GET", "/index.html", "viewer-password")[0], 200)  # the page itself is fine

    def test_admin_still_does_everything(self):
        self.enable()
        self.assertEqual(self.call("POST", "/api/schedule", body={"enabled": False})[0], 200)
        self.assertIn("alerts", self.call("GET", "/api/state")[1])
        self.assertTrue(self.call("GET", "/api/state")[1]["viewer_enabled"])

    def test_viewer_password_rules(self):
        self.assertEqual(self.call("POST", "/api/viewer", body={"password": "short"})[0], 400)
        st, resp = self.call("POST", "/api/viewer", body={"password": "admin-password"})
        self.assertEqual(st, 400)
        self.assertIn("main password", resp["error"])
        self.assertEqual(self.call("POST", "/api/viewer", body={"password": 12345678})[0], 400)
        self.assertEqual(self.call("POST", "/api/viewer", body="nope")[0], 400)
        self.assertFalse(authlib.auth["viewer"])

    def test_changing_or_turning_off_signs_viewers_out_immediately(self):
        self.enable("first-password")
        self.assertEqual(self.call("GET", "/api/state", "first-password")[0], 200)   # now cached as a good login
        self.enable("second-password")
        self.assertEqual(self.call("GET", "/api/state", "first-password")[0], 401)
        self.assertEqual(self.call("GET", "/api/state", "second-password")[0], 200)
        self.assertEqual(self.call("POST", "/api/viewer", body={"password": ""})[1]["viewer_enabled"], False)
        self.assertEqual(self.call("GET", "/api/state", "second-password")[0], 401)
        self.assertFalse(os.path.exists(config.VIEWER_FILE))
        self.assertEqual(self.call("GET", "/api/state")[0], 200)                      # the admin is unaffected

    def test_role_survives_the_login_cache(self):
        self.enable()
        for _ in range(2):  # the second request is answered from the cache
            self.assertEqual(self.call("GET", "/api/state", "viewer-password")[1]["role"], "viewer")
        self.assertEqual(self.call("POST", "/api/scan", "viewer-password", {})[0], 403)

    def test_wrong_viewer_guesses_count_towards_the_lockout(self):
        self.enable()
        codes = [self.call("GET", "/api/state", f"wrong{i}")[0] for i in range(authlib.LOCK_AFTER + 1)]
        self.assertEqual(codes[-1], 429)
        self.assertEqual(self.call("GET", "/api/state", "viewer-password")[0], 429)  # locked out, even with the right one

    @unittest.skipIf(os.name == "nt", "POSIX permissions")
    def test_saved_file_is_private_and_reloads(self):
        self.enable("saved-password")
        self.assertEqual(stat.S_IMODE(os.stat(config.VIEWER_FILE).st_mode), 0o600)
        authlib.auth["viewer"] = None
        authlib.load_viewer()
        self.assertEqual(authlib.check_login("saved-password"), "viewer")
        self.assertEqual(authlib.check_login("admin-password"), "admin")
        self.assertIsNone(authlib.check_login("nope"))

    def test_no_main_password_means_no_viewer(self):
        saved = authlib.auth["hash"]; authlib.auth["hash"] = None
        try:
            self.assertEqual(self.call("POST", "/api/viewer", None, {"password": "viewer-password"})[0], 400)
        finally:
            authlib.auth["hash"] = saved

    def test_env_var(self):
        with mock.patch.dict(os.environ, {"AJAR_VIEWER_PASSWORD": "from-the-env"}):
            authlib.load_viewer()
        self.assertEqual(authlib.check_login("from-the-env"), "viewer")


if __name__ == "__main__":
    unittest.main()


class EarlyRejection(unittest.TestCase):
    """A POST that is turned away (view-only, wrong password, locked out) must still get its answer.
    The server used to reply without reading the request body, and closing the connection then
    made the operating system reset it, so the browser saw "connection lost" instead of the reason."""

    @classmethod
    def setUpClass(cls):
        cls.saved = dict(authlib.auth)
        authlib.auth["hash"] = authlib.hash_pw("admin-password")
        authlib.auth["viewer"] = authlib.hash_pw("viewer-password")
        cls.server = aj_web.Server(("127.0.0.1", 0), aj_web.Handler)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close()
        authlib.auth.update(cls.saved); authlib.forget_all()

    def setUp(self):
        authlib.fails.clear(); authlib.good_auth.clear()

    def post(self, pw, body, hdr=None):
        import socket
        h = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=20)
        headers = {"Host": "localhost", "X-Ajar": "1", "Content-Type": "application/json", **(hdr or {})}
        if pw is not None:
            headers["Authorization"] = basic(pw)
        h.request("POST", "/api/settings", body, headers)
        r = h.getresponse(); data = r.read(); h.close()
        return r.status, data

    def test_rejected_posts_with_a_large_body_still_get_a_reply(self):
        big = json.dumps({"pad": "x" * 300_000})  # far more than fits in the socket buffers
        for _ in range(8):
            self.assertEqual(self.post("viewer-password", big)[0], 403)
        authlib.fails.clear()
        self.assertEqual(self.post("wrong", big)[0], 401)
        self.assertEqual(self.post(None, big)[0], 401)

    def test_oversized_request_is_refused_not_read(self):
        h = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=20)
        h.putrequest("POST", "/api/settings"); h.putheader("Host", "localhost"); h.putheader("X-Ajar", "1")
        h.putheader("Authorization", basic("admin-password")); h.putheader("Content-Length", str(50_000_000)); h.endheaders()
        self.assertEqual(h.getresponse().status, 413)
        h.close()

    def test_parallel_requests_with_a_new_login_are_one_attempt_not_many(self):
        """A page load sends several requests at once with the same new login."""
        codes, barrier = [], threading.Barrier(12)

        def get():
            barrier.wait()
            h = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=30)
            h.request("GET", "/app.css", headers={"Host": "localhost", "Authorization": basic("admin-password")})
            r = h.getresponse(); r.read(); h.close(); codes.append(r.status)
        ts = [threading.Thread(target=get) for _ in range(12)]
        [t.start() for t in ts]; [t.join() for t in ts]
        self.assertEqual(codes, [200] * 12)            # nobody was locked out for logging in correctly
        self.assertEqual(authlib.fails, {})            # and none of it counted as a failed attempt

    def test_parallel_wrong_guesses_are_still_limited(self):
        codes, barrier = [], threading.Barrier(12)

        def guess(i):
            barrier.wait()
            h = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=60)
            h.request("GET", "/app.css", headers={"Host": "localhost", "Authorization": basic(f"wrong{i}")})
            r = h.getresponse(); r.read(); h.close(); codes.append(r.status)
        ts = [threading.Thread(target=guess, args=(i,)) for i in range(12)]
        [t.start() for t in ts]; [t.join() for t in ts]
        self.assertEqual(codes.count(401), authlib.LOCK_AFTER, codes)   # only five guesses were ever checked
        self.assertEqual(codes.count(429), 12 - authlib.LOCK_AFTER, codes)


@unittest.skipUnless(__import__("shutil").which("openssl"), "needs openssl")
class EarlyRejectionOverTls(unittest.TestCase):
    """The same, over HTTPS, which is how Ajar normally runs. Over TLS an unread request body made
    the server's reply get lost far more often (the client saw 'remote end closed connection')."""

    @classmethod
    def setUpClass(cls):
        import ssl
        from aj import certs
        cls.dir = tempfile.mkdtemp()
        cls.patches = [mock.patch.object(config, "CERT_FILE", os.path.join(cls.dir, "t.crt")),
                       mock.patch.object(config, "KEY_FILE", os.path.join(cls.dir, "t.key"))]
        [p.start() for p in cls.patches]
        ok, why = certs.ensure_cert()
        assert ok, why
        cls.saved = dict(authlib.auth)
        authlib.auth["hash"] = authlib.hash_pw("admin-password")
        authlib.auth["viewer"] = authlib.hash_pw("viewer-password")
        cls.server = aj_web.Server(("127.0.0.1", 0), aj_web.Handler)
        cls.server.ssl_ctx = certs.server_context()
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.ctx = ssl._create_unverified_context()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close()
        authlib.auth.update(cls.saved); authlib.forget_all()
        [p.stop() for p in cls.patches]

    def test_viewer_posts_always_get_their_403(self):
        authlib.fails.clear(); authlib.good_auth.clear()
        results, errors = [], []

        def hammer():
            for _ in range(15):
                try:
                    h = http.client.HTTPSConnection("127.0.0.1", self.server.server_address[1], context=self.ctx, timeout=30)
                    h.request("POST", "/api/scan", "{}", {"Host": "localhost", "X-Ajar": "1", "Content-Type": "application/json",
                                                          "Authorization": basic("viewer-password")})
                    r = h.getresponse(); r.read(); results.append(r.status); h.close()
                except Exception as e:  # noqa: BLE001
                    errors.append(type(e).__name__)
        ts = [threading.Thread(target=hammer) for _ in range(4)]
        [t.start() for t in ts]; [t.join() for t in ts]
        self.assertEqual(errors, [])
        self.assertEqual(results, [403] * 60)
