"""The default-login check against real local servers: it must only report success when the
device treats the default login differently from no login or a made-up login."""
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

import helpers  # noqa: F401  (import path + throwaway database)
from aj import defaults

LONG_HEAD = "<html><head>" + "<style>x{}</style>" * 60 + "</head><body>Welcome to the device</body></html>"
LOGIN_PAGE = "<html><body><form method=post><input name=u><input type=password name=p></form></body></html>"


def serve(handler_cls):
    srv = HTTPServer(("127.0.0.1", 0), handler_cls)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


class Quiet(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def reply(self, code, body="", headers=None):
        self.send_response(code)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        data = body.encode()
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class OpenAdmin(Quiet):  # no login at all, and a long head so "login" isn't in the first 400 chars
    def do_GET(self): self.reply(200, LONG_HEAD)
    def do_POST(self): self.reply(200, LONG_HEAD)


class BasicAdmin(Quiet):
    def do_GET(self):
        import base64
        if self.headers.get("Authorization") == "Basic " + base64.b64encode(b"admin:admin").decode():
            return self.reply(200, "<html>admin panel</html>")
        self.reply(401, "denied", {"WWW-Authenticate": 'Basic realm="x"'})


class FormAdmin(Quiet):
    def do_GET(self): self.reply(200, LOGIN_PAGE)

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
        if "username=admin" in body and "password=admin" in body:
            return self.reply(302, "", {"Location": "/home"})
        self.reply(200, LOGIN_PAGE)


class SameAnswerForm(Quiet):  # a login page that answers every POST identically
    def do_GET(self): self.reply(200, LOGIN_PAGE)
    def do_POST(self): self.reply(200, LOGIN_PAGE)


class TestRealServers(unittest.TestCase):
    def attempt(self, handler, user="admin", pw="admin"):
        srv = serve(handler)
        try:
            base = {}
            return defaults._try_http_login("127.0.0.1", srv.server_address[1], False, user, pw, base), base
        finally:
            srv.shutdown(); srv.server_close()

    def test_open_admin_is_not_a_default_login(self):
        r, _ = self.attempt(OpenAdmin)
        self.assertFalse(r["ok"])  # used to be reported as "accepts factory default credential"

    def test_basic_auth_default_detected(self):
        self.assertTrue(self.attempt(BasicAdmin)[0]["ok"])

    def test_basic_auth_wrong_login_rejected(self):
        self.assertFalse(self.attempt(BasicAdmin, "admin", "nope")[0]["ok"])

    def test_form_default_detected_and_comparison_logged(self):
        r, base = self.attempt(FormAdmin)
        self.assertTrue(r["ok"])
        self.assertEqual(len(base["events"]), 1)  # the made-up login is recorded for the audit log

    def test_form_wrong_login_rejected(self):
        self.assertFalse(self.attempt(FormAdmin, "admin", "wrong")[0]["ok"])

    def test_identical_answers_prove_nothing(self):
        self.assertFalse(self.attempt(SameAnswerForm)[0]["ok"])

    def test_comparison_requests_logged_through_check(self):
        srv = serve(FormAdmin)
        logged = []
        try:
            from unittest import mock
            with mock.patch.object(defaults, "DEFAULTS", [("Acme", [("admin", "admin")])]):
                r = defaults.check_http_defaults("127.0.0.1", srv.server_address[1], False, "Acme", True,
                                                 log_fn=lambda h, p, u, s: logged.append(u))
        finally:
            srv.shutdown(); srv.server_close()
        self.assertTrue(r["success"])
        self.assertEqual(logged, [defaults.BOGUS[0], "admin"])


if __name__ == "__main__":
    unittest.main()
