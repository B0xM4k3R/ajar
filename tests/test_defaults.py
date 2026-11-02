import unittest
from unittest import mock
from aj import defaults
class TestDefaults(unittest.TestCase):
    def test_lookup_known(self): self.assertEqual(defaults.lookup("TP-LINK WR841N"), [("admin", "admin")])
    def test_no_consent_no_attempts(self):
        calls = []
        r = defaults.check_http_defaults("127.0.0.1", 80, False, "TP-Link", False, log_fn=lambda *a: calls.append(a))
        self.assertEqual(calls, []); self.assertIn("skipped", r)
    def test_lockout_stops(self):
        tries = []
        def fake(host, port, tls, user, pw): tries.append(user); return {"ok": False, "status": 401, "lockout_signal": False}
        with mock.patch.object(defaults, "_try_http_login", fake), mock.patch.object(defaults, "LOCKOUT_BACKOFF", 0):
            r = defaults.check_http_defaults("127.0.0.1", 80, False, "TP-Link", True, log_fn=lambda *a: None)
        self.assertTrue(r["lockout"]); self.assertLessEqual(len(tries), defaults.LOCKOUT_STOP_AFTER)
