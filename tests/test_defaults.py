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
        # A vendor with 4 default pairs: ajar must stop after LOCKOUT_STOP_AFTER failures.
        tries = []
        def fake(host, port, tls, user, pw, base=None): tries.append(user); return {"ok": False, "status": 401, "lockout_signal": False}
        pairs = [("a", "1"), ("b", "2"), ("c", "3"), ("d", "4")]
        with mock.patch.object(defaults, "_try_http_login", fake), mock.patch.object(defaults, "LOCKOUT_BACKOFF", 0), \
                mock.patch.object(defaults, "DEFAULTS", [("Acme", pairs)]):
            r = defaults.check_http_defaults("127.0.0.1", 80, False, "Acme", True, log_fn=lambda *a: None)
        self.assertTrue(r["lockout"]); self.assertEqual(len(tries), defaults.LOCKOUT_STOP_AFTER)
    def test_few_failures_is_not_lockout(self):
        def fake(host, port, tls, user, pw, base=None): return {"ok": False, "status": 401, "lockout_signal": False}
        with mock.patch.object(defaults, "_try_http_login", fake), mock.patch.object(defaults, "LOCKOUT_BACKOFF", 0):
            r = defaults.check_http_defaults("127.0.0.1", 80, False, "TP-Link", True, log_fn=lambda *a: None)
        self.assertFalse(r["lockout"]); self.assertFalse(r["success"])
    def test_no_sleep_after_last_attempt(self):
        def fake(host, port, tls, user, pw, base=None): return {"ok": False, "status": 401, "lockout_signal": False}
        with mock.patch.object(defaults, "_try_http_login", fake), mock.patch.object(defaults.time, "sleep") as sl:
            defaults.check_http_defaults("127.0.0.1", 80, False, "TP-Link", True, log_fn=lambda *a: None)
        sl.assert_not_called()  # TP-Link has a single pair, so there is nothing to wait for
    def test_lookup_whole_words_only(self):
        self.assertEqual(defaults.lookup("Apache/2.4.41 PHP/7.4"), [])
        self.assertEqual(defaults.lookup("HP LaserJet 400"), [("admin", "")])
        self.assertEqual(defaults.lookup("Welcome to Axis Mapping"), [("root", "pass")])
