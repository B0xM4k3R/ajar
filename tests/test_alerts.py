"""Alerts and the weekly report: per-channel selectability, levels, dedup, delivery."""
import os
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import helpers  # sets up the import path and a throwaway database
from aj import alerts as aj_alerts
from aj import config as aj_config
from aj import db as aj_db
from aj import events as aj_events


class NtfyReceiver(BaseHTTPRequestHandler):
    posts = []
    def log_message(self, *a): pass
    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        NtfyReceiver.posts.append({"path": self.path, "body": self.rfile.read(n).decode(),
                                   "title": self.headers.get("Title"), "priority": self.headers.get("Priority")})
        self.send_response(200); self.send_header("Content-Length", "0"); self.end_headers()


class FakeSMTP:
    sent = []
    def __init__(self, host, port, timeout=0): self.host = host
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def starttls(self, context=None): pass
    def login(self, u, p): self.user = u
    def send_message(self, msg): FakeSMTP.sent.append(msg)


class Fresh(unittest.TestCase):
    def setUp(self):
        self.saved = aj_config.DB
        aj_config.DB = os.path.join(tempfile.mkdtemp(), "t.db")
        aj_db.init_db()
        NtfyReceiver.posts.clear(); FakeSMTP.sent.clear()

    def tearDown(self):
        aj_config.DB = self.saved


class Config(Fresh):
    def test_defaults_and_secrets_hidden(self):
        cfg = aj_alerts.get_config()
        self.assertFalse(cfg["ntfy"]["enabled"])
        self.assertEqual(cfg["email"]["min_level"], "high")
        cfg["email"]["password"] = "hunter2"; cfg["ntfy"]["enabled"] = True
        aj_alerts.save_config(cfg)
        pub = aj_alerts.public_config()
        self.assertEqual(pub["email"]["password"], "")      # never sent to the browser
        self.assertTrue(pub["email"]["has_password"])
        self.assertTrue(pub["ntfy"]["enabled"])

    def test_summarize_marks_urgent(self):
        evs = [{"level": "high", "text": "Camera open"}, {"level": "medium", "text": "New device"}]
        title, body, pri = aj_alerts.summarize(evs)
        self.assertIn("urgent", title)
        self.assertEqual(pri, "high")
        self.assertIn("[!] Camera open", body)


class Ntfy(Fresh):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), NtfyReceiver)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close()

    def enable_ntfy(self, level="high"):
        cfg = aj_alerts.get_config()
        cfg["ntfy"].update(enabled=True, server=f"http://127.0.0.1:{self.port}", topic="home", min_level=level)
        aj_alerts.save_config(cfg)

    def test_dispatch_sends_once_then_dedups(self):
        self.enable_ntfy()
        aj_events.record("home", "camera_open", "high", "A camera plays with no password.")
        aj_events.record("home", "gone", "presence", "Phone offline.")
        sent = aj_alerts.dispatch("home", "Home")
        self.assertEqual(sent, {"ntfy": 1})               # the high one, not the presence one
        self.assertEqual(len(NtfyReceiver.posts), 1)
        self.assertEqual(NtfyReceiver.posts[0]["path"], "/home")
        self.assertIn("no password", NtfyReceiver.posts[0]["body"])
        self.assertEqual(NtfyReceiver.posts[0]["priority"], "high")
        self.assertEqual(aj_alerts.dispatch("home", "Home"), {})   # nothing new -> nothing sent
        self.assertEqual(len(NtfyReceiver.posts), 1)

    def test_level_filter_medium_not_sent_at_high(self):
        self.enable_ntfy("high")
        aj_events.record("home", "new_device", "medium", "New device joined.")
        self.assertEqual(aj_alerts.dispatch("home", "Home"), {})
        self.assertEqual(len(NtfyReceiver.posts), 0)
        # and because the watermark advanced, raising the level later won't re-send old ones
        self.enable_ntfy("medium")
        aj_events.record("home", "new_device", "medium", "Another new device.")
        aj_alerts.dispatch("home", "Home")
        self.assertEqual(len(NtfyReceiver.posts), 1)
        self.assertIn("Another new device", NtfyReceiver.posts[0]["body"])

    def test_test_send(self):
        self.enable_ntfy()
        ok, msg = aj_alerts.send_test("ntfy")
        self.assertTrue(ok)
        self.assertEqual(NtfyReceiver.posts[-1]["title"], "Test alert")


class Email(Fresh):
    def enable_email(self):
        cfg = aj_alerts.get_config()
        cfg["email"].update(enabled=True, host="smtp.example.com", port=587, user="me@example.com",
                            password="pw", to="me@example.com", min_level="high")
        aj_alerts.save_config(cfg)

    def test_email_built_and_sent(self):
        self.enable_email()
        aj_events.record("home", "router_changed", "high", "The router was replaced.")
        import aj.alerts as mod
        orig = mod.smtplib.SMTP
        mod.smtplib.SMTP = FakeSMTP
        try:
            sent = aj_alerts.dispatch("home", "Home")
        finally:
            mod.smtplib.SMTP = orig
        self.assertEqual(sent, {"email": 1})
        self.assertEqual(len(FakeSMTP.sent), 1)
        self.assertTrue(FakeSMTP.sent[0]["Subject"].startswith("Ajar: Home:"))
        self.assertIn("replaced", FakeSMTP.sent[0].get_content())


class Weekly(Fresh):
    def test_report_and_once_per_week(self):
        aj_db.set_net_setting("home", "score_history", [[time.time() - 6 * 86400, 70, False], [time.time(), 88, False]])
        now = time.time()
        aj_events.record("home", "new_device", "medium", "New device joined: a camera.", at=now - 3600)
        aj_events.record("home", "camera_open", "high", "A camera plays with no password.", at=now - 1800)
        title, body = aj_alerts.weekly_report("home", "Home", now)
        self.assertIn("(B)", title)
        self.assertIn("Security score: 88", body)
        self.assertIn("New devices: 1", body)
        self.assertIn("[!] A camera", body)

        cfg = aj_alerts.get_config()
        cfg["weekly"].update(enabled=True, day=time.localtime(now).tm_wday, hour=time.localtime(now).tm_hour,
                             ntfy=True, email=False)
        cfg["ntfy"].update(enabled=True, server="http://127.0.0.1:1", topic="x")  # will fail to send, but marks the week
        aj_alerts.save_config(cfg)
        aj_alerts.maybe_send_weekly("home", "Home", now)
        self.assertTrue(aj_db.net_setting("home", "weekly_sent"))
        # same week: does not compose/send again
        before = aj_db.net_setting("home", "weekly_sent")
        self.assertEqual(aj_alerts.maybe_send_weekly("home", "Home", now), [])
        self.assertEqual(aj_db.net_setting("home", "weekly_sent"), before)

    def test_not_due_off_schedule(self):
        now = time.time()
        cfg = aj_alerts.get_config()
        wrong_hour = (time.localtime(now).tm_hour + 1) % 24
        cfg["weekly"].update(enabled=True, day=time.localtime(now).tm_wday, hour=wrong_hour, email=True)
        aj_alerts.save_config(cfg)
        self.assertEqual(aj_alerts.maybe_send_weekly("home", "Home", now), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
