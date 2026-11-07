import time
import unittest
from unittest import mock

import helpers  # noqa: F401
from aj import config, jobs, schedule

ON = {"enabled": True, "scan_min": 15, "audit_hours": 24}


class TestDue(unittest.TestCase):
    def test_off_by_default(self):
        self.assertFalse(schedule.get_schedule()["enabled"])
        self.assertIsNone(schedule.due(1e9, None, None, {}, schedule.get_schedule()))

    def test_scan_then_audit(self):
        now = 1_000_000.0
        self.assertEqual(schedule.due(now, now - 16 * 60, now - 3600, {}, ON), "scan")
        self.assertIsNone(schedule.due(now, now - 14 * 60, now - 3600, {}, ON))
        self.assertEqual(schedule.due(now, now - 60, now - 25 * 3600, {}, ON), "audit")  # audit wins

    def test_never_scanned_is_due_now(self):
        self.assertEqual(schedule.due(1e9, None, None, {}, ON), "audit")

    def test_a_failed_attempt_waits_a_full_interval(self):
        now = 1_000_000.0
        tries = {"scan": now - 60}  # started a minute ago, never recorded as finished
        self.assertIsNone(schedule.due(now, None, now - 3600, tries, ON))
        self.assertEqual(schedule.due(now, None, now - 3600, {"scan": now - 16 * 60}, ON), "scan")


class TestSettings(unittest.TestCase):
    def test_clamped_and_saved(self):
        cfg = schedule.save_schedule({"enabled": True, "scan_min": 1, "audit_hours": 100000})
        self.assertEqual(cfg, {"enabled": True, "scan_min": 5, "audit_hours": 168})
        self.assertEqual(schedule.get_schedule(), cfg)
        self.assertEqual(schedule.save_schedule({"scan_min": "abc"})["scan_min"], 15)
        schedule.save_schedule({"enabled": False})

    def test_ignores_unknown_keys_and_junk(self):
        schedule.save_schedule({"enabled": False})
        self.assertEqual(schedule.save_schedule({"evil": 1, "enabled": "yes"})["enabled"], True)
        schedule.save_schedule({"enabled": False})


class TestTick(unittest.TestCase):
    def setUp(self):
        jobs._tries.clear()
        self.saved = {k: config.state.get(k) for k in ("scanning", "last_scan", "last_audit", "net")}
        config.state.update(scanning=False, last_scan=None, last_audit=None, net=None)
        schedule.save_schedule({"enabled": True, "scan_min": 15, "audit_hours": 24})

    def tearDown(self):
        schedule.save_schedule({"enabled": False})
        config.state.update(self.saved)

    def test_starts_an_audit_then_waits(self):
        calls = []
        start = lambda deep: calls.append(deep) or True
        self.assertEqual(jobs.schedule_tick(1e9, start), "audit")
        self.assertEqual(jobs.schedule_tick(1e9 + 30, start), None)  # not again 30 seconds later
        self.assertEqual(calls, [True])

    def test_quick_sweep_between_audits(self):
        config.state.update(last_audit=1e9 - 3600, last_scan=1e9 - 20 * 60)
        calls = []
        self.assertEqual(jobs.schedule_tick(1e9, lambda deep: calls.append(deep) or True), "scan")
        self.assertEqual(calls, [False])

    def test_never_starts_during_a_scan_or_when_off(self):
        config.state["scanning"] = True
        self.assertIsNone(jobs.schedule_tick(1e9, lambda deep: self.fail("started during a scan")))
        config.state["scanning"] = False
        schedule.save_schedule({"enabled": False})
        self.assertIsNone(jobs.schedule_tick(1e9, lambda deep: self.fail("started while off")))

    def test_if_the_scan_could_not_start_nothing_is_reported(self):
        self.assertIsNone(jobs.schedule_tick(1e9, lambda deep: False))  # lock was held

    def test_weekly_report_is_checked_on_each_tick(self):
        config.state["net"] = "nx"
        with mock.patch.object(jobs.alerts, "maybe_send_weekly") as w, mock.patch.object(jobs, "net_name", lambda n: "Home"):
            jobs.schedule_tick(1e9, lambda deep: True)
        w.assert_called_once_with("nx", "Home", 1e9)


if __name__ == "__main__":
    unittest.main()
