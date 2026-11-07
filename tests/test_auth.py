import os
import stat
import tempfile
import threading
import unittest
from unittest import mock

import helpers  # noqa: F401
from aj import auth, config


def _read(path):
    with open(path) as f:
        return f.read().strip()


class TestAttempts(unittest.TestCase):
    def setUp(self):
        auth.fails.clear(); auth.good_auth.clear()

    def test_parallel_guesses_cannot_beat_the_limit(self):
        # Before the fix every thread checked the count first and recorded failures afterwards,
        # so a burst all got through. Reserving the attempt up front caps the burst.
        tokens, barrier = [], threading.Barrier(40)

        def guess():
            barrier.wait()
            tokens.append(auth.reserve_attempt("10.0.0.9"))

        ts = [threading.Thread(target=guess) for _ in range(40)]
        [t.start() for t in ts]; [t.join() for t in ts]
        self.assertEqual(sum(t is not None for t in tokens), auth.LOCK_AFTER)
        self.assertTrue(auth.is_locked("10.0.0.9"))

    def test_correct_password_does_not_count(self):
        t = auth.reserve_attempt("10.0.0.1")
        auth.release_attempt("10.0.0.1", t)
        self.assertFalse(auth.is_locked("10.0.0.1"))
        self.assertNotIn("10.0.0.1", auth.fails)

    def test_lock_expires_and_leaves_no_entry(self):
        for i in range(auth.LOCK_AFTER):
            auth.reserve_attempt("10.0.0.2", now=1000.0 + i)
        self.assertTrue(auth.is_locked("10.0.0.2", now=1010.0))
        self.assertFalse(auth.is_locked("10.0.0.2", now=1000.0 + auth.LOCK_WINDOW + 10))
        self.assertNotIn("10.0.0.2", auth.fails)

    def test_other_addresses_unaffected(self):
        for _ in range(auth.LOCK_AFTER):
            auth.reserve_attempt("10.0.0.3")
        self.assertFalse(auth.is_locked("10.0.0.4"))


class TestGoodCache(unittest.TestCase):
    def setUp(self):
        auth.good_auth.clear()

    def test_expires(self):
        auth.remember("k", now=1000.0)
        self.assertTrue(auth.is_good("k", now=1000.0 + auth.GOOD_TTL - 1))
        self.assertFalse(auth.is_good("k", now=1000.0 + auth.GOOD_TTL + 1))
        self.assertNotIn("k", auth.good_auth)

    def test_is_capped(self):
        for i in range(auth.GOOD_MAX + 50):
            auth.remember(f"k{i}", now=1000.0 + i)
        self.assertLessEqual(len(auth.good_auth), auth.GOOD_MAX)
        self.assertTrue(auth.is_good(f"k{auth.GOOD_MAX + 49}", now=1000.0 + auth.GOOD_MAX + 49))  # newest kept

    def test_forget_all(self):
        auth.remember("k"); auth.forget_all()
        self.assertFalse(auth.is_good("k"))


@unittest.skipIf(os.name == "nt", "POSIX permissions")
class TestPasswordFile(unittest.TestCase):
    def test_private_from_creation(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "ajar.auth")
        with mock.patch.object(config, "AUTH_FILE", path), mock.patch.object(auth, "prompt_password", lambda: "correct horse"), \
                mock.patch("sys.stdin.isatty", return_value=True), mock.patch("sys.argv", ["ajar.py", "--set-password"]):
            with self.assertRaises(SystemExit):
                auth.setup_auth()
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        self.assertTrue(auth.check_pw("correct horse", _read(path)))


if __name__ == "__main__":
    unittest.main()
