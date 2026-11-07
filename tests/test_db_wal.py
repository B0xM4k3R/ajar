import os
import tempfile
import threading
import unittest
from unittest import mock

import helpers  # noqa: F401
from aj import config, db


class TestWal(unittest.TestCase):
    def test_wal_and_concurrent_read_while_writing(self):
        path = os.path.join(tempfile.mkdtemp(), "w.db")
        with mock.patch.object(config, "DB", path):
            db.init_db()
            c = db.db()
            self.assertEqual(c.execute("PRAGMA journal_mode").fetchone()[0].lower(), "wal")
            c.close()
            w = db.db()
            w.execute("BEGIN IMMEDIATE")
            w.execute("INSERT INTO settings VALUES ('k','1')")
            seen = []
            t = threading.Thread(target=lambda: seen.append(db.get_setting("k", "none")))
            t.start(); t.join(5)  # a reader is not blocked by the open write
            self.assertFalse(t.is_alive())
            self.assertEqual(seen, ["none"])  # and sees only committed data
            w.commit(); w.close()
            self.assertEqual(db.get_setting("k"), 1)


if __name__ == "__main__":
    unittest.main()
