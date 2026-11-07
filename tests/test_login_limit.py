"""Through the real server: a burst of parallel wrong passwords must hit the lockout, and the
right password must keep working (and be remembered) for someone who isn't locked out."""
import base64
import http.client
import threading
import unittest

import helpers  # noqa: F401
from aj import auth as authlib
from aj import web as aj_web


def basic(pw):
    return "Basic " + base64.b64encode(f"u:{pw}".encode()).decode()


class LoginLimit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.saved = dict(authlib.auth)
        authlib.auth["hash"] = authlib.hash_pw("right-password")
        cls.server = aj_web.Server(("127.0.0.1", 0), aj_web.Handler)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close()
        authlib.auth.update(cls.saved)

    def get(self, hdr):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        c.request("GET", "/api/ping" if False else "/app.css", headers={"Host": "localhost", "Authorization": hdr})
        r = c.getresponse(); r.read(); c.close()
        return r.status

    def test_parallel_wrong_passwords_are_capped_then_locked(self):
        authlib.fails.clear(); authlib.good_auth.clear()
        codes, barrier = [], threading.Barrier(15)

        def guess(i):
            barrier.wait()
            codes.append(self.get(basic(f"wrong{i}")))

        ts = [threading.Thread(target=guess, args=(i,)) for i in range(15)]
        [t.start() for t in ts]; [t.join() for t in ts]
        self.assertEqual(codes.count(401), authlib.LOCK_AFTER, codes)  # only 5 guesses were ever checked
        self.assertEqual(codes.count(429), 15 - authlib.LOCK_AFTER, codes)
        self.assertEqual(self.get(basic("right-password")), 429)  # locked out, even with the right one

    def test_right_password_works_and_is_remembered(self):
        authlib.fails.clear(); authlib.good_auth.clear()
        self.assertEqual(self.get(basic("right-password")), 200)
        self.assertEqual(len(authlib.good_auth), 1)
        self.assertEqual(self.get(basic("right-password")), 200)
        self.assertFalse(authlib.fails)  # a correct login leaves nothing counted against the address


if __name__ == "__main__":
    unittest.main()
