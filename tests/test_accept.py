import json
import unittest

import helpers  # noqa: F401
from aj import accept, score
from aj.db import set_net_setting

NET = "nacc"
CAM = {"mac": "aa:bb:cc:00:00:01", "ip": "192.168.1.20", "name": "Garage camera", "kind": "iot", "online": 1, "approved": 1,
       "audit": {"ports": [{"port": 23, "name": "Telnet"}], "shares": [], "info": {}}}
PC = {"mac": "aa:bb:cc:00:00:02", "ip": "192.168.1.30", "hostname": "office-pc", "kind": "personal", "online": 1, "approved": 0,
      "audit": {"ports": [], "shares": [], "info": {}}}


def report(**kw):
    return score.security_report([dict(CAM), dict(PC)], None, net=None, **kw)


class Accept(unittest.TestCase):
    def setUp(self):
        set_net_setting(NET, "accepted", [])

    def test_unaccepted_baseline(self):
        r = report()
        self.assertIn("telnet", {i["id"] for i in r["issues"]})
        self.assertEqual(r["accepted"], [])

    def test_accepting_removes_it_from_score_and_lists_it(self):
        before = report()["score"]
        accept.accept(NET, CAM["mac"], "telnet", "can't update this camera", known_ids=set(score.FIXES))
        r = report(accepted=accept.get(NET))
        self.assertNotIn("telnet", {i["id"] for i in r["issues"]})
        self.assertEqual(r["score"], before + score.SCORE_POINTS["telnet"])
        self.assertEqual([(a["id"], a["reason"]) for a in r["accepted"]], [("telnet", "can't update this camera")])
        telnet_check = next(c for c in r["checks"] if c["label"].startswith("Telnet"))
        self.assertEqual(telnet_check["status"], "pass")

    def test_acceptance_is_per_device(self):
        other = {**CAM, "mac": "aa:bb:cc:00:00:99", "ip": "192.168.1.21", "name": "Porch camera"}
        accept.accept(NET, CAM["mac"], "telnet")
        r = score.security_report([dict(CAM), other], None, accepted=accept.get(NET))
        self.assertEqual([i["who"] for i in r["issues"] if i["id"] == "telnet"], ["Porch camera"])

    def test_network_wide_item_can_be_accepted(self):
        self.assertIn("unapproved", {i["id"] for i in report()["issues"]})
        accept.accept(NET, "net", "unapproved")
        r = report(accepted=accept.get(NET))
        self.assertNotIn("unapproved", {i["id"] for i in r["issues"]})  # and the points edit didn't hit another issue
        self.assertIn("telnet", {i["id"] for i in r["issues"]})
        self.assertEqual(next(i for i in r["issues"] if i["id"] == "telnet")["points"], score.SCORE_POINTS["telnet"])

    def test_undo(self):
        accept.accept(NET, CAM["mac"], "telnet")
        self.assertTrue(accept.unaccept(NET, CAM["mac"], "telnet"))
        self.assertFalse(accept.unaccept(NET, CAM["mac"], "telnet"))
        self.assertIn("telnet", {i["id"] for i in report(accepted=accept.get(NET))["issues"]})

    def test_refuses_junk_and_replaces_duplicates(self):
        self.assertFalse(accept.accept(NET, CAM["mac"], "not_a_real_finding", known_ids=set(score.FIXES)))
        self.assertFalse(accept.accept(NET, "", "telnet"))
        accept.accept(NET, CAM["mac"], "telnet", "first")
        accept.accept(NET, CAM["mac"], "telnet", "second")
        self.assertEqual([i["reason"] for i in accept.get(NET)], ["second"])

    def test_through_the_api_and_device_rows(self):
        import http.client, threading
        from aj import web
        from aj.db import db
        import time
        c = db()
        c.execute("DELETE FROM devices"); c.execute("DELETE FROM networks")
        c.execute("INSERT INTO networks (id, name, gateway_mac, gateway_ip, subnet, first_seen, last_seen) VALUES (?,?,?,?,?,?,?)",
                  (NET, "T", "aa:aa:aa:aa:aa:aa", "192.168.1.1", "192.168.1.0/24", 1, 1))
        c.execute("INSERT INTO devices (net, mac, ip, kind, first_seen, last_seen, approved, online, audit) VALUES (?,?,?,?,?,?,1,1,?)",
                  (NET, CAM["mac"], CAM["ip"], "iot", 1, time.time(), json.dumps(CAM["audit"])))
        c.commit(); c.close()
        server = web.Server(("127.0.0.1", 0), web.Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()

        def call(method, path, body=None):
            h = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=20)
            h.request(method, path, json.dumps(body) if body else None,
                      {"Host": "localhost", "X-Ajar": "1", "Content-Type": "application/json"})
            r = h.getresponse(); data = r.read(); h.close()
            return json.loads(data)
        try:
            call("POST", f"/api/settings?net={NET}", {"accept": {"mac": CAM["mac"], "id": "telnet", "reason": "isolated VLAN"}})
            snap = call("GET", f"/api/state?net={NET}")
            self.assertEqual(snap["devices"][0]["accepted"], ["telnet"])
            self.assertEqual(snap["security"]["accepted"][0]["reason"], "isolated VLAN")
            self.assertNotIn("telnet", {i["id"] for i in snap["security"]["issues"]})
            call("POST", f"/api/settings?net={NET}", {"accept": {"mac": CAM["mac"], "id": "bogus"}})  # junk is refused
            self.assertEqual(len(call("GET", f"/api/state?net={NET}")["security"]["accepted"]), 1)
            call("POST", f"/api/settings?net={NET}", {"unaccept": {"mac": CAM["mac"], "id": "telnet"}})
            self.assertEqual(call("GET", f"/api/state?net={NET}")["devices"][0]["accepted"], [])
        finally:
            server.shutdown(); server.server_close()


if __name__ == "__main__":
    unittest.main()
