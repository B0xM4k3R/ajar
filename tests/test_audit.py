"""Services check: the deep check's handling of nmap results."""
import unittest

import helpers  # sets up the import path and a throwaway database
from aj import audit as aj_audit


DEEP_XML = """<nmaprun>
<host><status state="up" reason="user-set"/><address addr="192.168.1.93" addrtype="ipv4"/>
  <ports><extraports state="closed" count="10000"/></ports></host>
<host><status state="up" reason="user-set"/><address addr="192.168.1.50" addrtype="ipv4"/>
  <ports><extraports state="closed" count="9998"/>
    <port protocol="tcp" portid="1883"><state state="open"/><service name="mqtt"/></port>
    <port protocol="tcp" portid="4321"><state state="open"/><service name="rwhois"/></port>
    <port protocol="tcp" portid="22"><state state="closed"/></port></ports></host>
<host><status state="up" reason="user-set"/><address addr="192.168.1.60" addrtype="ipv4"/></host>
</nmaprun>"""


class Deep(unittest.TestCase):
    def test_clean_devices_are_marked_checked(self):
        import xml.etree.ElementTree as ET
        res = {ip: {"ports": [], "shares": [], "ftp_anon": False, "nfs": []}
               for ip in ("192.168.1.93", "192.168.1.50", "192.168.1.60")}
        done = aj_audit.merge_deep(ET.fromstring(DEEP_XML), res)
        self.assertEqual(done, {"192.168.1.93", "192.168.1.50"})
        self.assertEqual(res["192.168.1.93"]["depth"], "deep")   # clean, but checked
        self.assertNotIn("depth", res["192.168.1.60"])          # timed out: no result
        self.assertEqual([(p["port"], p["name"]) for p in res["192.168.1.50"]["ports"]],
                         [(1883, "MQTT (unencrypted)"), (4321, "rwhois")])


class Reuse(unittest.TestCase):
    def test_week_old_results_are_reused_new_devices_are_not(self):
        now = 1_000_000
        prev = {"a": {"deep_at": now - 3 * 86400}, "b": {"deep_at": now - 8 * 86400}, "c": {}}
        due, reuse = aj_audit.plan_reuse(["a", "b", "c", "d"], prev, "deep_at", now)
        self.assertEqual((due, reuse), (["b", "c", "d"], ["a"]))

    def test_full_check_redoes_everything(self):
        now = 1_000_000
        due, reuse = aj_audit.plan_reuse(["a"], {"a": {"deep_at": now - 60}}, "deep_at", now, force=True)
        self.assertEqual((due, reuse), (["a"], []))


if __name__ == "__main__":
    unittest.main(verbosity=2)
