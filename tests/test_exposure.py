"""What the router opens to the internet: asked from a fake router that speaks real UPnP."""
import os
import re
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import helpers  # sets up the import path and a throwaway database
from helpers import dev
from aj import config as aj_config
from aj import db as aj_db
from aj import events as aj_events
from aj import exposure as aj_exposure
from aj import score as aj_score

DESC = """<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0"><device>
  <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
  <deviceList><device><deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
    <deviceList><device><deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
      <serviceList><service>
        <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
        <controlURL>{ctl}</controlURL>
      </service></serviceList>
    </device></deviceList></device></deviceList>
</device></root>"""

ENTRY = """<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>
<u:GetGenericPortMappingEntryResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
<NewRemoteHost></NewRemoteHost><NewExternalPort>{ext}</NewExternalPort><NewProtocol>{proto}</NewProtocol>
<NewInternalPort>{port}</NewInternalPort><NewInternalClient>{client}</NewInternalClient>
<NewEnabled>{enabled}</NewEnabled><NewPortMappingDescription>{desc}</NewPortMappingDescription>
<NewLeaseDuration>0</NewLeaseDuration></u:GetGenericPortMappingEntryResponse></s:Body></s:Envelope>"""

FAULT = """<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>
<s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail>
<UPnPError xmlns="urn:schemas-upnp-org:control-1-0"><errorCode>713</errorCode>
<errorDescription>SpecifiedArrayIndexInvalid</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>"""

EXT_IP = """<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>
<u:GetExternalIPAddressResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
<NewExternalIPAddress>{ip}</NewExternalIPAddress></u:GetExternalIPAddressResponse></s:Body></s:Envelope>"""


class FakeRouter(BaseHTTPRequestHandler):
    mappings = []
    external_ip = "73.12.34.56"
    ctl = "/ctl/IPConn"

    def log_message(self, *a):
        pass

    def reply(self, code, body):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/xml")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self.reply(200, DESC.format(ctl=self.ctl)) if self.path == "/desc.xml" else self.reply(404, "")

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
        action = self.headers.get("SOAPAction", "").strip('"').split("#")[-1]
        if action == "GetExternalIPAddress":
            return self.reply(200, EXT_IP.format(ip=self.external_ip))
        if action == "GetGenericPortMappingEntry":
            i = int(re.search(r"<NewPortMappingIndex>(\d+)<", body).group(1))
            if i < len(self.mappings):
                return self.reply(200, ENTRY.format(**self.mappings[i]))
            return self.reply(500, FAULT)
        self.reply(500, FAULT)


def mapping(ext, port, client, proto="TCP", enabled=1, desc="test"):
    return {"ext": ext, "port": port, "client": client, "proto": proto, "enabled": enabled, "desc": desc}


DEVICES = [dict(dev("192.168.1.30"), name="Office PC", kind="personal"),
           dict(dev("192.168.1.40"), name="Xbox", kind="other"),
           dict(dev("192.168.1.20"), name="Garage camera", kind="iot")]


class Router(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), FakeRouter)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        self.saved_db = aj_config.DB
        aj_config.DB = os.path.join(tempfile.mkdtemp(), "t.db")
        aj_db.init_db()
        FakeRouter.mappings, FakeRouter.external_ip, FakeRouter.ctl = [], "73.12.34.56", "/ctl/IPConn"

    def tearDown(self):
        aj_config.DB = self.saved_db

    def ssdp(self):
        return {"127.0.0.1": {"st": {"urn:schemas-upnp-org:device:InternetGatewayDevice:1"},
                              "loc": f"http://127.0.0.1:{self.port}/desc.xml",
                              "locs": {"urn:schemas-upnp-org:device:InternetGatewayDevice:1":
                                       f"http://127.0.0.1:{self.port}/desc.xml"}}}

    def test_lists_what_the_router_opens(self):
        FakeRouter.mappings = [mapping(3389, 3389, "192.168.1.30", desc="RDP"),
                               mapping(3074, 3074, "192.168.1.40", proto="UDP", desc="Xbox"),
                               mapping(8080, 80, "192.168.1.20", enabled=0)]
        r = aj_exposure.check(self.ssdp(), "127.0.0.1")
        self.assertEqual((r["status"], r["wan"], r["service"]), ("listed", "public", "WANIPConnection"))
        self.assertEqual([(m["proto"], m["ext"], m["client"], m["enabled"]) for m in r["mappings"]],
                         [("TCP", 3389, "192.168.1.30", True), ("UDP", 3074, "192.168.1.40", True),
                          ("TCP", 8080, "192.168.1.20", False)])
        v = aj_exposure.view(r, DEVICES)
        self.assertEqual([(m["device"], m["risky"], m["service"]) for m in v["mappings"]],
                         [("Office PC", True, "Remote Desktop"), ("Garage camera", True, "Web (HTTP)"),
                          ("Xbox", False, "Xbox Live")])

    def test_no_upnp(self):
        self.assertEqual(aj_exposure.check({}, "192.168.1.1")["status"], "no_upnp")

    def test_refuses_to_follow_a_control_url_to_another_host(self):
        FakeRouter.ctl = "http://203.0.113.9/ctl"
        r = aj_exposure.check(self.ssdp(), "127.0.0.1")
        self.assertEqual(r["status"], "error")
        self.assertEqual(r["mappings"], [])

    def test_double_nat_is_not_counted_as_internet_exposure(self):
        FakeRouter.external_ip = "192.168.0.15"
        FakeRouter.mappings = [mapping(3389, 3389, "192.168.1.30")]
        r = aj_exposure.check(self.ssdp(), "127.0.0.1")
        self.assertEqual(r["wan"], "private")
        rep = aj_score.security_report(DEVICES, None, exposure=r)
        self.assertFalse(any(i["id"].startswith("internet_") for i in rep["issues"]))
        self.assertFalse(rep["exposure"]["reachable"])
        self.assertEqual(aj_exposure.address_kind("100.70.1.2"), "cgnat")

    def test_score(self):
        FakeRouter.mappings = [mapping(3389, 3389, "192.168.1.30")] + \
            [mapping(p, p, "192.168.1.40", proto="UDP") for p in (3074, 3075, 3478, 3479)]
        rep = aj_score.security_report(DEVICES, None, exposure=aj_exposure.check(self.ssdp(), "127.0.0.1"))
        issues = {i["id"]: i for i in rep["issues"]}
        self.assertEqual(issues["internet_risky"]["points"], 30)
        self.assertEqual(issues["internet_risky"]["title"], "Close TCP 3389 (Remote Desktop) to the internet for Office PC")
        self.assertEqual(issues["internet_open"]["points"], 9)  # 3 each, up to 9
        check = next(c for c in rep["checks"] if "internet" in c["label"])
        self.assertEqual(check["status"], "fail")

    def test_checks_pass_without_upnp_and_are_unknown_before_any_check(self):
        rep = aj_score.security_report(DEVICES, None, exposure={"status": "no_upnp", "mappings": []})
        self.assertEqual(next(c for c in rep["checks"] if "internet" in c["label"])["status"], "pass")
        rep = aj_score.security_report(DEVICES, None)
        self.assertEqual(next(c for c in rep["checks"] if "internet" in c["label"])["status"], "unknown")

    def test_changes_and_keeping_the_last_good_list(self):
        c = aj_db.db()
        for d in DEVICES:
            c.execute("INSERT INTO devices (net, mac, ip, name, kind) VALUES ('home',?,?,?,?)",
                      (d["mac"], d["ip"], d["name"], d["kind"]))
        c.commit()
        c.close()
        FakeRouter.mappings = [mapping(3074, 3074, "192.168.1.40", proto="UDP")]
        aj_exposure.run("home", self.ssdp(), "127.0.0.1")                      # baseline: quiet
        self.assertEqual(aj_events.recent("home"), [])
        FakeRouter.mappings = [mapping(3389, 3389, "192.168.1.30"), mapping(32400, 32400, "192.168.1.40")]
        aj_exposure.run("home", self.ssdp(), "127.0.0.1")
        ev = sorted((e["level"], e["text"]) for e in aj_events.recent("home"))
        self.assertEqual([lvl for lvl, _ in ev], ["high", "info", "info"])
        self.assertIn("opened TCP 3389 (Remote Desktop) to the internet for Office PC", ev[0][1])
        self.assertTrue(any("closed UDP 3074" in t for _, t in ev))
        FakeRouter.ctl = "http://203.0.113.9/ctl"                               # router misbehaves
        r = aj_exposure.run("home", self.ssdp(), "127.0.0.1")
        self.assertEqual((r["status"], r.get("stale"), len(r["mappings"])), ("error", True, 2))


if __name__ == "__main__":
    unittest.main(verbosity=2)
