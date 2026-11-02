"""What the router opens to the internet, asked through UPnP (read-only).

Apps and devices can ask a router with UPnP on to open ports to the internet, without
asking you: game consoles, media servers, cameras. Routers list these openings through
the same standard interface, so ajar asks for the list. It never adds or removes one.

Two limits, said plainly on the dashboard:
  - Port forwards set up by hand in the router's settings usually don't show here.
  - If the router's own internet address is private (a second router, or the provider's
    shared addressing), the ports it opens probably don't reach the internet at all.
"""
import ipaddress
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from urllib.parse import urljoin, urlparse

from .audit import IOT_PORT_NAMES, PORT_NAMES
from .db import db, net_setting, set_net_setting
from .events import device_label, record

WAN_SERVICES = ("WANIPConnection", "WANPPPConnection")
MAX_ENTRIES = 256

# Services that should never be reachable from the internet.
RISKY_PORTS = {21, 22, 23, 2323, 111, 135, 139, 445, 548, 554, 1433, 1883, 2049, 3306, 3389, 5432,
               5555, 5900, 6379, 6668, 8554, 9100, 9999, 27017}
WEB_PORTS = {80, 443, 8000, 8080, 8443, 8888}
SMART_KINDS = {"iot", "tv", "printer", "router"}  # their web pages are admin pages
INTERNET_PORT_NAMES = {
    3074: "Xbox Live", 3075: "Xbox Live", 3478: "PlayStation/Xbox (STUN)", 3479: "PlayStation",
    3480: "PlayStation", 9308: "PlayStation", 32400: "Plex", 25565: "Minecraft", 27015: "Steam game server",
    51413: "BitTorrent", 6881: "BitTorrent", 500: "VPN (IKE)", 4500: "VPN (IPsec)", 1194: "OpenVPN",
    51820: "WireGuard VPN", 1935: "Video streaming (RTMP)", 5060: "Phone (SIP)",
}
CGNAT = ipaddress.ip_network("100.64.0.0/10")
PRIVATE = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


class UpnpError(Exception):
    def __init__(self, code, text=""):
        super().__init__(f"UPnP error {code} {text}".strip())
        self.code = code


def local(tag):
    return tag.rsplit("}", 1)[-1]


def http(url, data=None, headers=None, timeout=3, limit=200000):
    """GET or POST without any proxy. Returns (status, body)."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    req = urllib.request.Request(url, data=data, headers=headers or {}, method="POST" if data else "GET")
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, r.read(limit).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(limit).decode("utf-8", "replace")


def find_igd(ssdp, gateway=None):
    """The router's UPnP description URL from an SSDP scan, preferring the gateway."""
    hits = []
    for ip, d in ssdp.items():
        sts = d.get("locs") or {s: d.get("loc") for s in d.get("st", ())}
        for st, loc in sts.items():
            if loc and ("InternetGatewayDevice" in st or any(w in st for w in WAN_SERVICES)):
                hits.append((ip != gateway, "InternetGatewayDevice" not in st, ip, loc))
    hits.sort()
    return (hits[0][2], hits[0][3]) if hits else (None, None)


def wan_service(ip, loc):
    """Reads the router's description and returns (service type, control URL) for its
    internet connection, or (None, None). Only follows URLs on the router itself."""
    u = urlparse(loc)
    if u.scheme != "http" or u.hostname != ip:
        return None, None
    status, body = http(loc)
    if status != 200:
        return None, None
    root = ET.fromstring(body)
    base = next((e.text.strip() for e in root.iter() if local(e.tag) == "URLBase" and e.text), loc)
    found = []
    for svc in root.iter():
        if local(svc.tag) != "service":
            continue
        fields = {local(e.tag): (e.text or "").strip() for e in svc}
        st, ctl = fields.get("serviceType", ""), fields.get("controlURL", "")
        if ctl and any(w in st for w in WAN_SERVICES):
            url = urljoin(base, ctl)
            cu = urlparse(url)
            if cu.scheme == "http" and cu.hostname == ip:
                found.append((not st.startswith("urn:schemas-upnp-org:service:WANIPConnection"), st, url))
    found.sort()
    return (found[0][1], found[0][2]) if found else (None, None)


def soap(url, service, action, args=None):
    """Calls one UPnP action and returns its result fields, or raises UpnpError."""
    params = "".join(f"<{k}>{v}</{k}>" for k, v in (args or {}).items())
    body = ('<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
            's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
            f'<u:{action} xmlns:u="{service}">{params}</u:{action}></s:Body></s:Envelope>')
    status, text = http(url, body.encode(), {"Content-Type": 'text/xml; charset="utf-8"',
                                            "SOAPAction": f'"{service}#{action}"'})
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        raise UpnpError(status, "unreadable reply")
    if status != 200:
        code = next((e.text for e in root.iter() if local(e.tag) == "errorCode"), str(status))
        desc = next((e.text for e in root.iter() if local(e.tag) == "errorDescription"), "")
        raise UpnpError(int(code) if str(code).isdigit() else status, desc or "")
    resp = next((e for e in root.iter() if local(e.tag) == action + "Response"), None)
    return {local(e.tag): (e.text or "").strip() for e in (resp if resp is not None else [])}


def address_kind(ip):
    """public, private (behind another router), cgnat (provider's shared address), or unknown."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "unknown"
    if a in CGNAT:
        return "cgnat"
    if any(a in n for n in PRIVATE):
        return "private"
    return "public" if a.version == 4 and not a.is_unspecified else "unknown"


def list_mappings(url, service):
    out = []
    for i in range(MAX_ENTRIES):
        try:
            r = soap(url, service, "GetGenericPortMappingEntry", {"NewPortMappingIndex": i})
        except UpnpError as e:
            if i == 0 and e.code not in (713, 714, 402, 500):
                raise
            break  # 713 SpecifiedArrayIndexInvalid: the end of the list
        try:
            out.append({
                "proto": (r.get("NewProtocol") or "").upper(),
                "ext": int(r.get("NewExternalPort") or 0),
                "port": int(r.get("NewInternalPort") or 0),
                "client": r.get("NewInternalClient") or "",
                "enabled": (r.get("NewEnabled") or "1").strip() not in ("0", "false"),
                "desc": (r.get("NewPortMappingDescription") or "")[:80],
                "lease": int(r.get("NewLeaseDuration") or 0),
                "remote": r.get("NewRemoteHost") or "",
            })
        except ValueError:
            continue
    return out


def check(ssdp, gateway=None):
    """Asks the router what it opens to the internet. Always returns a result dict:
    status is "listed", "no_upnp" (router doesn't answer UPnP) or "error"."""
    result = {"checked": time.time(), "status": "no_upnp", "mappings": [], "wan": "unknown",
              "router": None, "service": None}
    ip, loc = find_igd(ssdp, gateway)
    if not ip:
        return result
    result["router"] = ip
    try:
        service, url = wan_service(ip, loc)
        if not url:
            result.update(status="error", error="The router answers UPnP but doesn't list its internet "
                                                "connection, so its open ports can't be read.")
            return result
        result["service"] = service.split(":")[-2] if service.count(":") >= 2 else service
        try:
            result["wan"] = address_kind(soap(url, service, "GetExternalIPAddress").get("NewExternalIPAddress", ""))
        except UpnpError:
            pass
        result["mappings"] = list_mappings(url, service)
        result["status"] = "listed"
    except (OSError, ET.ParseError, UpnpError) as e:
        result.update(status="error", error=f"The router's UPnP didn't answer properly ({e}).")
    return result


def port_name(port):
    return INTERNET_PORT_NAMES.get(port) or IOT_PORT_NAMES.get(port) or PORT_NAMES.get(port) or ""


def view(result, devices):
    """Adds what ajar knows to each opening: which device, what service, and whether
    it's risky. devices are this network's rows (dicts with ip, kind, name...)."""
    from .events import device_label
    if not result:
        return None
    by_ip = {d.get("ip"): d for d in devices}
    reachable = result.get("wan") not in ("private", "cgnat")
    out = dict(result, reachable=reachable, mappings=[])
    for m in result.get("mappings", []):
        d = by_ip.get(m["client"])
        kind = (d or {}).get("kind")
        risky = m["port"] in RISKY_PORTS or (kind in SMART_KINDS and m["port"] in WEB_PORTS)
        out["mappings"].append(dict(m, device=device_label(d) if d else m["client"], known=bool(d),
                                    service=port_name(m["port"]), risky=risky))
    out["mappings"].sort(key=lambda m: (not m["risky"], not m["enabled"], m["ext"]))
    return out


def key(m):
    return f"{m['proto']}:{m['ext']}:{m['client']}:{m['port']}"


def changes(before, after, devices):
    """Openings that appeared or went away since the last check. The first check is a
    quiet baseline. Risky openings are High; others are Info, because game consoles and
    media servers open and close ports all the time."""
    if not before or before.get("status") != "listed" or not after or after.get("status") != "listed":
        return []
    b = {key(m): m for m in view(before, devices)["mappings"] if m["enabled"]}
    a = {key(m): m for m in view(after, devices)["mappings"] if m["enabled"]}
    out = []
    for k, m in a.items():
        if k not in b:
            what = f"{m['proto']} {m['ext']}" + (f" ({m['service']})" if m["service"] else "")
            if m["risky"] and after.get("wan") not in ("private", "cgnat"):
                out.append(("internet_opened", "high", f"The router opened {what} to the internet for {m['device']}. "
                            "Anyone on the internet can now try to connect to it."))
            else:
                out.append(("internet_opened", "info", f"The router opened {what} to the internet for {m['device']}."))
    for k, m in b.items():
        if k not in a:
            out.append(("internet_closed", "info", f"The router closed {m['proto']} {m['ext']} "
                        f"to the internet for {m['device']}."))
    return out


def devices_of(net):
    c = db()
    rows = [dict(r) for r in c.execute("SELECT mac, ip, kind, name, hostname, vendor FROM devices WHERE net=?", (net,))]
    c.close()
    return rows


def run(net, ssdp, gateway=None):
    """The services check's last step: ask the router, save the answer for this network,
    and record what changed."""
    result = check(ssdp, gateway)
    before = net_setting(net, "exposure")
    if result["status"] == "error" and before and before.get("status") == "listed":
        result["mappings"] = before["mappings"]  # keep the last good list rather than show nothing
        result["stale"] = True
    devs = devices_of(net)
    for kind, level, text in changes(before, result, devs):
        record(net, kind, level, text)
    set_net_setting(net, "exposure", result)
    return result
