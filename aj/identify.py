"""Asks devices to describe themselves: UPnP, Bonjour (mDNS) and Samsung's TV API."""
import json
import re
import socket
import struct
import time
import xml.etree.ElementTree as ET
from urllib.parse import parse_qs, urlparse

from .tools import fetch


def ssdp_scan(own_ip=None, wait=3):
    """Finds UPnP devices (including routers with UPnP on and media servers).
    Returns {ip: {"st": set of service types, "loc": first description URL or None,
    "locs": {service type: description URL}}}."""
    search = lambda st: ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
                         f"MAN: \"ssdp:discover\"\r\nMX: 2\r\nST: {st}\r\n\r\n").encode()
    found = {}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.settimeout(1)
    try:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        if own_ip:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(own_ip))
        s.sendto(search("ssdp:all"), ("239.255.255.250", 1900))
        # Some routers only answer a search for exactly what they are.
        s.sendto(search("urn:schemas-upnp-org:device:InternetGatewayDevice:1"), ("239.255.255.250", 1900))
        end = time.time() + wait
        while time.time() < end:
            try:
                data, (ip, _) = s.recvfrom(65507)
            except socket.timeout:
                continue
            text = data.decode("utf-8", "replace")
            st = re.search(r"^ST:\s*(.+)$", text, re.I | re.M)
            loc = re.search(r"^LOCATION:\s*(\S+)", text, re.I | re.M)
            if st:
                d = found.setdefault(ip, {"st": set(), "loc": None, "locs": {}})
                d["st"].add(st.group(1).strip())
                if loc:
                    d["locs"].setdefault(st.group(1).strip(), loc.group(1))
                    if not d["loc"]:
                        d["loc"] = loc.group(1)
    except OSError:
        pass  # no multicast on this network or interface: skip UPnP
    finally:
        s.close()
    return found


# Bonjour / mDNS: devices announce their own name, model and services.
MDNS_TYPES = ["_services._dns-sd._udp", "_airplay._tcp", "_raop._tcp", "_googlecast._tcp",
              "_spotify-connect._tcp", "_ipp._tcp", "_printer._tcp", "_http._tcp", "_smb._tcp",
              "_companion-link._tcp", "_hap._tcp", "_homekit._tcp", "_device-info._tcp",
              "_workstation._tcp", "_ssh._tcp", "_mediaremotetv._tcp", "_androidtvremote2._tcp",
              "_samsungmsf._tcp"]


MDNS_LABELS = {
    "_airplay._tcp": "AirPlay", "_raop._tcp": "AirPlay audio", "_googlecast._tcp": "Google Cast",
    "_spotify-connect._tcp": "Spotify Connect", "_ipp._tcp": "Printing (IPP)",
    "_printer._tcp": "Printing (LPD)", "_http._tcp": "Web page", "_smb._tcp": "SMB file sharing",
    "_companion-link._tcp": "Apple device link", "_hap._tcp": "HomeKit", "_homekit._tcp": "HomeKit",
    "_ssh._tcp": "SSH", "_mediaremotetv._tcp": "Apple TV remote",
    "_androidtvremote2._tcp": "Android TV remote", "_samsungmsf._tcp": "Samsung multiscreen",
}


MDNS_NAME_ORDER = ["_companion-link._tcp", "_airplay._tcp", "_googlecast._tcp", "_device-info._tcp",
                   "_raop._tcp", "_workstation._tcp", "_ipp._tcp", "_printer._tcp", "_hap._tcp",
                   "_homekit._tcp", "_smb._tcp", "_http._tcp", "_ssh._tcp"]


def mdns_query(names):
    out = struct.pack(">6H", 0, 0, len(names), 0, 0, 0)
    for n in names:
        for label in (n if n.endswith(".arpa") else n + ".local").split("."):
            b = label.encode("utf-8")
            out += bytes([len(b)]) + b
        out += b"\x00" + struct.pack(">HH", 12, 0x8001)  # PTR, IN, unicast reply wanted
    return out


def dns_read_name(data, pos):
    labels, end = [], None
    for _ in range(128):
        n = data[pos]
        if n == 0:
            return labels, (end if end is not None else pos + 1)
        if n & 0xC0 == 0xC0:  # compression pointer
            if end is None:
                end = pos + 2
            pos = ((n & 0x3F) << 8) | data[pos + 1]
            continue
        labels.append(data[pos + 1:pos + 1 + n].decode("utf-8", "replace"))
        pos += 1 + n
    raise ValueError("bad DNS name")


def dns_records(data):
    """Returns [(name_labels, type, value)] for the PTR, SRV, TXT and A records in a DNS packet."""
    qd, an, ns, ar = struct.unpack(">4H", data[4:12])
    pos = 12
    for _ in range(qd):
        _, pos = dns_read_name(data, pos)
        pos += 4
    recs = []
    for _ in range(an + ns + ar):
        name, pos = dns_read_name(data, pos)
        rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", data[pos:pos + 10])
        start = pos + 10
        pos = start + rdlen
        if rtype == 12:
            recs.append((name, 12, dns_read_name(data, start)[0]))
        elif rtype == 33:
            target = dns_read_name(data, start + 6)[0]
            recs.append((name, 33, target))
        elif rtype == 16:
            txt, i = {}, start
            while i < pos:
                n = data[i]
                item = data[i + 1:i + 1 + n].decode("utf-8", "replace")
                i += 1 + n
                if "=" in item:
                    k, v = item.split("=", 1)
                    txt[k.lower()] = v
            recs.append((name, 16, txt))
        elif rtype == 1 and rdlen == 4:
            recs.append((name, 1, ".".join(str(b) for b in data[start:pos])))
    return recs


def strip_local(labels):
    if labels and labels[-1].lower() == "local":
        labels = labels[:-1]
    return ".".join(labels)


def mdns_merge(found, ip, data):
    """Folds one mDNS reply into `found`. Returns service types that a device announced."""
    types = set()
    try:
        recs = dns_records(data)
    except (ValueError, IndexError, struct.error):
        return types
    d = found.setdefault(ip, {"names": [], "txt": {}, "svcs": set(), "host": ""})
    for name, rtype, val in recs:
        if rtype == 12 and name and name[-1].lower() == "arpa":
            d["host"] = d["host"] or strip_local(val)  # reverse lookup: the device's own hostname
            continue
        if rtype == 12:
            if strip_local(name).lower() == "_services._dns-sd._udp":
                types.add(strip_local(val))
            elif len(val) > 1:
                svc = strip_local(val[1:])
                d["names"].append((svc, val[0]))
                d["svcs"].add(svc)
        elif rtype == 33:
            d["host"] = d["host"] or strip_local(val)
        elif rtype == 16:
            for k, v in val.items():
                d["txt"].setdefault(k, v)
        elif rtype == 1 and val == ip:
            d["host"] = d["host"] or strip_local(name)
    return types


def mdns_scan(own_ip=None, targets=(), wait=2.5):
    """Asks the network what Bonjour services exist. Returns {ip: raw details}.
    Devices that stay silent are then asked directly, which wakes many phones."""
    found, sent, todo = {}, set(), list(MDNS_TYPES)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.settimeout(1)

    def listen(seconds):
        end = time.time() + seconds
        while time.time() < end:
            try:
                data, (ip, _) = s.recvfrom(9000)
            except (socket.timeout, ConnectionResetError):
                continue
            yield from mdns_merge(found, ip, data)

    try:
        try:  # round 1 and 2: ask everyone, then ask about the service types found
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
            if own_ip:
                s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(own_ip))
            for _ in range(2):
                fresh = [t for t in todo if t not in sent][:24]
                if not fresh:
                    break
                for i in range(0, len(fresh), 8):
                    s.sendto(mdns_query(fresh[i:i + 8]), ("224.0.0.251", 5353))
                sent.update(fresh)
                todo = list(listen(wait))
        except OSError:
            pass  # no multicast here: skip straight to asking devices directly
        try:  # round 3: ask quiet devices one by one, including their own hostname
            asked = 0
            for ip in list(targets)[:40]:
                if ip in found and (found[ip]["names"] or found[ip]["host"]):
                    continue
                rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
                s.sendto(mdns_query(["_services._dns-sd._udp", "_companion-link._tcp",
                                     "_airplay._tcp", rev]), (ip, 5353))
                asked += 1
            if asked:
                list(listen(2))
        except OSError:
            pass
    finally:
        s.close()
    return found


def mdns_info(d):
    """Turns raw Bonjour details into a name, model and list of announced services."""
    txt = d["txt"]
    first = {}
    for svc, inst in d["names"]:
        first.setdefault(svc, inst)
    name = txt.get("fn", "")
    if not name:
        for svc in MDNS_NAME_ORDER + list(first):
            if svc in first:
                name = first[svc]
                if svc == "_raop._tcp":
                    name = re.sub(r"^[0-9A-Fa-f]+@", "", name)
                if svc == "_workstation._tcp":
                    name = re.sub(r"\s*\[[0-9a-fA-F:]+\]$", "", name)
                break
    model = ""
    for key in ("md", "model", "ty", "product", "am"):
        if txt.get(key):
            model = txt[key].strip("()")
            break
    return {"name": name, "model": model, "host": d["host"],
            "maker": txt.get("usb_mfg") or txt.get("mfg") or "",
            "bonjour": sorted({MDNS_LABELS[s] for s in d["svcs"] if s in MDNS_LABELS})}


def upnp_info(ip, loc):
    """Reads the name and model a UPnP device announces about itself."""
    try:
        u = urlparse(loc)
        if u.scheme != "http" or u.hostname != ip:  # only ask the device that answered
            return {}
        root = ET.fromstring(fetch(loc))
    except Exception:
        return {}
    dev = next((e for e in root.iter() if e.tag.split("}")[-1] == "device"), None)
    if dev is None:
        return {}

    def t(name):
        for e in dev:
            if e.tag.split("}")[-1] == name:
                return (e.text or "").strip()
        return ""
    return {"name": t("friendlyName"), "maker": t("manufacturer"),
            "model": t("modelName") or t("modelNumber")}


def samsung_info(ip):
    """Samsung smart TVs describe themselves at port 8001."""
    try:
        dev = json.loads(fetch(f"http://{ip}:8001/api/v2/")).get("device", {})
    except Exception:
        return {}
    return {"name": dev.get("name") or "", "maker": "Samsung",
            "model": dev.get("modelName") or dev.get("model") or ""}


def size_from_model(model):
    """Samsung, LG and similar TV model numbers start with the screen size in inches,
    for example UN55TU8000 or QN65Q80B."""
    m = re.match(r"^(?:UN|QN|UE|QE|UA|QA|LS)(\d{2})", (model or "").upper())
    if m and 19 <= int(m.group(1)) <= 98:
        return int(m.group(1))
    return None
