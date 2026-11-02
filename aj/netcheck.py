"""Catching tampering with the network itself: a rogue DHCP server handing out
addresses, DNS pointing you somewhere it shouldn't, and whether the internet is up.

All read-only. DHCP discovery is done by nmap (which Ajar already uses); DNS and the
internet health checks are small stdlib queries and TCP connects. Nothing here changes
the network.
"""
import ipaddress
import socket
import struct
import time

from .identify import dns_records
from .tools import run_nmap
from .db import net_setting, set_net_setting
from .events import record

# Well-known names that must resolve to a public address. If your network's resolver
# answers one of these with a LAN/private address, something is intercepting DNS.
CANARIES = ["example.com", "www.cloudflare.com", "dns.google"]
# Public hosts to test internet reachability (TCP connect only, no data sent).
INTERNET_TARGETS = [("1.1.1.1", 443), ("8.8.8.8", 53), ("9.9.9.9", 443)]
HEALTH_KEEP = 2100  # ~2 weeks of 10-minute samples


def is_private(ip):
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local or a.is_unspecified
    except ValueError:
        return False


# ---------------------------------------------------------------- rogue DHCP (via nmap)

def _local(tag):
    return tag.rsplit("}", 1)[-1]


def parse_dhcp(root):
    """Reads nmap's broadcast-dhcp-discover output into a list of offers, one per DHCP
    server that answered: {server, routers, dns}."""
    offers = []
    for script in root.iter("script"):
        if script.get("id") != "broadcast-dhcp-discover":
            continue
        for tbl in script.findall("table"):  # one table per response
            rec = {}
            for e in tbl.iter("elem"):
                k = (e.get("key") or "").strip()
                if k:
                    rec.setdefault(k, []).append((e.text or "").strip())
            server = (rec.get("Server Identifier") or [""])[0]
            offers.append({
                "server": server,
                "routers": rec.get("Router", []),
                "dns": rec.get("Domain Name Server", []) or rec.get("Domain Name Servers", []),
            })
    return offers


def assess_dhcp(offers, gateway):
    """Findings about who's handing out addresses. Returns [(id, level, text)]."""
    out = []
    servers = [o["server"] for o in offers if o["server"]]
    uniq = list(dict.fromkeys(servers))
    if len(uniq) > 1:
        out.append(("rogue_dhcp", "high",
                    "More than one device on your network is handing out addresses (DHCP servers at "
                    + ", ".join(uniq) + "). One of them may be an attacker or an extra router redirecting your "
                    "traffic. Find the one that isn't your router and unplug it, or turn off its DHCP."))
    elif uniq and gateway and gateway not in uniq:
        out.append(("dhcp_not_router", "info",
                    f"Addresses on your network are handed out by {uniq[0]}, which isn't your router ({gateway}). "
                    "That's normal if you set up a separate DHCP server (like Pi-hole) on purpose; if you didn't, "
                    "look into it."))
    for o in offers:
        for r in o["routers"]:
            if gateway and r and r != gateway:
                out.append(("dhcp_gateway", "high",
                            f"A DHCP server ({o['server'] or 'unknown'}) is telling devices to use {r} as the "
                            f"gateway instead of your router ({gateway}). That's how traffic gets redirected. "
                            "Investigate this now."))
    return out


# ---------------------------------------------------------------- DNS sanity

def build_dns_query(domain, qid=0x1234):
    q = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)  # standard query, recursion desired
    for label in domain.split("."):
        q += bytes([len(label)]) + label.encode("ascii")
    return q + b"\x00" + struct.pack(">HH", 1, 1)  # type A, class IN


def a_records(data):
    """The IPv4 addresses from a DNS response (reuses the shared DNS parser)."""
    try:
        return [val for _, rtype, val in dns_records(data) if rtype == 1]
    except (ValueError, IndexError, struct.error):
        return []


def resolve_with(server, domain, timeout=3):
    """Asks one DNS server for a domain's A records. Returns [] on any trouble."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(build_dns_query(domain), (server, 53))
        data, _ = s.recvfrom(2048)
        return a_records(data)
    except (OSError, socket.timeout):
        return []
    finally:
        s.close()


def check_dns(resolvers, canaries=None):
    """Asks each resolver for the canary domains. Returns {resolver: {domain: [ips]}}."""
    canaries = canaries or CANARIES
    out = {}
    for r in resolvers:
        if not r:
            continue
        out[r] = {d: resolve_with(r, d) for d in canaries}
    return out


def assess_dns(results, gateway, known_good=None):
    """Findings about DNS. A public domain answered with a private address is the strong
    signal of interception. known_good is a set of expected/trusted resolver addresses."""
    out = []
    for resolver, answers in results.items():
        got_any = any(ips for ips in answers.values())
        hijacked = [d for d, ips in answers.items() if ips and all(is_private(ip) for ip in ips)]
        if hijacked:
            out.append(("dns_hijack", "high",
                        f"Your DNS server {resolver} is sending a public website ({hijacked[0]}) to a device on "
                        "your own network instead of the real site. That's how fake login pages are served. "
                        "Check your router's DNS settings and that nothing on the network is intercepting DNS."))
        elif got_any and known_good and resolver not in known_good and gateway and resolver != gateway:
            out.append(("dns_unexpected", "info",
                        f"Your network's DNS is handled by {resolver}, which isn't your router or a well-known "
                        "provider. That's fine if you set it up (like Pi-hole or a custom DNS); otherwise it's "
                        "worth a look."))
    return out


# ---------------------------------------------------------------- internet health

def probe_gateway(gateway, timeout=1.5):
    """True if the router answers at all. A refused connection still means it's reachable."""
    if not gateway:
        return None
    for port in (80, 443, 53):
        try:
            with socket.create_connection((gateway, port), timeout=timeout):
                return True
        except ConnectionRefusedError:
            return True  # something answered (closed port), so the host is up
        except (OSError, socket.timeout):
            continue
    return False


def probe_internet(targets=None, timeout=1.5):
    """Returns (up, latency_ms). Connects to public hosts; no data is sent."""
    for host, port in (targets or INTERNET_TARGETS):
        start = time.time()
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True, round((time.time() - start) * 1000)
        except ConnectionRefusedError:
            return True, round((time.time() - start) * 1000)
        except (OSError, socket.timeout):
            continue
    return False, None


def sample_health(gateway, now=None):
    """One health reading: {t, gw, net, lat}."""
    gw = probe_gateway(gateway)
    up, lat = probe_internet()
    return {"t": now or time.time(), "gw": gw, "net": up, "lat": lat}


def cause(sample):
    """Plain-English cause of an outage, or None when the internet is up."""
    if sample["net"]:
        return None
    if sample["gw"] is False:
        return "your router or local network (the router didn't answer)"
    if sample["gw"]:
        return "your internet provider (your router is fine, but the internet is unreachable)"
    return "the network (couldn't reach the router or the internet)"


def health_events(prev, sample, net_name):
    """Timeline entries when the internet goes down or comes back. prev is the last sample."""
    if prev is None:
        return []
    if prev["net"] and not sample["net"]:
        return [("internet_down", "medium", f"The internet went down. Looks like {cause(sample)}.")]
    if not prev["net"] and sample["net"]:
        return [("internet_up", "info", "The internet is back.")]
    return []


def health_summary(samples, now=None):
    """Uptime and the last outage from the stored samples."""
    now = now or time.time()
    if not samples:
        return {"status": "unknown", "uptime_7d": None, "last_outage": None, "latency": None}
    week = [s for s in samples if s["t"] > now - 7 * 86400]
    up = sum(1 for s in week if s["net"])
    latest = samples[-1]
    lats = [s["lat"] for s in week if s.get("lat")]
    # find the most recent run of down samples
    last_outage = None
    i = len(samples) - 1
    end = None
    while i >= 0:
        if not samples[i]["net"]:
            end = end or samples[i]["t"]
            start = samples[i]["t"]
            j = i
            while j >= 0 and not samples[j]["net"]:
                start = samples[j]["t"]
                j -= 1
            last_outage = {"start": start, "end": end if end != samples[i]["t"] or i == len(samples) - 1 else end,
                           "ongoing": i == len(samples) - 1, "cause": cause(samples[i])}
            break
        i -= 1
    return {
        "status": "up" if latest["net"] else "down",
        "cause": cause(latest),
        "uptime_7d": round(100 * up / len(week), 2) if week else None,
        "samples_7d": len(week),
        "latency": round(sum(lats) / len(lats)) if lats else None,
        "last_outage": last_outage,
    }


PUBLIC_RESOLVERS = {"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
                    "208.67.222.222", "208.67.220.220"}


def host_resolvers():
    """DNS servers this computer is set to use, from /etc/resolv.conf (Linux/macOS)."""
    out = []
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) > 1:
                        out.append(parts[1])
    except OSError:
        pass
    return out


def run(net, net_name, gateway):
    """Checks DHCP and DNS for tampering, stores the result for this network, and records
    any new problem in the timeline. Returns the result dict. Never raises."""
    result = {"at": time.time(), "dhcp": [], "dns": {}, "findings": []}
    try:
        root = run_nmap(["--script", "broadcast-dhcp-discover"], timeout=60)
        result["dhcp"] = parse_dhcp(root)
    except Exception:
        pass
    dhcp_dns = [d for o in result["dhcp"] for d in o.get("dns", [])]
    resolvers = list(dict.fromkeys([gateway] + dhcp_dns + host_resolvers()))
    resolvers = [r for r in resolvers if r]
    try:
        result["dns"] = check_dns(resolvers)
    except Exception:
        pass
    findings = assess_dhcp(result["dhcp"], gateway) + assess_dns(
        result["dns"], gateway, known_good=PUBLIC_RESOLVERS | ({gateway} if gateway else set()))
    result["findings"] = [{"id": i, "level": l, "text": t} for i, l, t in findings]

    before = {f["id"] for f in (net_setting(net, "netcheck") or {}).get("findings", [])}
    for f in result["findings"]:
        if f["id"] not in before and f["level"] in ("high", "medium"):
            record(net, f["id"], f["level"], f["text"])
    set_net_setting(net, "netcheck", result)
    return result


def record_health(net, net_name, gateway, now=None):
    """Takes one health sample, appends it to this network's log, and records an outage
    starting or ending. Returns the sample."""
    now = now or time.time()
    s = sample_health(gateway, now)
    log = net_setting(net, "health", [])
    prev = log[-1] if log else None
    for kind, level, text in health_events(prev, s, net_name):
        record(net, kind, level, text)
    log.append(s)
    set_net_setting(net, "health", log[-HEALTH_KEEP:])
    return s
