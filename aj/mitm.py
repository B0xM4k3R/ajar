"""Detects ARP spoofing (Man-in-the-Middle attacks).

What counts as a real warning: the router's address answering with a different MAC than the
one ajar recorded for it. That is what an attacker posing as the router looks like.

What does not: several addresses sharing one MAC. Routers with a second address, VMs, Docker
hosts, NAS boxes and routers that answer for the whole network (proxy ARP) all do that
legitimately, so it is reported as information, or as a "worth a look" only when it involves
the router and ajar has no recorded router MAC to compare against.
"""
import ipaddress
import platform
import re
import subprocess

# Matches Windows ("192.168.1.1   aa-bb-cc-dd-ee-ff   dynamic"),
# Linux net-tools ("? (192.168.1.1) at aa:bb:... [ether] on eth0") and
# macOS ("? (192.168.1.1) at a:b:c:d:e:f on en0 ifscope [ethernet]"), where the
# MAC's octets may be 1 or 2 digits because macOS drops leading zeros.
ARP_LINE = re.compile(
    r"(?P<ip>\d+\.\d+\.\d+\.\d+)\)?\s+(?:at\s+)?"
    r"(?P<mac>[0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})(?![0-9a-fA-F:-])")


def norm_mac(mac):
    """aa-bb-0-1-2-3 -> aa:bb:00:01:02:03 (lowercase, zero-padded)."""
    return ":".join(p.zfill(2) for p in mac.replace("-", ":").lower().split(":"))


def parse_arp_output(output):
    """Turns `arp -a` text into {ip: mac}. Skips incomplete entries."""
    table = {}
    for line in (output or "").splitlines():
        if "incomplete" in line.lower():
            continue
        m = ARP_LINE.search(line)
        if m:
            table[m.group("ip")] = norm_mac(m.group("mac"))
    return table


def read_arp_table():
    if platform.system() == "Linux":
        try:
            with open("/proc/net/arp", "r") as f:
                lines = f.readlines()[1:]
        except OSError:
            return {}
        table = {}
        for line in lines:
            parts = line.split()
            if len(parts) >= 4 and parts[3] != "00:00:00:00:00:00":
                table[parts[0]] = parts[3].lower()
        return table
    try:
        out = subprocess.check_output(["arp", "-a"], text=True, errors="ignore", timeout=15)
    except (OSError, subprocess.SubprocessError):
        return {}
    return parse_arp_output(out)


def in_subnet(table, subnet):
    """Only the network being scanned: the ARP table also holds Docker, VPN and other interfaces."""
    if not subnet:
        return dict(table)
    try:
        net = ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        return dict(table)
    keep = {}
    for ip, mac in table.items():
        try:
            if ipaddress.ip_address(ip) in net:
                keep[ip] = mac
        except ValueError:
            pass
    return keep


def analyze(table, gateway_ip=None, gateway_mac=None):
    """Turns an {ip: mac} table into findings. gateway_mac is the router MAC ajar recorded earlier."""
    findings = []
    gateway_mac = (norm_mac(gateway_mac) if gateway_mac else None)
    seen_gw = table.get(gateway_ip) if gateway_ip else None

    if seen_gw and gateway_mac and seen_gw != gateway_mac:
        sharing = sorted(ip for ip, m in table.items() if m == seen_gw and ip != gateway_ip)
        findings.append({"level": "high", "id": "arp_spoof", "ips": [gateway_ip] + sharing,
                         "text": f"The router's address ({gateway_ip}) is answering with MAC {seen_gw}, but ajar "
                                 f"recorded {gateway_mac} for it. If you didn't replace or reset your router, "
                                 "something on the network may be pretending to be it (an ARP spoofing attack)."
                                 + (f" The same MAC also answers for {', '.join(sharing)}." if sharing else "")})

    groups = {}
    for ip, mac in table.items():
        if mac.startswith("ff:ff:ff") or mac.startswith("01:00:5e"):
            continue
        groups.setdefault(mac, []).append(ip)
    for mac, ips in sorted(groups.items()):
        if len(ips) < 2:
            continue
        ips = sorted(ips)
        if gateway_ip in ips and seen_gw != gateway_mac and gateway_mac and mac == seen_gw:
            continue  # already reported above as the real warning
        shared = f"{', '.join(ips)} all answer with the same MAC ({mac})."
        if gateway_ip in ips and not gateway_mac:
            findings.append({"level": "medium", "id": "arp_shared_gateway", "ips": ips,
                             "text": shared + " That includes the router, and ajar has no earlier record of the "
                                     "router's MAC to compare with. Usually harmless (a router with several "
                                     "addresses); worth a look if you didn't expect it."})
        else:
            findings.append({"level": "info", "id": "arp_shared_mac", "ips": ips,
                             "text": shared + " That is normal for routers, VMs, Docker hosts and NAS boxes, "
                                     "which use several addresses; it is not by itself a sign of an attack."})
    return findings


def check_arp(subnet=None, gateway_ip=None, gateway_mac=None):
    return analyze(in_subnet(read_arp_table(), subnet), gateway_ip, gateway_mac)
