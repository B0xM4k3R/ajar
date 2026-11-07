"""IPv6 discovery using nmap."""
import subprocess, xml.etree.ElementTree as ET
from .tools import is_admin
def scan_ipv6(interface):
    if not is_admin(): return []
    try:
        result = subprocess.run(["nmap", "-6", "-sn", f"-e{interface}", "ff02::1"], capture_output=True, text=True, timeout=120)
        if result.returncode != 0: return []
        devices = []
        root = ET.fromstring(result.stdout)
        for host in root.findall("host"):
            if host.find("status").get("state") != "up": continue
            ipv6, mac = None, None
            for addr in host.findall("address"):
                if addr.get("addrtype") == "ipv6": ipv6 = addr.get("addr")
                elif addr.get("addrtype") == "mac": mac = addr.get("addr").lower()
            if ipv6: devices.append({"ip": ipv6, "mac": mac})
        return devices
    except Exception: return []


# ---------------------------------------------------------------- who has which IPv6 address
# Devices answer to several IPv6 addresses, and most never show up in an IPv4 scan's results as such.
# The computer's neighbor table links them to the MAC address Ajar already knows. It costs nothing
# (nothing is sent), but only lists devices this computer has recently talked to.
import ipaddress
import platform
import re

LINUX_NEIGH = re.compile(r"^(?P<ip>\S+)\s+dev\s+\S+\s+lladdr\s+(?P<mac>\S+)\s*(?P<rest>.*)$")
MAC_NEIGH = re.compile(r"^(?P<ip>[0-9a-fA-F:.]+)(?:%\S+)?\s+(?P<mac>(?:[0-9a-fA-F]{1,2}:){5}[0-9a-fA-F]{1,2})\s+\S+")
WIN_NEIGH = re.compile(r"^\s*(?P<ip>[0-9a-fA-F:.]+)(?:%\S+)?\s+(?P<mac>(?:[0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2})\s+(?P<state>\w+)")


def _norm_mac(mac):
    return ":".join(p.zfill(2) for p in mac.replace("-", ":").lower().split(":"))


def parse_neighbors(output, system):
    """Neighbor-table text -> {mac: [ipv6 addresses]}. Skips failed entries and addresses that say
    nothing useful about a device (link-local, multicast, loopback)."""
    out = {}
    for line in (output or "").splitlines():
        if system == "Linux":
            m = LINUX_NEIGH.match(line.strip())
            if not m or m.group("rest").split()[-1:] in (["FAILED"], ["INCOMPLETE"]):
                continue
        elif system == "Darwin":
            m = MAC_NEIGH.match(line.strip())
        elif system == "Windows":
            m = WIN_NEIGH.match(line)
            if m and m.group("state").lower() in ("unreachable", "incomplete"):
                continue
        else:
            return {}
        if not m:
            continue
        try:
            ip = ipaddress.ip_address(m.group("ip"))
        except ValueError:
            continue
        if ip.version != 6 or ip.is_multicast or ip.is_link_local or ip.is_loopback or ip.is_unspecified:
            continue
        addrs = out.setdefault(_norm_mac(m.group("mac")), [])
        if str(ip) not in addrs:
            addrs.append(str(ip))
    return {mac: sorted(a) for mac, a in out.items()}


def neighbors(system=None, run=None):
    system = system or platform.system()
    cmd = {"Linux": ["ip", "-6", "neigh"], "Darwin": ["ndp", "-an"],
           "Windows": ["netsh", "interface", "ipv6", "show", "neighbors"]}.get(system)
    if not cmd:
        return {}
    try:
        text = (run or (lambda c: subprocess.run(c, capture_output=True, text=True, errors="ignore", timeout=10).stdout))(cmd)
    except (OSError, subprocess.SubprocessError):
        return {}
    return parse_neighbors(text, system)


def is_public(addr):
    """A globally routable address (not a private fd00::/8 one): reachable from the internet
    unless the router's firewall stops it."""
    try:
        return ipaddress.ip_address(addr).is_global
    except ValueError:
        return False
