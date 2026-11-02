"""Works out this computer's gateway, subnet, address and MAC on each operating system."""
import ipaddress
import json
import re

from .config import SYSTEM
from .tools import sh


def cap_subnet(ip, prefix):
    """Return the network as CIDR text, keeping scans to a /24 at most."""
    net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
    if net.prefixlen < 24:  # keep scans small and fast on the Pi
        net = ipaddress.ip_network(f"{ip}/24", strict=False)
    return str(net)


def parse_linux(route_out, addr_out):
    m = re.search(r"default via (\S+) dev (\S+)", route_out)
    if not m:
        raise RuntimeError("No network connection found")
    gw, dev = m.groups()
    m = re.search(r"inet (\S+)", addr_out)
    if not m:
        raise RuntimeError("No IPv4 address on " + dev)
    iface = ipaddress.ip_interface(m.group(1))
    return gw, dev, str(iface.ip), iface.network.prefixlen


def net_info_linux():
    route_out = sh(["ip", "route", "show", "default"])
    m = re.search(r"default via \S+ dev (\S+)", route_out)
    dev = m.group(1) if m else ""
    gw, dev, ip, prefix = parse_linux(route_out, sh(["ip", "-4", "-o", "addr", "show", "dev", dev]))
    mac = None
    try:
        mac = open(f"/sys/class/net/{dev}/address").read().strip().lower()
    except OSError:
        pass
    return gw, cap_subnet(ip, prefix), ip, mac


def parse_mac(route_out, ifconfig_out):
    g = re.search(r"gateway:\s*(\S+)", route_out)
    i = re.search(r"interface:\s*(\S+)", route_out)
    if not (g and i):
        raise RuntimeError("No network connection found")
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+) netmask (0x[0-9a-fA-F]+)", ifconfig_out)
    if not m:
        raise RuntimeError("No IPv4 address on " + i.group(1))
    prefix = bin(int(m.group(2), 16)).count("1")
    e = re.search(r"ether\s+([0-9a-fA-F:]{17})", ifconfig_out)
    return g.group(1), i.group(1), m.group(1), prefix, (e.group(1).lower() if e else None)


def net_info_mac():
    route_out = sh(["route", "-n", "get", "default"])
    i = re.search(r"interface:\s*(\S+)", route_out)
    ifconfig_out = sh(["ifconfig", i.group(1)]) if i else ""
    gw, dev, ip, prefix, mac = parse_mac(route_out, ifconfig_out)
    return gw, cap_subnet(ip, prefix), ip, mac


WIN_PS = (
    "$r = Get-NetRoute -DestinationPrefix '0.0.0.0/0' | "
    "Sort-Object {$_.RouteMetric + $_.InterfaceMetric} | Select-Object -First 1; "
    "$a = Get-NetIPAddress -InterfaceIndex $r.InterfaceIndex -AddressFamily IPv4 | "
    "Where-Object {$_.IPAddress -notlike '169.254*'} | Select-Object -First 1; "
    "$n = Get-NetAdapter -InterfaceIndex $r.InterfaceIndex; "
    "[pscustomobject]@{gw=$r.NextHop; ip=$a.IPAddress; prefix=$a.PrefixLength; mac=$n.MacAddress} "
    "| ConvertTo-Json"
)


def parse_windows(ps_out):
    try:
        d = json.loads(ps_out)
    except ValueError:
        raise RuntimeError("No network connection found")
    if not d.get("gw") or not d.get("ip"):
        raise RuntimeError("No network connection found")
    mac = (d.get("mac") or "").replace("-", ":").lower() or None
    return d["gw"], d["ip"], int(d["prefix"]), mac


def net_info_windows():
    gw, ip, prefix, mac = parse_windows(sh(["powershell", "-NoProfile", "-Command", WIN_PS]))
    return gw, cap_subnet(ip, prefix), ip, mac


def net_info():
    """Returns (gateway_ip, subnet_cidr, own_ip, own_mac)."""
    if SYSTEM == "Linux":
        return net_info_linux()
    if SYSTEM == "Darwin":
        return net_info_mac()
    if SYSTEM == "Windows":
        return net_info_windows()
    raise RuntimeError("Unsupported system: " + SYSTEM)
