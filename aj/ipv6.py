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
