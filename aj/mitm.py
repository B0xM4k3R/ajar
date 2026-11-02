"""Detects ARP spoofing (Man-in-the-Middle attacks)."""
import subprocess, re, platform
def check_arp():
    findings = []
    if platform.system() == "Linux":
        try:
            with open("/proc/net/arp", "r") as f: lines = f.readlines()[1:]
            arp_table = {}
            for line in lines:
                parts = line.split()
                if len(parts) >= 4 and parts[3] != "00:00:00:00:00:00": arp_table[parts[0]] = parts[3].lower()
        except Exception: return []
    else:
        try:
            output = subprocess.check_output(["arp", "-a"], text=True, errors="ignore")
            arp_table = {}
            for line in output.splitlines():
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:-]{17})', line)
                if ip_match: arp_table[ip_match.group(1)] = ip_match.group(2).replace("-", ":").lower()
        except Exception: return []
    mac_to_ips = {}
    for ip, mac in arp_table.items():
        if mac.startswith("ff:ff:ff") or mac.startswith("01:00:5e"): continue
        mac_to_ips.setdefault(mac, []).append(ip)
    for mac, ips in mac_to_ips.items():
        if len(ips) > 1:
            findings.append({"level": "high", "id": "arp_spoof", "text": f"Multiple IPs ({', '.join(ips)}) use the same MAC ({mac}). Possible ARP spoofing (MITM) attack.", "ips": ips})
    return findings
