"""The security score: points per problem, fixes, checks and history."""
import time
from .db import net_setting, set_net_setting
from .events import device_label, record
from .audit import SMART_HOME_KINDS, assess, is_tv
from .exposure import view as exposure_view

SCORE_POINTS = {
    "wifi_open": 30, "wifi_wep": 30, "wifi_wpa": 30, "wifi_twin": 15, "wifi_mixed": 8,
    "wifi_wps": 8, "wifi_mismatch": 6, "telnet": 15, "ftp_anon": 15, "share_write": 15, "nfs_any": 15,
    "share_read": 8, "vnc": 8, "ftp": 6, "nfs": 6, "rdp": 6, "upnp": 6, "adb": 15, "mqtt": 6, "kasa": 6, "iot_mixed": 6,
    "internet_risky": 30, "internet_open": 3, "share_sensitive": 15, "ftp_sensitive": 15,
    "smb1": 15, "camera_open": 30, "admin_open": 30, "http_login_plain": 6,
    "rogue_dhcp": 30, "dhcp_gateway": 30, "dns_hijack": 30,
    "default_banner": 15, "snmp_public": 6, "ssh_legacy": 6, "default_cred_success": 30,
    "arp_spoof": 30, "cve_critical": 30, "cve_high": 15,
}
INTERNET_OPEN_MAX, UNAPPROVED_EACH, UNAPPROVED_MAX, SCORE_WINDOW = 9, 3, 12, 7 * 86400

FIXES = {
    "wifi_open": ("Put a password on your WiFi", "In the router's WiFi settings, set security to WPA2-Personal (AES) or WPA2/WPA3 and choose a long passphrase. Every device will need the new password."),
    "wifi_wep": ("Replace WEP with WPA2 or WPA3", "In the router's WiFi settings, change security from WEP to WPA2-Personal (AES) or WPA2/WPA3. If an old device can only do WEP, retire it or give it its own isolated network."),
    "wifi_wpa": ("Replace WPA/TKIP with WPA2 or WPA3", "In the router's WiFi settings, choose WPA2-Personal with AES (also called CCMP), or WPA2/WPA3."),
    "wifi_mixed": ("Turn off the old WPA/TKIP mode", "Change the router's security mode from WPA/WPA2 (or TKIP+AES) to WPA2 with AES only, or WPA2/WPA3. Very old devices may stop connecting; that's the point."),
    "wifi_wps": ("Turn off WPS", "In the router's wireless settings, switch WPS off. You'll type the WiFi password on new devices instead of pressing a button."),
    "wifi_twin": ("Check the look-alike network", "Look at the flagged access point on the WiFi tab. If it isn't an extender or old router of yours, don't join it, and tell your devices to forget any open network with your name."),
    "wifi_mismatch": ("Make all your access points match", "Set the same security mode on every band, mesh node and extender, so none is a weaker way in."),
    "telnet": ("Turn off Telnet on {who}", "Look for Telnet or remote access in the device's settings page or app and switch it off. If it can't be turned off, move the device to a guest network."),
    "ftp_anon": ("Turn off anonymous FTP on {who}", "In the device's file-sharing settings, disable anonymous or guest FTP, or turn FTP off and use password-protected SMB instead."),
    "ftp": ("Turn off FTP on {who}", "If you don't use FTP, switch it off. If you do, use SFTP or password-protected SMB instead."),
    "share_write": ("Lock the share '{what}' on {who}", "Turn off guest access for the share. On Windows: Control Panel, Network and Sharing Center, Advanced sharing settings, All networks, and turn Password protected sharing on. On a NAS, remove guest permissions from the share."),
    "share_sensitive": ("Get the sensitive files off the open share '{what}' on {who}", "Anyone on your network can read these without a password. Move passwords, keys, tax and financial files, and backups somewhere private, and turn off guest access to the share (on Windows: Advanced sharing settings, All networks, turn Password protected sharing on)."),
    "ftp_sensitive": ("Get the sensitive files off anonymous FTP on {who}", "Turn off anonymous FTP in the device's settings, or move passwords, financial files and backups off it. Anyone on your network can download them right now."),
    "share_read": ("Require a password for the share '{what}' on {who}", "Turn off guest access for the share. On Windows, turn Password protected sharing on (Advanced sharing settings, All networks). On a NAS, remove guest read access."),
    "nfs_any": ("Limit the NFS export on {who}", "Change the export from every device (*) to the specific addresses that need it, in /etc/exports or the NAS's NFS settings."),
    "nfs": ("Review the NFS export on {who}", "Check the export still needs to exist, and that it only lists the devices that use it."),
    "rdp": ("Lock down Remote Desktop on {who}", "If you don't use it, turn it off (Settings, System, Remote Desktop). If you do, keep Network Level Authentication on and use a strong password."),
    "vnc": ("Lock down VNC on {who}", "Turn VNC off if you don't use it, or set a strong VNC password and keep the software updated."),
    "upnp": ("Turn off UPnP on the router", "In the router's settings (often under Advanced or NAT), switch UPnP off. Some game consoles may then need a port forwarded by hand."),
    "adb": ("Turn off network debugging on {who}", "In the device's Developer options, switch off ADB / network (wireless) debugging. If you didn't turn it on yourself, factory-reset the device: some cheap TV boxes ship like this."),
    "mqtt": ("Secure MQTT on {who}", "In the device's or hub's settings, require a username and password for MQTT, or switch to the encrypted port (8883). If you don't use MQTT, turn it off."),
    "kasa": ("Update {who}", "Update the device in the Kasa or Tapo app. Newer firmware replaces this old protocol. If it can't be updated, put it on a guest or IoT network."),
    "iot_mixed": ("Move smart-home devices to their own network", "Use your router's guest or IoT network for cameras, doorbells, plugs and the like, and check that guest devices can't reach your main network (look for client isolation, or a setting like \"allow guests to see each other and access my local network\" switched off). The devices keep working: they only need the internet. Re-add each one in its app with the new network."),
    "internet_risky": ("Close {what} to the internet for {who}", "Turn off the feature on the device that asked for it (remote access, cloud sharing or similar, in its app or settings). The surest fix is turning UPnP off in the router's settings, then restarting the router: many routers keep openings until they restart. If you need to reach the device from outside, use a VPN instead."),
    "internet_open": ("Review what's open to the internet", "These are usually game consoles, media servers or VPNs asking for what they need. If you don't recognize one, or no longer use that feature, turn it off on the device, or turn UPnP off in the router's settings and restart the router."),
    "smb1": ("Turn off SMBv1 on {who}", "SMBv1 is the old, unsafe file-sharing protocol behind WannaCry. On Windows: Turn Windows features on or off, and untick SMB 1.0/CIFS, then restart. On a NAS, disable SMB1/NT1 in its file-sharing settings and allow only SMB2/SMB3."),
    "camera_open": ("Secure the camera stream on {who}", "Its video stream plays with no password, so anyone on your network can watch. Open the camera's app or web page, set a strong password, and turn off any \"anonymous\" or \"guest\" viewing. If you don't use the stream, turn it off."),
    "admin_open": ("Set a password on {who}", "Its control page opens with no login, so anyone on your network can change its settings. Open the page, create an admin password, and if the device doesn't need a web page at all, turn it off."),
    "default_risk": ("Check the password on {who}", "This kind of device often ships with a default password (and attackers know the defaults). Open its admin page and make sure the password has been changed to something strong and unique. Ajar can't tell whether yours was changed, so it's worth a look."),
    "http_login_plain": ("Stop sending {who}'s login over plain HTTP", "Its login page uses plain HTTP, so anyone on your WiFi can read the password as you type it. Use the device's HTTPS page if it has one, turn on HTTPS in its settings, or only manage it over a trusted connection."),
    "rogue_dhcp": ("Find the extra device handing out addresses", "More than one thing on your network is acting as a DHCP server. Usually it's a second router or access point plugged in with its DHCP left on. Find it and switch its DHCP off (set it to \"access point\" or \"bridge\" mode), or unplug it. If you can't account for it, treat it as an intruder and disconnect it."),
    "dhcp_gateway": ("Stop the traffic redirection", "Something is telling your devices to route through a gateway that isn't your router, which is how traffic gets intercepted. Disconnect any router or device you didn't set up, then restart your own router and reconnect your devices."),
    "dns_hijack": ("Fix your DNS", "A public website is being answered with an address on your own network, which can serve fake login pages. Check your router's DNS settings (set them back to automatic or a trusted resolver), make sure no device is set as a DNS server without your knowledge, and restart the router. If it persists, factory-reset the router and change its admin password."),
    "default_banner": ("Change {who}'s password now", "Its login page says it's still on the default password. Open the page, set a strong unique password, and save."),
    "snmp_public": ("Change {who}'s SNMP community string", "It answers to the factory default 'public' community string, which lets anyone on your network read its details. In its SNMP settings, set a unique community string or switch SNMP off if you don't use it."),
    "ssh_legacy": ("Disable legacy SSH algorithms on {who}", "It offers old SSH algorithms (ssh-rsa, diffie-hellman-group1-sha1) that are no longer safe. Update the SSH server (usually OpenSSH) and set HostKeyAlgorithms and KexAlgorithms to modern values, or restrict SSH to a management VLAN."),
    "default_cred_success": ("Change {who}'s factory default password NOW", "Its admin login accepted a documented factory default credential, so anyone on your network can log in and change its settings. Open its admin page, set a strong unique password, and check for unknown changes or users."),
    "arp_spoof": ("Investigate possible ARP spoofing", "Multiple IP addresses are using the same MAC address, which usually means someone is intercepting traffic (a Man-in-the-Middle attack). Disconnect the suspect device and restart your router."),
    "cve_critical": ("Update {who} to patch critical CVEs", "Ajar found critical vulnerabilities (CVSS 9.0+) on this device. Check for a firmware update from the manufacturer immediately, or disconnect the device if it can't be patched."),
    "cve_high": ("Update {who} to patch high-risk CVEs", "Ajar found high-risk vulnerabilities (CVSS 7.0-8.9) on this device. Check for a firmware update from the manufacturer."),
    "unapproved": ("Review new devices", "Open the Devices tab, approve the devices you recognize, and rename them so you'll know them next time. Look into any you don't recognize: check your router's device list or turn devices off one at a time."),
}

CHECKS = [
    ("WiFi has a password (WPA2 or better)", {"wifi_open", "wifi_wep", "wifi_wpa"}, "wifi"),
    ("No old WPA/TKIP mode", {"wifi_mixed"}, "wifi"),
    ("WPS is off", {"wifi_wps"}, "wps"),
    ("No look-alike copies of your WiFi", {"wifi_twin", "wifi_mismatch"}, "wifi"),
    ("Telnet is off everywhere", {"telnet"}, "audit"),
    ("No anonymous FTP", {"ftp_anon"}, "audit"),
    ("File shares need a password", {"share_write", "share_read"}, "audit"),
    ("No NFS exports open to everyone", {"nfs_any"}, "audit"),
    ("Remote Desktop and VNC not exposed", {"rdp", "vnc"}, "audit"),
    ("UPnP is off on the router", {"upnp"}, "audit"),
    ("Every device is approved", {"unapproved"}, "devices"),
    ("No Android debugging open", {"adb"}, "audit"),
    ("No unencrypted MQTT or password-less smart-plug control", {"mqtt", "kasa"}, "audit"),
    ("Smart-home devices kept apart from computers", {"iot_mixed"}, "devices"),
    ("Nothing risky opened to the internet through UPnP", {"internet_risky"}, "exposure"),
    ("No sensitive files exposed on open shares or FTP", {"share_sensitive", "ftp_sensitive"}, "audit"),
    ("No old SMBv1 file sharing", {"smb1"}, "audit"),
    ("No logins open or sent in the clear", {"camera_open", "admin_open", "http_login_plain"}, "audit"),
    ("No rogue DHCP server or DNS tampering", {"rogue_dhcp", "dhcp_gateway", "dns_hijack"}, "netcheck"),
    ("No device still on a documented factory default password", {"default_cred_success", "default_banner"}, "audit"),
    ("SNMP not on the default 'public' community string", {"snmp_public"}, "audit"),
    ("SSH not offering legacy algorithms", {"ssh_legacy"}, "audit"),
    ("No ARP spoofing (Man-in-the-Middle) detected", {"arp_spoof"}, "audit"),
    ("No critical CVEs on devices", {"cve_critical"}, "audit"),
]

IOT_ACCOUNT_TIP = ("Smart-home apps ({names}): give each account a unique password and turn on two-step verification. A stolen app login is the usual way into cameras and doorbells, and no scan can see it.")
def grade_of(score): return "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 60 else "F"

def security_report(devices, wres, now=None, net=None, exposure=None, netcheck=None):
    now = now or time.time()
    recent = [d for d in devices if d.get("online") or (d.get("last_seen") or 0) > now - SCORE_WINDOW]
    audited = [d for d in recent if d.get("audit")]
    issues = []

    def issue(fid, who, problem, level, where="", what=""):
        title, steps = FIXES[fid]
        issues.append({"id": fid, "who": who, "where": where, "level": level, "points": SCORE_POINTS.get(fid, 0), "problem": problem, "title": title.format(who=who, what=what), "fix": steps})

    advisories = []
    for d in audited:
        for f in assess(d["audit"]):
            if f["id"] in SCORE_POINTS: issue(f["id"], device_label(d), f["text"], f["level"], d.get("ip", ""), f.get("what", ""))
            elif f["id"] == "default_risk":
                # Only show the advisory if the device hasn't been credential-tested yet
                cred_res = d.get("audit", {}).get("default_cred_result") or {}
                if not (cred_res.get("tried") or cred_res.get("success")):
                    advisories.append(f"Check the password on {device_label(d)}: devices like it often ship with a default one, and Ajar can't tell whether yours was changed.")
            elif f["id"] == "default_cred_lockout": advisories.append(f"Lockout suspected on {device_label(d)} during the credential test. Open its admin page to confirm it isn't locked, then re-authorize the test.")
    
    fresh = [d for d in recent if d.get("online") and not d.get("approved")]
    if fresh:
        names = ", ".join(f"{device_label(d)} ({d.get('ip')})" if device_label(d) != d.get("ip") else d.get("ip") for d in fresh[:5]) + (" and more" if len(fresh) > 5 else "")
        issue("unapproved", "Devices", f"{len(fresh)} device{'s' if len(fresh) > 1 else ''} you haven't approved yet: {names}. Unknown devices are worth a look.", "medium")
        issues[-1]["points"] = min(UNAPPROVED_MAX, UNAPPROVED_EACH * len(fresh))
    
    iot = [d for d in recent if d.get("kind") in SMART_HOME_KINDS or (d.get("audit") and is_tv(d["audit"]))]
    people = [d for d in recent if d.get("kind") in ("personal", "this device", "pi") and d not in iot]
    if iot and people:
        names = ", ".join(device_label(d) for d in iot[:4]) + (" and more" if len(iot) > 4 else "")
        issue("iot_mixed", "Network", f"{len(iot)} smart-home device{'s' if len(iot) > 1 else ''} ({names}) share your network with computers and phones. If one is hacked, it can reach everything else.", "medium")
    
    nc = netcheck or {}
    for f in nc.get("findings", []):
        if f["id"] in SCORE_POINTS: issue(f["id"], "Network", f["text"], f["level"])
        elif f["level"] == "info": advisories.append(f["text"])
    
    ex = exposure_view(exposure, devices)
    if ex and ex["reachable"]:
        others = []
        for m in ex["mappings"]:
            if not m["enabled"]: continue
            what = f"{m['proto']} {m['ext']}" + (f" ({m['service']})" if m["service"] else "")
            if m["risky"]: issue("internet_risky", m["device"], f"The router lets anyone on the internet reach {m['device']} on {m['proto']} port {m['port']}" + (f" ({m['service']})" if m["service"] else "") + (", from one address only" if m["remote"] else "") + ".", "high", m["client"], what)
            else: others.append(f"{what} for {m['device']}")
        if others:
            issue("internet_open", "Router", f"{len(others)} other port{'s' if len(others) > 1 else ''} open to the internet: {'; '.join(others[:5])}" + (" and more" if len(others) > 5 else "") + ".", "medium")
            issues[-1]["points"] = min(INTERNET_OPEN_MAX, SCORE_POINTS["internet_open"] * len(others))
    
    if wres and wres.get("mine_known"):
        for f in wres["findings"]:
            if f.get("cat") == "security" and f.get("id") in SCORE_POINTS: issue(f["id"], "WiFi " + f["who"], f["text"], f["level"])

    lost = sum(i["points"] for i in issues)
    score = max(0, 100 - lost)
    issues.sort(key=lambda i: (-i["points"], {"high": 0, "medium": 1}.get(i["level"], 2), i["title"]))

    have = {"wifi": bool(wres and wres.get("mine_known")), "wps": bool(wres and wres.get("mine_known") and wres.get("source") == "iw"), "audit": bool(audited), "devices": bool(recent), "exposure": bool(ex and ex.get("status") in ("listed", "no_upnp")), "netcheck": bool(netcheck)}
    failed = {i["id"] for i in issues}
    checks = []
    for label, ids, need in CHECKS:
        status = ("fail" if ids & failed else "pass") if have[need] else "unknown"
        checks.append({"label": label, "status": status})
    
    missing = []
    if not have["audit"]: missing.append("services and shares (tap Check services)")
    if not wres: missing.append("WiFi (tap Scan WiFi)")
    elif not wres.get("mine_known"): missing.append("your WiFi network (tap This is mine on the WiFi tab)")
    
    optional = []
    if wres and wres.get("mine_known"): optional = [f["text"] for f in wres["findings"] if f.get("id") in ("wifi_wpa3", "wifi_owe")]
    if iot: optional.append(IOT_ACCOUNT_TIP.format(names=", ".join(device_label(d) for d in iot[:6])))
    optional += advisories

    area = lambda i: "internet" if i["id"].startswith("internet_") else "wifi" if i["who"].startswith("WiFi ") else "devices"
    by_area = {a: sum(i["points"] for i in issues if area(i) == a) for a in ("wifi", "devices", "internet")}
    report = {"score": score, "grade": grade_of(score), "issues": issues, "checks": checks, "exposure": ex, "unscored": not have["audit"] and not have["wifi"], "partial": bool(missing), "missing": missing, "optional": optional, "lost": by_area, "wps_unknown_reason": None if have["wps"] or not have["wifi"] else "WPS can only be seen on Linux when ajar scans with iw."}
    report["history"] = score_history(score, report["partial"], now, net) if net else []
    return report

def score_history(score, partial, now, net):
    hist = net_setting(net, "score_history", [])
    if not hist or hist[-1][1] != score or now - hist[-1][0] > 6 * 3600:
        last = hist[-1] if hist else None
        hist = (hist + [[now, score, partial]])[-60:]
        set_net_setting(net, "score_history", hist)
        if last and last[1] != score and not partial and not (len(last) > 2 and last[2]):
            up = score > last[1]
            record(net, "score", "info" if up else "medium", f"Security score {'rose' if up else 'fell'} from {last[1]} to {score} ({grade_of(last[1])} to {grade_of(score)}).")
    return hist
