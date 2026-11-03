"""The services check: open ports, guest shares, OS guess, deep check, MITM, and CVEs."""
import json, re, subprocess, time

from .config import set_step, state
from .db import db, net_setting
from .tools import find_script, host_ip, is_admin, run_nmap
from .networks import current_net
from .events import device_label, record
from . import shares as sharelib
from . import weakauth
from . import probe as probelib
from . import defaults as credlib
from . import mitm as mitmlib
from . import cve as cvelib
from .identify import mdns_info, mdns_scan, samsung_info, size_from_model, ssdp_scan, upnp_info

PORT_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 80: "Web (HTTP)", 111: "RPC",
    139: "SMB (NetBIOS)", 443: "Web (HTTPS)", 445: "SMB file sharing",
    548: "AFP file sharing", 554: "Video stream (RTSP)", 631: "Printing (IPP)",
    2049: "NFS file sharing", 3389: "Remote Desktop", 5900: "VNC remote screen",
    8001: "Samsung TV control", 8002: "Samsung TV control (alt)", 
    8080: "Web (alt)", 8200: "Media server", 9100: "Printing (raw)",
}
PORTS = ",".join(str(p) for p in PORT_NAMES)
DEEP_PORTS = "1-10000"
DEEP_KINDS = ("iot", "tv", "other", "router")
SMART_HOME_KINDS = ("iot", "tv")

IOT_PORT_NAMES = {
    1883: "MQTT (unencrypted)", 8883: "MQTT (encrypted)", 5555: "Android debug (ADB)",
    6668: "Tuya local control", 9999: "TP-Link Kasa control", 6053: "ESPHome control",
    2323: "Telnet (alt port)", 4444: "Remote shell (alt)", 8008: "Chromecast", 8009: "Chromecast",
    8443: "Web (HTTPS alt)", 5000: "Web/UPnP (alt)", 7000: "AirPlay", 7100: "AirPlay", 1900: "UPnP",
    53: "DNS", 67: "DHCP", 22: "SSH", 5353: "Bonjour",
}

EXPECTED_PORTS = {53, 80, 443, 8080, 8443, 1900, 5000, 7000, 7100, 8008, 8009, 8001, 8002, 49152,
                  554, 631, 9100, 6668, 6053, 8883, 515, 3689, 5353}

def norm_access(*vals):
    t = " ".join(v.upper() for v in vals if v)
    if "WRITE" in t: return "read/write" if "READ" in t else "write"
    if "READ" in t: return "read"
    return "none"

def parse_shares(script):
    shares = []
    for t in script.findall("table"):
        full = t.get("key") or ""
        name = full.rsplit("\\", 1)[-1] or full
        if name.upper() == "IPC$": continue
        el = {e.get("key"): (e.text or "") for e in t.findall("elem")}
        shares.append({"name": name, "type": el.get("Type", ""), "comment": el.get("Comment", ""), "access": norm_access(el.get("Anonymous access"), el.get("Current user access"))})
    return shares

def parse_lines(output):
    lines = []
    for raw in (output or "").splitlines():
        line = raw.strip()
        if not line or line.upper().startswith(("ERROR", "FAILED", "COULDN")): continue
        if line.lower().startswith("nfs-showmount"): continue
        lines.append(line)
    return lines

def is_tv(a):
    inf = a.get("info") or {}
    ports = {p["port"] for p in a.get("ports", [])}
    return bool(inf.get("size_in") or 8001 in ports or 8002 in ports or re.search(r"\btv\b|television", f"{inf.get('model', '')} {inf.get('name', '')}", re.I))

def assess(a):
    out = []
    ports = {p["port"] for p in a.get("ports", [])}
    def add(level, fid, text, what=""): out.append({"level": level, "id": fid, "text": text, "what": what})

    if 23 in ports: add("high", "telnet", "Telnet is open. It sends passwords in plain text. Turn it off if you can.")
    elif 2323 in ports: add("high", "telnet", "Telnet is open on port 2323, the port botnets like Mirai hunt for. It sends passwords in plain text.")
    if 5555 in ports: add("high", "adb", "Android debugging (ADB) is open to the network. Anyone on your network can take control of this device and run commands on it.")
    if 1883 in ports: add("medium", "mqtt", "MQTT on port 1883 is unencrypted and often needs no password, so others on your network may be able to read or send this device's messages.")
    if 9999 in ports: add("medium", "kasa", "Port 9999 is open. On TP-Link Kasa plugs and bulbs this is an old control protocol that accepts commands from anyone on your network, no password needed.")
    
    if a.get("ftp_anon"):
        extra = sharelib.describe(a.get("ftp_exposed"))
        add("high", "ftp_anon", "FTP allows anonymous login. Anyone on your network can browse its files" + (f", including {extra}" if extra else "") + ".")
        if a.get("ftp_exposed", {}).get("sensitive"): add("high", "ftp_sensitive", f"The anonymous FTP server is sharing {sharelib.describe(a['ftp_exposed'])}. Turn off anonymous FTP now, or move those files off it.")
    elif 21 in ports: add("medium", "ftp", "FTP is open. It sends passwords in plain text.")
    
    for sh_ in a.get("shares", []):
        extra = sharelib.describe(sh_.get("exposed"))
        inside = f" It contains {extra}." if extra else ""
        if "write" in sh_["access"]: add("high", "share_write", f"Share '{sh_['name']}' can be changed by anyone on your network, no password needed." + inside, sh_["name"])
        elif sh_["access"] == "read": add("medium", "share_read", f"Share '{sh_['name']}' can be read by anyone on your network, no password needed." + inside, sh_["name"])
        if sh_.get("exposed", {}).get("sensitive"): add("high", "share_sensitive", f"Share '{sh_['name']}' is exposing {sharelib.describe(sh_['exposed'])} to anyone on your network, no password needed.", sh_["name"])
    
    if (445 in ports or 139 in ports) and not a.get("shares"): add("info", "smb", "File sharing (SMB) is on. No shares were visible without a password.")
    for line in a.get("nfs", []):
        if "*" in line: add("high", "nfs_any", "NFS export open to every device: " + line, line)
        else: add("medium", "nfs", "NFS export: " + line, line)
    
    if 3389 in ports: add("medium", "rdp", "Remote Desktop is reachable on your network. Use a strong password and keep it updated.")
    if 5900 in ports: add("medium", "vnc", "VNC remote screen is reachable. Many VNC setups use weak or no passwords.")
    if a.get("upnp_igd"): add("medium", "upnp", "UPnP is on. Apps can open ports in your router without asking. Turn it off if you don't need it.")
    if a.get("upnp_media"): add("info", "dlna", "A media server (DLNA) is sharing files on your network.")
    if 554 in ports: add("info", "rtsp", "A video stream port (RTSP) is open, which is typical of cameras.")
    if 80 in ports and 443 not in ports: add("info", "http", "This device has a web page on port 80 with no HTTPS.")

    kind = a.get("kind")
    admin_class = kind in weakauth.DEFAULT_RISK_KINDS
    web = a.get("web") or {}
    if a.get("smb1"): add("high", "smb1", "Old SMBv1 file sharing is switched on. It's the flaw behind WannaCry and is unsafe. Turn SMBv1 off (on the device, or on Windows via Turn Windows features on or off).")
    if a.get("rtsp", {}).get("open"): add("high", "camera_open", "A camera video stream (RTSP) plays on your network with no password. Anyone here can watch it. Set a password on the camera, or turn the stream off.")
    if web.get("auth") == "open" and admin_class: add("high", "admin_open", "This device's web page opens with no login at all, so anyone on your network can control it. Set a password on it now.")
    if admin_class and web.get("auth") in ("basic", "login_form", "open"): add("info", "default_risk", "This device has a reachable admin page. Devices like it often ship with a default password. Open its page and make sure yours has been changed to something strong and unique.")
    if web.get("plain") and web.get("auth") in ("basic", "login_form") and admin_class: add("medium", "http_login_plain", "This device's admin login is sent over plain HTTP, so anyone on your WiFi can read the password as you type it. Use its HTTPS page if it has one, or keep this device off shared WiFi.")

    probes = a.get("probes") or {}
    for _, data in probes.items():
        h = data.get("http") or {}
        if h.get("default_banner"): add("high", "default_banner", "This device's login page says it is still on the default password.")
        s = data.get("ssh") or {}
        if s.get("legacy"): add("medium", "ssh_legacy", "SSH offers old algorithms (ssh-rsa, diffie-hellman-group1-sha1) that are no longer safe.")
        sn = data.get("snmp") or {}
        if sn.get("answered"): add("medium", "snmp_public", f"SNMP answers the default 'public' community string (sysDescr: {sn.get('sysdescr', '')[:60]}).")
    
    credr = a.get("default_cred_result") or {}
    if credr.get("success"): add("high", "default_cred_success", "Admin login accepts a documented factory default credential.")
    if credr.get("lockout"): add("info", "default_cred_lockout", "Lockout suspected during credential test; re-test manually after checking the device.")

    for f in a.get("extra_findings", []): add(f["level"], f["id"], f["text"])
    cves = a.get("cves", [])
    if cves:
        critical = [c for c in cves if c["cvss"] >= 9.0]
        high = [c for c in cves if 7.0 <= c["cvss"] < 9.0]
        if critical:
            names = ", ".join(c["id"] for c in critical[:3]) + (" and more" if len(critical) > 3 else "")
            add("high", "cve_critical", f"Critical vulnerabilities found: {names}.")
        elif high:
            names = ", ".join(c["id"] for c in high[:3]) + (" and more" if len(high) > 3 else "")
            add("medium", "cve_high", f"High-risk vulnerabilities found: {names}.")

    known = set(PORT_NAMES) | {2323, 5555, 1883, 9999}
    other = [p for p in a.get("ports", []) if p["port"] not in known and p["port"] not in EXPECTED_PORTS]
    if other: add("info", "other_ports", "Other open ports: " + ", ".join(f"{p['port']} ({p['name']})" for p in other) + ". Not a problem by themselves, but worth knowing what they are.")
    order = {"high": 0, "medium": 1, "info": 2}
    return sorted(out, key=lambda f: order[f["level"]])

REUSE_FOR = 7 * 86400
def plan_reuse(ips, prev, key, now, force=False):
    due, reuse = [], []
    for ip in ips:
        at = (prev.get(ip) or {}).get(key)
        (reuse if at and not force and now - at < REUSE_FOR else due).append(ip)
    return due, reuse

def merge_deep(root, res):
    done = set()
    for h in root.findall("host"):
        ip = host_ip(h)
        if ip not in res: continue
        st = h.find("status")
        if st is not None and st.get("reason") == "user-set" and h.find("ports") is None: continue
        if h.find("ports") is None: continue
        have = {p["port"] for p in res[ip]["ports"]}
        for p in h.findall("ports/port"):
            pst = p.find("state")
            if pst is None or pst.get("state") != "open": continue
            n = int(p.get("portid"))
            if n in have: continue
            svc = p.find("service")
            res[ip]["ports"].append({"port": n, "name": IOT_PORT_NAMES.get(n) or PORT_NAMES.get(n) or (svc.get("name") if svc is not None else str(n)), "deep": True})
        res[ip]["depth"] = "deep"
        done.add(ip)
    return done

def audit_changes(before, after, name):
    if not before or "ports" not in before: return []
    out = []
    key = lambda f: (f["id"], f.get("what", ""))
    old = {key(f): f for f in assess(before)}
    new = {key(f): f for f in after["findings"]}
    for k, f in new.items():
        if k not in old and f["level"] in ("high", "medium"): out.append(("problem_new", f["level"], f"{name}: {f['text']}"))
    for k, f in old.items():
        if k not in new and f["level"] in ("high", "medium"): out.append(("problem_fixed", "info", f"Fixed on {name}: {f['text']}"))
    same_depth = before.get("depth", "common") == after.get("depth", "common")
    scope = (lambda p: True) if same_depth else (lambda p: p in PORT_NAMES)
    was = {p["port"]: p["name"] for p in before.get("ports", []) if scope(p["port"])}
    now = {p["port"]: p["name"] for p in after.get("ports", []) if scope(p["port"])}
    explained = {f["id"] for f in after["findings"]}
    opened = [f"{now[p]} ({p})" for p in sorted(set(now) - set(was))]
    closed = [f"{was[p]} ({p})" for p in sorted(set(was) - set(now))]
    if opened:
        risky = any(p not in EXPECTED_PORTS for p in set(now) - set(was))
        out.append(("ports_opened", "medium" if risky and not explained & {"telnet", "adb"} else "info", f"{name} opened {', '.join(opened)}."))
    if closed: out.append(("ports_closed", "info", f"{name} closed {', '.join(closed)}."))
    return out

def audit(full=False):
    c = db()
    net = current_net()
    rows = [dict(r) for r in c.execute("SELECT mac, ip, kind, vendor, name, hostname, audit FROM devices WHERE online=1 AND net=?", (net,))]
    c.close()
    if not rows: return
    now = time.time()
    prev = {}
    for r in rows:
        try: prev[r["ip"]] = json.loads(r.pop("audit") or "null") or {}
        except ValueError: prev[r["ip"]] = {}
    ips = [r["ip"] for r in rows]
    res = {ip: {"ports": [], "shares": [], "ftp_anon": False, "nfs": []} for ip in ips}

    set_step(1, "Checking common ports")
    root = run_nmap(["-Pn", "-T4", "--open", "--max-retries", "1", "--host-timeout", "90s", "-p", PORTS] + ips, 900)
    for h in root.findall("host"):
        ip = host_ip(h)
        if ip not in res: continue
        for p in h.findall("ports/port"):
            st = p.find("state")
            if st is None or st.get("state") != "open": continue
            n = int(p.get("portid"))
            svc = p.find("service")
            res[ip]["ports"].append({"port": n, "name": PORT_NAMES.get(n, svc.get("name") if svc is not None else str(n))})

    def with_open(*nums): return [ip for ip, r in res.items() if any(p["port"] in nums for p in r["ports"])]
    notes = []
    def stage(label, fn):
        if state.get("stop_requested"):
            raise RuntimeError("Scan stopped by user.")
        try:
            fn()
        except RuntimeError as e:
            if state.get("stop_requested"):
                raise RuntimeError("Scan stopped by user.")
            notes.append(f"{label}: {e}")
        except subprocess.TimeoutExpired:
            if state.get("stop_requested"):
                raise RuntimeError("Scan stopped by user.")
            notes.append(f"{label}: timed out")

    def smb_stage():
        hosts = with_open(139, 445)
        if not hosts: return
        root = run_nmap(["-Pn", "-p", "139,445", "--script", "smb-protocols,smb-enum-shares,smb-ls", "--script-args", "ls.maxfiles=200,ls.maxdepth=1", "--script-timeout", "120s"] + hosts, 1200)
        for h in root.findall("host"):
            ip, sc = host_ip(h), find_script(h, "smb-enum-shares")
            if ip not in res or sc is None: continue
            res[ip]["shares"] = parse_shares(sc)
            proto = find_script(h, "smb-protocols")
            if proto is not None and weakauth.smb1_enabled(proto): res[ip]["smb1"] = True
            ls = find_script(h, "smb-ls")
            listing = sharelib.parse_smb_ls(ls) if ls is not None else {}
            by_name = {k.lower(): v for k, v in listing.items()}
            for sh_ in res[ip]["shares"]:
                files = by_name.get(sh_["name"].lower())
                if files is not None:
                    sh_["files"] = files
                    sh_["exposed"] = sharelib.classify(files)

    def ftp_stage():
        hosts = with_open(21)
        if not hosts: return
        root = run_nmap(["-Pn", "-p", "21", "--script", "ftp-anon", "--script-timeout", "30s"] + hosts, 600)
        for h in root.findall("host"):
            ip, sc = host_ip(h), find_script(h, "ftp-anon")
            if ip in res and sc is not None: res[ip]["ftp_anon"] = "anonymous ftp login allowed" in (sc.get("output") or "").lower()
        for ip in with_open(21):
            if res[ip].get("ftp_anon"):
                files = sharelib.list_ftp(ip)
                if files:
                    res[ip]["ftp_files"] = files
                    res[ip]["ftp_exposed"] = sharelib.classify(files)

    def nfs_stage():
        hosts = with_open(111, 2049)
        if not hosts: return
        root = run_nmap(["-Pn", "-p", "111,2049", "--script", "nfs-showmount", "--script-timeout", "30s"] + hosts, 600)
        for h in root.findall("host"):
            ip, sc = host_ip(h), find_script(h, "nfs-showmount")
            if ip in res and sc is not None: res[ip]["nfs"] = parse_lines(sc.get("output"))

    def os_stage():
        if not is_admin(): return
        due, reuse = plan_reuse(ips, prev, "os_at", now, full)
        for ip in reuse:
            if prev[ip].get("os"): res[ip]["os"] = prev[ip]["os"]
            res[ip]["os_at"] = prev[ip]["os_at"]
        if not due: return
        state["phase"] = f"Guessing operating systems for {len(due)} device(s)" + (f", reusing {len(reuse)} from the last week" if reuse else "")
        root = run_nmap(["-Pn", "-O", "--osscan-limit", "--max-os-tries", "1", "-T4", "-p", "1," + PORTS] + due, 900)
        for ip in due: res[ip]["os_at"] = now
        for h in root.findall("host"):
            ip, best = host_ip(h), h.find("os/osmatch")
            if ip in res and best is not None and int(best.get("accuracy", "0")) >= 85: res[ip]["os"] = {"name": best.get("name"), "accuracy": int(best.get("accuracy"))}

    set_step(2, "Checking file sharing")
    stage("Share check", smb_stage)
    stage("FTP check", ftp_stage)
    stage("NFS check", nfs_stage)

    def deep_stage():
        hosts = [r["ip"] for r in rows if r.get("kind") in DEEP_KINDS or not r.get("vendor") or 8001 in {p["port"] for p in res[r["ip"]]["ports"]}]
        hosts = [h for h in hosts if h != state.get("own_ip")]
        due, reuse = plan_reuse(hosts, prev, "deep_at", now, full)
        for ip in reuse:
            have = {p["port"] for p in res[ip]["ports"]}
            res[ip]["ports"] += [p for p in prev[ip].get("ports", []) if p.get("deep") and p["port"] not in have]
            res[ip].update(depth="deep", deep_at=prev[ip]["deep_at"])
        if not due: return
        state["phase"] = f"Deep-checking {len(due)} device(s)" + (f", reusing results for {len(reuse)} checked in the last week" if reuse else "")
        root = run_nmap(["-Pn", "--max-retries", "1", "--max-rate", "1000", "--host-timeout", "5m", "-p", DEEP_PORTS] + due, 1200)
        for ip in merge_deep(root, res): res[ip]["deep_at"] = now

    set_step(3, "Guessing operating systems")
    stage("OS guess", os_stage)
    set_step(4, "Deep-checking smart-home devices")
    stage("Deep check", deep_stage)

    def vuln_stage():
        hosts = [ip for ip, r in res.items() if r["ports"] and ip != state.get("own_ip")]
        if not hosts: return
        state["phase"] = f"Checking for known CVEs on {len(hosts)} device(s)"
        root = run_nmap(["-Pn", "-sV", "--script", "vulners", "-p", PORTS] + hosts, 1200)
        for h in root.findall("host"):
            ip = host_ip(h)
            sc = find_script(h, "vulners")
            if ip in res and sc is not None:
                cves = cvelib.parse_vulners(sc)
                if cves: res[ip]["cves"] = cves

    set_step(5, "Checking for known CVEs")
    stage("Vulnerability check", vuln_stage)

    def probe_stage():
        for ip, r in res.items():
            if ip == state.get("own_ip"): continue
            ports = {p["port"] for p in r["ports"]}
            if not ports: continue
            row = next((x for x in rows if x["ip"] == ip), {})
            try_snmp = row.get("kind") == "router" or r.get("upnp_igd") or 161 in ports
            probes = probelib.probe_device(ip, ports, try_snmp=try_snmp)
            if probes:
                r["probes"] = probes
                r["fingerprint"] = probelib.fingerprint(probes)

    set_step(6, "Probing what's behind open ports")
    stage("Probe", probe_stage)

    def login_stage():
        for ip, r in res.items():
            if ip == state.get("own_ip"): continue
            ports = {p["port"] for p in r["ports"]}
            web = set(weakauth.WEB_PORTS) & ports
            if web:
                info = weakauth.check_web(ip, ports)
                if info: r["web"] = info
            if ports & {554, 8554}:
                rt = weakauth.probe_rtsp(ip, 554 if 554 in ports else 8554)
                if rt: r["rtsp"] = rt

    set_step(7, "Checking logins and camera streams")
    stage("Login check", login_stage)

    def cred_stage():
        if not net_setting(net, "allow_default_cred_checks", False): return
        consented = set(net_setting(net, "cred_consent", []))
        if not consented: return
        c2 = db()
        try:
            c2.execute("""CREATE TABLE IF NOT EXISTS default_cred_audit (ts REAL, host TEXT, port INTEGER, username TEXT, status TEXT, mac TEXT)""")
            def log_fn(host, port, user, status, _mac=None): c2.execute("INSERT INTO default_cred_audit VALUES (?,?,?,?,?,?)", (time.time(), host, port, user, str(status), _mac or ""))
            c2.commit()
            for ip, r in res.items():
                row = next((x for x in rows if x["ip"] == ip), None)
                if not row or row["mac"] not in consented: continue
                
                # Fallback: use MAC vendor or UPnP maker if the HTTP fingerprint is useless
                # (e.g. routers that return a generic "302 Found" or "Login" page)
                fp = r.get("fingerprint") or ""
                useless = {"302 Found", "301 Moved Permanently", "401 Unauthorized", 
                           "403 Forbidden", "404 Not Found", "Redirecting...", "Login", "Router"}
                if not fp or fp in useless:
                    fp = row.get("vendor") or ""
                    if not fp and r.get("info"):
                        fp = r["info"].get("maker") or r["info"].get("model") or ""

                if not credlib.lookup(fp):
                    r["default_cred_result"] = {"skipped": f"No documented defaults matched fingerprint '{fp}'"}
                    continue
                    
                ports = {p["port"] for p in r["ports"]}
                https_port = next((p for p in (443, 8443, 9443) if p in ports), None)
                http_port = next((p for p in (80, 8000, 8080, 8888) if p in ports), None)
                
                if https_port: result = credlib.check_http_defaults(ip, https_port, True, fp, True, log_fn=lambda h, p, u, s, _m=row["mac"]: log_fn(h, p, u, s, _m))
                elif http_port: result = credlib.check_http_defaults(ip, http_port, False, fp, True, log_fn=lambda h, p, u, s, _m=row["mac"]: log_fn(h, p, u, s, _m))
                else: result = {"skipped": "No web admin port open"}
                
                # ALWAYS save the result so the UI stops saying 'Waiting...'
                r["default_cred_result"] = result
                c2.commit()
        finally: c2.close()

    set_step(8, "Checking factory-default credentials")
    stage("Credential check", cred_stage)

    def mitm_stage():
        findings = mitmlib.check_arp()
        for f in findings:
            for ip in f.get("ips", []):
                if ip in res: res[ip].setdefault("extra_findings", []).append(f)

    set_step(9, "Checking for ARP spoofing")
    stage("MITM check", mitm_stage)

    set_step(10, "Reading device names")
    ssdp = ssdp_scan(state.get("own_ip"))
    ports_of = {ip: {p["port"] for p in r["ports"]} for ip, r in res.items()}
    mdns = mdns_scan(state.get("own_ip"), ips)

    stamp = time.time()
    c = db()
    for r in rows:
        a = res[r["ip"]]
        a["kind"] = r.get("kind")
        seen = ssdp.get(r["ip"], {"st": set(), "loc": None})
        a["upnp_igd"] = any("InternetGatewayDevice" in st for st in seen["st"])
        a["upnp_media"] = any("MediaServer" in st for st in seen["st"])
        sources = []
        if 8001 in ports_of[r["ip"]]: sources.append(samsung_info(r["ip"]))
        if seen["loc"]: sources.append(upnp_info(r["ip"], seen["loc"]))
        if r["ip"] in mdns: sources.append(mdns_info(mdns[r["ip"]]))
        info = {}
        for src in sources:
            for k, v in src.items():
                if v and k not in info: info[k] = v
        size = size_from_model(info.get("model"))
        if size: info["size_in"] = size
        a["info"] = info
        a["scanned"] = stamp
        a.setdefault("depth", "common")
        a["findings"] = assess(a)
        for kind, level, text in audit_changes(prev.get(r["ip"]), a, device_label(dict(r, audit=a))): record(net, kind, level, text, r["mac"], stamp, c)
        c.execute("UPDATE devices SET audit=? WHERE net=? AND mac=?", (json.dumps(a), net, r["mac"]))
        if is_tv(a): c.execute("UPDATE devices SET kind='tv' WHERE net=? AND mac=?", (net, r["mac"]))
    c.commit()
    c.close()
    state["audit_note"] = "; ".join(notes) or None
    return ssdp
