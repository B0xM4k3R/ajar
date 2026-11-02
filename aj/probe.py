"""Deep, read-only introspection of what's behind an open port."""
import socket, ssl, re, http.client
BANNER_TIMEOUT = 3.0
HTTP_TIMEOUT   = 4.0
BODY_LIMIT     = 65536
def _first(xs): return xs[0].strip() if xs else ""
def _realm(header):
    m = re.search(r'realm="([^"]+)"', header or "")
    return m.group(1) if m else ""
def _dn(seq): return ", ".join(f"{k}={v}" for rdn in seq for k, v in rdn)
def grab_banner(host, port, timeout=BANNER_TIMEOUT):
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            return s.recv(1024).decode("utf-8", "replace").strip()
    except (socket.timeout, ConnectionError, OSError):
        return ""
def http_probe(host, port, tls=False, timeout=HTTP_TIMEOUT):
    out = {"scheme": "https" if tls else "http"}
    try:
        if tls:
            ctx = ssl._create_unverified_context()
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.request("GET", "/", headers={"User-Agent": "ajar-probe/1"})
        r = conn.getresponse()
        body = r.read(BODY_LIMIT).decode("utf-8", "replace")
        out.update({
            "status": r.status, "server": r.getheader("Server", ""), "powered_by": r.getheader("X-Powered-By", ""),
            "auth_realm": _realm(r.getheader("WWW-Authenticate", "")), "location": r.getheader("Location", ""),
            "title": _first(re.findall(r"<title[^>]*>(.*?)</title>", body, re.S | re.I)),
            "generator": _first(re.findall(r'name=["\']generator["\'][^>]*content=["\']([^"\']+)', body, re.I)),
            "login_form": bool(re.search(r"<input[^>]+type=[\"']?password", body, re.I)),
            "default_banner": bool(re.search(r"default (password|credential)", body, re.I)),
        })
        conn.close()
    except Exception as e: out["error"] = type(e).__name__
    return out
def tls_info(host, port, timeout=HTTP_TIMEOUT):
    out = {}
    try:
        ctx = ssl._create_unverified_context()
        with socket.create_connection((host, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                c = ss.getpeercert()
                out = {
                    "version": ss.version(), "cipher": ss.cipher()[0],
                    "subject": _dn(c.get("subject", [])), "issuer": _dn(c.get("issuer", [])),
                    "san": [v for k, v in c.get("subjectAltName", []) if k == "DNS"],
                    "not_after": c.get("notAfter"), "self_signed": c.get("subject") == c.get("issuer"),
                }
    except Exception as e: out["error"] = type(e).__name__
    return out
def ssh_probe(host, port=22, timeout=BANNER_TIMEOUT):
    banner = grab_banner(host, port, timeout)
    m = re.search(r"SSH-\S+-(.+)", banner)
    legacy = []
    if re.search(r"OpenSSH_(?:[0-6]\.|7\.[0-1])", banner) or "dropbear_20" in banner:
        legacy = ["ssh-rsa", "diffie-hellman-group1-sha1"]
    return {"banner": banner, "software": m.group(1).strip() if m else "", "legacy": legacy}
def snmp_public(host, timeout=2.0):
    import shutil, subprocess
    if not shutil.which("snmpget"): return {"answered": False, "reason": "snmpget not installed"}
    try:
        r = subprocess.run(["snmpget", "-v1", "-c", "public", "-t", "1", "-r", "0", host, "1.3.6.1.2.1.1.1.0"], capture_output=True, text=True, timeout=timeout)
        if r.returncode == 0 and "STRING:" in r.stdout: return {"answered": True, "sysdescr": r.stdout.split("STRING:")[1].strip()}
    except Exception: pass
    return {"answered": False}
def probe_device(host, open_ports, try_snmp=False):
    out = {}
    http_ports  = [p for p in open_ports if p in (80, 8000, 8080, 8888, 5000, 8081, 9000)]
    https_ports = [p for p in open_ports if p in (443, 8443, 9443, 5001)]
    for p in http_ports: out[p] = {"http": http_probe(host, p)}
    for p in https_ports: out[p] = {"http": http_probe(host, p, tls=True), "tls": tls_info(host, p)}
    if 22 in open_ports: out[22] = {"ssh": ssh_probe(host)}
    if 23 in open_ports: out[23] = {"banner": grab_banner(host, 23)}
    if 21 in open_ports: out[21] = {"banner": grab_banner(host, 21)}
    if try_snmp:
        sn = snmp_public(host)
        if sn.get("answered"): out[161] = {"snmp": sn}
    return out
def fingerprint(probes):
    for _, data in probes.items():
        h = data.get("http", {})
        for k in ("title", "server"):
            v = h.get(k, "")
            if v: return v
        t = data.get("tls", {})
        if t.get("subject"): return t["subject"].split("=")[-1]
        s = data.get("ssh", {})
        if s.get("software"): return s["software"]
    return ""
