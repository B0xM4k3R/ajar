"""Exposed and unencrypted: logins that are wide open, sent in the clear, or likely
still on their factory default.

Everything here is read-only and never tries a password. It asks the same first
question any visitor's browser asks ("do you want a login?") and notes the answer:
  - A web admin page that answers 200 with no login at all -> wide open.
  - A camera stream (RTSP) that plays without asking -> wide open.
  - Telnet, FTP, plain-HTTP logins, SMBv1 -> a password typed here travels unencrypted.
  - A camera/router/printer/DVR whose login is reachable -> a reminder to make sure the
    factory default password was changed (Ajar does not display or test default passwords).
"""
import re
import socket
import urllib.request

# Device kinds that ship with a web/Telnet admin and are infamous for unchanged defaults.
DEFAULT_RISK_KINDS = {"iot", "tv", "printer", "router"}
WEB_PORTS = [80, 8080, 8000, 8888, 443, 8443]
LOGIN_HINT = re.compile(r"(type=['\"]?password|name=['\"]?(pass|password|pwd|login)|"
                        r"<title>[^<]*(login|sign in|router|camera|nvr|dvr|webcam)[^<]*</title>)", re.I)


# ---------------------------------------------------------------- SMB protocol version

def smb1_enabled(script):
    """Reads nmap's smb-protocols output. SMBv1 shows as the 'NT LM 0.12' dialect (or a
    line naming SMBv1/SMB1). SMBv1 is the WannaCry/EternalBlue protocol."""
    text = (script.get("output") or "").lower()
    if "nt lm 0.12" in text or re.search(r"\bsmb\s*v?1\b", text):
        return True
    for t in script.iter("elem"):
        v = (t.text or "").lower()
        if "nt lm 0.12" in v or v.strip() in ("smbv1", "smb1"):
            return True
    return False


# ---------------------------------------------------------------- HTTP admin auth state

def classify_http(status, www_authenticate, body, scheme):
    """Works out, from one GET of a device's web root, whether its admin page is
    protected. Returns one of: 'basic' (asks for a login), 'open' (served with no login),
    'login_form' (a login page, so app-level auth), or 'unknown'. Also whether the login,
    if any, would travel unencrypted (plain HTTP)."""
    plain = scheme == "http"
    if status in (401, 407) or (www_authenticate or "").strip():
        return {"auth": "basic", "plain": plain, "reachable": True}
    if status in (403,):
        return {"auth": "basic", "plain": plain, "reachable": True}
    if status and 200 <= status < 300:
        # If the page has a password field, login form, or the word "login", 
        # it's a login page, NOT a wide-open page.
        if LOGIN_HINT.search(body or ""):
            return {"auth": "login_form", "plain": plain, "reachable": True}
        # Fallback: also catch generic login words if LOGIN_HINT missed them
        if re.search(r'(?i)(sign\s*in|log\s*in|login|password|username|passwd)', body or ""):
            return {"auth": "login_form", "plain": plain, "reachable": True}
        return {"auth": "open", "plain": plain, "reachable": True}
    if status and 300 <= status < 400:
        return {"auth": "login_form", "plain": plain, "reachable": True}  # redirect, usually to a login
    return {"auth": "unknown", "plain": plain, "reachable": bool(status)}


def probe_http(ip, port, timeout=4):
    """GETs a device's web root once, read-only, and classifies its login. Returns None
    if nothing answers."""
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{ip}:{port}/"
    ctx = None
    if scheme == "https":
        import ssl
        ctx = ssl._create_unverified_context()  # we're only reading the status, not trusting it
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    req = urllib.request.Request(url, headers={"User-Agent": "Ajar"}, method="GET")
    try:
        with opener.open(req, timeout=timeout, **({"context": ctx} if ctx else {})) as r:
            body = r.read(20000).decode("utf-8", "replace")
            info = classify_http(r.status, r.headers.get("WWW-Authenticate"), body, scheme)
    except urllib.error.HTTPError as e:
        info = classify_http(e.code, e.headers.get("WWW-Authenticate"), "", scheme)
    except (urllib.error.URLError, OSError, ValueError, socket.timeout):
        return None
    info["port"], info["scheme"], info["url"] = port, scheme, f"{scheme}://{ip}:{port}/"
    return info


def check_web(ip, open_ports, timeout=4):
    """Probes the first reachable web port and returns its auth state, preferring HTTPS."""
    for port in sorted(set(open_ports) & set(WEB_PORTS), key=lambda p: (p not in (443, 8443), p)):
        info = probe_http(ip, port, timeout)
        if info:
            return info
    return None


# ---------------------------------------------------------------- RTSP camera stream

def rtsp_open_noauth(response_text):
    """From an RTSP DESCRIBE reply, True only when the stream is served with no login.
    A 401/403 means it asks for one (good); a 200 means it played without asking."""
    m = re.match(r"RTSP/\d\.\d\s+(\d{3})", (response_text or "").strip())
    if not m:
        return False
    code = int(m.group(1))
    if code in (401, 403):
        return False
    return code == 200


def probe_rtsp(ip, port=554, timeout=4):
    """Sends OPTIONS then DESCRIBE (read-only queries, no credentials) and reports whether
    the stream answered without asking for a login. Returns None if nothing answers."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            url = f"rtsp://{ip}:{port}/"
            s.sendall(f"DESCRIBE {url} RTSP/1.0\r\nCSeq: 1\r\nAccept: application/sdp\r\n\r\n".encode())
            data = s.recv(2048).decode("utf-8", "replace")
            return {"open": rtsp_open_noauth(data), "port": port, "url": url}
    except (OSError, socket.timeout):
        return None
