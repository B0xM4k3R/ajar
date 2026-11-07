"""Factory-default credential check. Off by default. Tier C."""
import re
import time
DEFAULTS = [
    ("TP-Link", [("admin", "admin")]), ("Netgear", [("admin", "password")]),
    ("D-Link", [("admin", ""), ("admin", "admin")]), ("Linksys", [("admin", "admin")]),
    ("ASUS", [("admin", "admin")]), ("ZyXEL", [("admin", "1234")]),
    ("MikroTik", [("admin", "")]), ("Ubiquiti", [("ubnt", "ubnt")]),
    ("SonicWall", [("admin", "password")]), ("Fortinet", [("admin", "")]),
    ("pfSense", [("admin", "pfsense")]), ("Cisco", [("cisco", "cisco"), ("admin", "admin")]),
    ("Hikvision", [("admin", "12345")]), ("Dahua", [("admin", "admin"), ("888888", "888888")]),
    ("Axis", [("root", "pass")]), ("Foscam", [("admin", "")]),
    ("Reolink", [("admin", "")]), ("Synology", [("admin", "")]),
    ("QNAP", [("admin", "admin")]), ("HP", [("admin", "")]),
    ("Brother", [("admin", "access")]), ("Canon", [("admin", "")]),
    ("HPE", [("admin", "")]), ("Aruba", [("admin", "admin")]),
]
LOCKOUT_STOP_AFTER, LOCKOUT_BACKOFF, MAX_ATTEMPTS_PER_RUN = 3, 30, 6
def lookup(fp):
    """Finds documented defaults for a fingerprint. Matches whole words only, so the
    banner 'Apache PHP/7.4' does not count as an HP device."""
    if not fp: return []
    for key, pairs in DEFAULTS:
        if re.search(r"(?<![A-Za-z0-9])" + re.escape(key) + r"(?![A-Za-z0-9])", fp, re.I): return pairs
    return []
def _try_http_login(host, port, tls, user, pw):
    import http.client, ssl, base64
    try:
        ctx = ssl._create_unverified_context() if tls else None
        conn = (http.client.HTTPSConnection(host, port, timeout=5, context=ctx) if tls else http.client.HTTPConnection(host, port, timeout=5))
        token = base64.b64encode(f"{user}:{pw}".encode()).decode()
        conn.request("GET", "/", headers={"Authorization": f"Basic {token}", "User-Agent": "ajar/1"})
        r = conn.getresponse()
        body = r.read(4096).decode("utf-8", "replace").lower()
        status = r.status
        if status == 200 and "invalid" not in body and "incorrect" not in body and "login" not in body[:400]:
            conn.close()
            return {"ok": True, "status": status, "lockout_signal": False}
        conn.request("POST", "/", f"username={user}&password={pw}".encode(), {"Content-Type": "application/x-www-form-urlencoded", "User-Agent": "ajar/1"})
        r = conn.getresponse()
        body = r.read(4096).decode("utf-8", "replace").lower()
        status = r.status
        conn.close()
        ok = status in (200, 302) and "invalid" not in body and "incorrect" not in body and "too many" not in body
        lock = "too many" in body or "locked" in body or status == 429
        return {"ok": ok, "status": status, "lockout_signal": lock}
    except Exception as e: return {"ok": False, "status": type(e).__name__, "lockout_signal": False}
def check_http_defaults(host, port, tls, fp, consent, log_fn=None):
    if not consent: return {"skipped": "no per-device consent"}
    pairs = lookup(fp)
    if not pairs: return {"skipped": "no documented defaults for fingerprint"}
    tried, success, lockout = [], False, False
    todo = pairs[:MAX_ATTEMPTS_PER_RUN]
    for i, (user, pw) in enumerate(todo):
        result = _try_http_login(host, port, tls, user, pw)
        if log_fn: log_fn(host, port, user, result["status"])
        tried.append({"user": user, "status": result["status"]})
        if result["ok"]:
            success = True
            break
        more = i + 1 < len(todo)
        if result["lockout_signal"]:
            lockout = True
            break
        if len(tried) >= LOCKOUT_STOP_AFTER and more:
            lockout = True  # stopped early to avoid tripping a real lockout
            break
        if more:
            time.sleep(LOCKOUT_BACKOFF)  # no pointless wait after the last attempt
    return {"tried": tried, "success": success, "lockout": lockout, "fingerprint": fp}
