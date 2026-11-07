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
BOGUS = ("ajar-probe-user", "ajar-probe-not-a-password")  # a login no device can have as a default
REDIRECT = (301, 302, 303, 307, 308)
LOGIN_WORDS = ("login", "signin", "sign-in", "error", "denied", "fail")


def _request(host, port, tls, method="GET", body=None, headers=None):
    import http.client, ssl
    ctx = ssl._create_unverified_context() if tls else None
    conn = (http.client.HTTPSConnection(host, port, timeout=5, context=ctx) if tls
            else http.client.HTTPConnection(host, port, timeout=5))
    try:
        conn.request(method, "/", body, {"User-Agent": "ajar/1", **(headers or {})})
        r = conn.getresponse()
        text = r.read(8192).decode("utf-8", "replace").lower()
        return {"status": r.status, "location": r.getheader("Location", "") or "",
                "www": r.getheader("WWW-Authenticate", "") or "", "body": text}
    finally:
        conn.close()


def _locked(r):
    return r["status"] == 429 or "too many" in r["body"] or "locked" in r["body"]


def _has_pw_field(body):
    return bool(re.search(r"<input[^>]+type=[\"']?password", body, re.I))


def _post_login(host, port, tls, user, pw):
    from urllib.parse import urlencode
    return _request(host, port, tls, "POST", urlencode({"username": user, "password": pw}),
                    {"Content-Type": "application/x-www-form-urlencoded"})


def _form_success(r, bogus):
    """A form login worked only if the page reacted differently to the default login than to a
    made-up one. A device that answers every POST alike (or an open page) proves nothing."""
    if r["status"] >= 400 or _locked(r):
        return False
    if r["status"] in REDIRECT:
        loc = r["location"].lower()
        return loc != bogus["location"].lower() and not any(w in loc for w in LOGIN_WORDS)
    if r["status"] == 200:
        return not _has_pw_field(r["body"]) and (_has_pw_field(bogus["body"]) or bogus["status"] != 200)
    return False


def _try_http_login(host, port, tls, user, pw, base=None):
    """Tries one default login. `base` is a dict shared across the attempts on one device: it
    holds the comparison requests so they are made once. Extra attempts made on the device's
    behalf are listed in base["events"] so the caller can log them too.

    Success is only reported when the device behaves differently for the default login than
    for no login (HTTP Basic) or for a made-up login (forms). A page that is open to everyone,
    or that answers everything with the same 200, is not a 'default password works' result."""
    base = {} if base is None else base
    try:
        if "noauth" not in base:
            base["noauth"] = _request(host, port, tls)
        na = base["noauth"]
        if na["status"] in (401, 403) or "basic" in na["www"].lower():
            import base64
            token = base64.b64encode(f"{user}:{pw}".encode()).decode()
            r = _request(host, port, tls, headers={"Authorization": f"Basic {token}"})
            return {"ok": 200 <= r["status"] < 300, "status": r["status"], "lockout_signal": _locked(r)}
        if "bogus_form" not in base:  # one made-up login, to see what a wrong password looks like
            base["bogus_form"] = _post_login(host, port, tls, *BOGUS)
            base.setdefault("events", []).append((BOGUS[0], base["bogus_form"]["status"]))
        r = _post_login(host, port, tls, user, pw)
        return {"ok": _form_success(r, base["bogus_form"]), "status": r["status"], "lockout_signal": _locked(r)}
    except Exception as e:
        return {"ok": False, "status": type(e).__name__, "lockout_signal": False}


def check_http_defaults(host, port, tls, fp, consent, log_fn=None):
    if not consent: return {"skipped": "no per-device consent"}
    pairs = lookup(fp)
    if not pairs: return {"skipped": "no documented defaults for fingerprint"}
    tried, success, lockout = [], False, False
    todo = pairs[:MAX_ATTEMPTS_PER_RUN]
    base = {}
    for i, (user, pw) in enumerate(todo):
        result = _try_http_login(host, port, tls, user, pw, base)
        for extra_user, extra_status in base.pop("events", []):  # comparison attempts are logged too
            if log_fn: log_fn(host, port, extra_user, extra_status)
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
