"""The dashboard's web server and API."""
import base64
import gzip
import hashlib
import ipaddress
import json
import re
import os
import socket
import time
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import config
from .config import state
from .db import db, net_setting, set_net_setting
from .tools import is_admin
from .wifi_analyze import set_mine, wifi_snapshot
from .score import security_report
from .networks import all_networks, current_net, rename_network
from .events import latest_id, recent
from .jobs import start_scan, start_wifi
from . import alerts
from . import netcheck
from . import report
from . import auth as authlib
from .auth import auth


STATIC = {  # the dashboard's files, in web/
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/app.css": ("app.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
}


def ip_key(row):
    try:
        return tuple(int(x) for x in row["ip"].split("."))
    except (ValueError, AttributeError):
        return (999, 999, 999, 999)


def known_net(net):
    """A network id from a request, if ajar knows it; otherwise the current network."""
    nets = {n["id"] for n in all_networks()}
    return net if net in nets else current_net()


HEAVY_AUDIT_KEYS = ("probes", "ftp_files")  # large, and only shown when a device is expanded


def slim_audit(a):
    """A device's audit without the bulky parts: banners and probe results, and the file listings of
    shares and FTP. Everything the device row and the badges need stays."""
    if not isinstance(a, dict):
        return a
    out = {k: v for k, v in a.items() if k not in HEAVY_AUDIT_KEYS}
    if a.get("shares"):
        out["shares"] = [{k: v for k, v in s.items() if k != "files"} for s in a["shares"]]
    return out


def snapshot(net=None, expand=None):
    """Everything the dashboard shows, for one network: the current one by default,
    or saved results for another.

    expand=None gives the full detail for every device (reports use this). A set of MACs gives
    the compact form the 5-second refresh uses: full detail only for those devices (the ones the
    person has open), and a slim audit for the rest. The score is always worked out from the full data."""
    here = current_net()
    net = known_net(net) if net else here
    c = db()
    rows = [dict(r) for r in c.execute("SELECT * FROM devices WHERE net=?", (net or "",))]
    c.close()
    # Tell the UI which devices have been authorized for credential testing
    consented = set(net_setting(net, "cred_consent", []) if net else [])
    for r in rows:
        r["cred_consent"] = r["mac"] in consented
    for r in rows:
        try:
            r["audit"] = json.loads(r["audit"]) if r.get("audit") else None
        except ValueError:
            r["audit"] = None
    rows.sort(key=lambda r: (not r["online"], r["approved"], ip_key(r)))
    warn = None if is_admin() else ("Not running with admin rights: MAC addresses and vendors are unavailable. "
                                    "Use sudo on Linux and macOS, or Run as administrator on Windows. "
                                    "On a Pi, install it as a service with sudo ./setup.sh.")
    w = wifi_snapshot(net)
    nets = all_networks()
    # Until this session's first scan finishes, the remembered network counts as current.
    view = {"id": net, "current": net == here,
            **next(({k: n[k] for k in ("name", "subnet", "last_seen")} for n in nets if n["id"] == net), {})}
    sec = security_report(rows, w["result"], net=net if view["current"] else None,
                          exposure=net_setting(net, "exposure") if net else None,
                          netcheck=net_setting(net, "netcheck") if net else None)
    sec["allow_creds"] = bool(net and net_setting(net, "allow_default_cred_checks", False))
    if expand is not None:
        for r in rows:
            if r["mac"] not in expand:
                r["audit"] = slim_audit(r["audit"])
    return {"state": {**state, "warning": warn, "now": time.time()}, "devices": rows,
            "wifi": w, "security": sec,
            "network": view, "networks": nets, "events_latest": latest_id(net) if net else 0,
            "alerts": alerts.public_config(),
            "health": netcheck.health_summary(net_setting(net, "health", [])) if net else None}


def approve(net, mac):
    c = db()
    if mac == "all":
        c.execute("UPDATE devices SET approved=1 WHERE net=?", (net,))
    else:
        c.execute("UPDATE devices SET approved=1 WHERE net=? AND mac=?", (net, mac))
    c.commit()
    c.close()


def rename(net, mac, name):
    c = db()
    c.execute("UPDATE devices SET name=? WHERE net=? AND mac=?", ((name or "").strip()[:40] or None, net, mac))
    c.commit()
    c.close()


VIEWER_API = {"/api/state", "/api/events", "/api/report", "/api/ping"}  # what a view-only login may fetch


class Handler(BaseHTTPRequestHandler):
    timeout = 60  # drop idle connections, so they can't pile up
    role = "admin"  # set by authed(): "admin", or "viewer" for the view-only login
    body = b""      # the request body, read at the start of do_POST

    def log_message(self, *args):
        pass

    def setup(self):
        """With HTTPS on, look at the first byte: a TLS handshake starts with 0x16. Anything
        else is plain HTTP, which gets a redirect before any password is sent."""
        self.is_tls = False
        ctx = getattr(self.server, "ssl_ctx", None)
        if ctx:
            self.request.settimeout(10)
            if self.request.recv(1, socket.MSG_PEEK) == b"\x16":
                self.request = ctx.wrap_socket(self.request, server_side=True)
                self.is_tls = True
        super().setup()

    def finish(self):
        try:
            super().finish()
        finally:
            if self.is_tls:  # the server only closes the plain socket it handed us
                try:
                    self.request.close()
                except OSError:
                    pass

    def to_https(self):
        """Sends plain-HTTP visitors to the HTTPS address. Returns True if it did."""
        if not getattr(self.server, "ssl_ctx", None) or self.is_tls:
            return False
        host = self.headers.get("Host") or f"localhost:{config.PORT}"
        self.send_response(308)  # keeps the method, so a POST stays a POST
        self.send_header("Location", f"https://{host}{self.path}")
        self.send_header("Content-Length", "0")
        self.end_headers()
        return True

    def host_ok(self):
        """Only answer requests addressed to this device by a local name or private IP.
        Blocks DNS-rebinding attacks from web pages open in your browser."""
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]").lower()
        if host == "localhost" or host.endswith(".local") or ("." not in host and host):
            return True
        try:
            ip = ipaddress.ip_address(host)
            return ip.is_private or ip.is_loopback or ip.is_link_local
        except ValueError:
            return False

    def authed(self):
        """Checks the dashboard password. Sends the login prompt itself when it fails."""
        self.role = "admin"
        if not auth["hash"]:
            return True
        ip = self.client_address[0]
        too_many = lambda: self.send(429, {"error": "Too many wrong passwords. Try again in a few minutes."},
                                     extra={"Retry-After": str(authlib.LOCK_WINDOW)})
        if authlib.is_locked(ip):
            too_many()
            return False
        hdr = self.headers.get("Authorization", "")
        ok, role = False, None
        if hdr.startswith("Basic "):
            key = hashlib.sha256(hdr.encode()).hexdigest()
            role = authlib.is_good(key)
            if role:
                ok = True
            else:
                with authlib.verify_lock(ip):  # one password check at a time per address
                    role = authlib.is_good(key)  # a request that was waiting may have just verified it
                    if role:
                        ok = True
                    else:
                        token = authlib.reserve_attempt(ip)  # counted before it's checked, so guesses can't beat the limit
                        if token is None:
                            too_many()
                            return False
                        try:
                            userpass = base64.b64decode(hdr[6:]).decode("utf-8")
                        except (ValueError, UnicodeDecodeError):
                            userpass = ""
                        role = authlib.check_login(userpass.split(":", 1)[1] if ":" in userpass else "")
                        ok = bool(role)
                        if ok:
                            authlib.release_attempt(ip, token)
                            authlib.remember(key, role)
                        else:
                            time.sleep(1)  # slows down guessing
        if ok:
            self.role = role
        else:
            self.send(401, {"error": "login required"},
                      extra={"WWW-Authenticate": 'Basic realm="Ajar", charset="UTF-8"'})
        return ok

    def send(self, code, body, ctype="application/json", extra=None):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        gz = ctype == "application/json" and len(data) > 1400 and "gzip" in self.headers.get("Accept-Encoding", "")
        if gz:
            data = gzip.compress(data, 5)
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        if gz:
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Vary", "Accept-Encoding")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")  # no clickjacking of the Approve buttons
        # Scripts only from our own app.js: if a device name or SSID ever slipped past escaping,
        # the browser still would not run it. Inline styles stay allowed (the dashboard uses style=).
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                         "img-src 'self' data:; connect-src 'self'; base-uri 'none'; "
                         "form-action 'self'; frame-ancestors 'none'")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if not self.host_ok():
            return self.send(403, {"error": "forbidden"})
        if self.to_https():
            return
        if not self.authed():
            return
        u = urlparse(self.path)
        path, q = u.path, parse_qs(u.query)
        net = q.get("net", [""])[0]
        if self.role == "viewer" and path.startswith("/api/") and path not in VIEWER_API:
            return self.send(403, {"error": "This is a view-only login."})
        if path == "/api/state":
            expand = None
            if q.get("slim", [""])[0] == "1":  # the dashboard's refresh: detail only for open devices
                expand = set(list(filter(None, q.get("expand", [""])[0].split(",")))[:200])
            snap = snapshot(net or None, expand)
            snap["role"] = self.role
            if self.role == "viewer":
                snap.pop("alerts", None)  # alert settings hold passwords, tokens and URLs
            else:
                snap["viewer_enabled"] = bool(auth["viewer"])
            self.send(200, snap)
        elif path == "/api/events":
            net = known_net(net or None)
            before = q.get("before", [""])[0]
            self.send(200, {"events": recent(net, 200, float(before) if before.replace(".", "", 1).isdigit() else None,
                                             presence=q.get("presence", ["1"])[0] == "1") if net else []})
        elif path == "/api/report":
            data = snapshot(net or None)
            name = (data.get("network") or {}).get("name") or (data.get("network") or {}).get("subnet") or "network"
            fname = "ajar-audit-" + re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-") + "-" + time.strftime("%Y%m%d") + ".html"
            self.send(200, report.build_report(data).encode("utf-8"), "text/html; charset=utf-8",
                      extra={"Content-Disposition": f'attachment; filename="{fname}"'})
        elif path == "/api/ping":
            gw = state.get("gateway")
            if not gw:
                # If we haven't run a network scan yet, ask the OS for the default gateway right now
                try:
                    from .netinfo import net_info
                    gw, subnet, own_ip, mac = net_info()
                    state.update(gateway=gw, subnet=subnet, own_ip=own_ip) # Cache it for later
                except Exception:
                    pass
            
            if not gw:
                self.send(200, {"error": "Could not determine your router's IP. Are you connected?"})
            else:
                try:
                    # Cross-platform ping arguments
                    if platform.system() == "Windows":
                        cmd = ["ping", "-n", "20", "-w", "200", gw]
                    else:
                        cmd = ["ping", "-c", "20", "-i", "0.2", "-W", "1", gw]
                    out = subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout
                    times = [float(m) for m in re.findall(r"time[=<]\s*([\d.]+)\s*ms", out)]
                    if not times:
                        self.send(200, {"error": "No replies from router."})
                    else:
                        avg = statistics.mean(times)
                        jitter = statistics.stdev(times) if len(times) > 1 else 0
                        self.send(200, {
                            "avg": round(avg, 1),
                            "jitter": round(jitter, 1),
                            "loss": 20 - len(times),
                            "max": round(max(times), 1)
                        })
                except Exception as e:
                    self.send(200, {"error": str(e)})
        elif path in STATIC:
            name, ctype = STATIC[path]
            with open(os.path.join(config.HERE, "web", name), "rb") as f:
                self.send(200, f.read(), ctype)
        else:
            self.send(404, {"error": "not found"})

    MAX_BODY = 1_000_000

    def do_POST(self):
        # Read the request body first, always. If we answered (403, 401, 429...) with the body still
        # unread and closed the connection, the operating system would reset it and the browser
        # would show "connection lost" instead of the reason.
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = 0
        if n > self.MAX_BODY:
            self.close_connection = True
            return self.send(413, {"error": "request too large"})
        self.body = self.rfile.read(n) if n > 0 else b""
        # A custom header forces browsers to ask permission first, which other
        # websites cannot get. This stops them from clicking Approve for you.
        if not self.host_ok():
            return self.send(403, {"error": "forbidden"})
        if self.to_https():
            return
        if not self.authed():
            return
        if self.headers.get("X-Ajar") != "1":
            return self.send(403, {"error": "forbidden"})
        if self.role == "viewer":
            return self.send(403, {"error": "This is a view-only login. Sign in with the main password to change things."})
        u = urlparse(self.path)
        q = parse_qs(u.query)
        mac = q.get("mac", [""])[0]
        net = known_net(q.get("net", [""])[0] or None)
        if u.path == "/api/stop":
            from . import tools
            state["stop_requested"] = True
            state["scanning"] = False
            state["phase"] = "Stopped by user."
            state["error"] = "Scan was stopped. Click Scan now to try again."
            killed = tools.kill_active_nmap()
            self.send(200, {"ok": True, "killed": killed})
        elif u.path == "/api/scan":
            self.send(200, {"started": start_scan()})
        elif u.path == "/api/audit":
            self.send(200, {"started": start_scan(deep=True, full=q.get("full", ["0"])[0] == "1")})
        elif u.path == "/api/wifi":
            self.send(200, {"started": start_wifi()})
        elif u.path == "/api/settings":
            body = self.read_json()
            if body and net:
                if "allow_default_cred_checks" in body:
                    set_net_setting(net, "allow_default_cred_checks", bool(body["allow_default_cred_checks"]))
                if "cred_toggle" in body:
                    mac = body["cred_toggle"]
                    current = list(net_setting(net, "cred_consent", []))
                    if mac in current:
                        current.remove(mac)
                    else:
                        current.append(mac)
                    set_net_setting(net, "cred_consent", current)
            self.send(200, {"ok": True})
        elif u.path == "/api/mynet":
            ssid = q.get("ssid", [""])[0][:64]
            if ssid and net:
                set_mine(ssid, q.get("mine", ["1"])[0] == "1", net)
            self.send(200, {"ok": bool(ssid and net)})
        elif u.path == "/api/approve":
            if mac and net:
                approve(net, mac)
            self.send(200, {"ok": bool(mac and net)})
        elif u.path == "/api/rename":
            if mac and net:
                rename(net, mac, q.get("name", [""])[0])
            self.send(200, {"ok": bool(mac and net)})
        elif u.path == "/api/rename_net":
            self.send(200, {"ok": bool(net) and rename_network(net, q.get("name", [""])[0])})
        elif u.path == "/api/viewer":
            body = self.read_json()
            if not isinstance(body, dict) or not isinstance(body.get("password", ""), str):
                return self.send(400, {"error": "bad request"})
            if not auth["hash"]:
                return self.send(400, {"error": "There is no main password, so there is nothing to keep view-only access apart from."})
            if body.get("password"):
                err = authlib.set_viewer_password(body["password"])
                if err:
                    return self.send(400, {"error": err})
            else:
                authlib.clear_viewer()
            self.send(200, {"ok": True, "viewer_enabled": bool(auth["viewer"])})
        elif u.path == "/api/alerts":
            body = self.read_json()
            self.send(200, {"ok": True, "alerts": self.save_alerts(body)}) if body is not None \
                else self.send(400, {"error": "bad request"})
        elif u.path == "/api/alert_test":
            ok, msg = alerts.send_test(q.get("channel", ["ntfy"])[0])
            self.send(200, {"ok": ok, "message": msg})
        else:
            self.send(404, {"error": "not found"})

    def read_json(self):
        try:
            return json.loads(self.body.decode("utf-8")) if self.body else {}
        except (ValueError, UnicodeDecodeError):
            return None

    def save_alerts(self, body):
        # Merge the submitted settings over the current ones, keeping a secret the user
        # left blank (the dashboard never sends existing passwords/tokens back).
        cfg = alerts.get_config()
        for ch in ("ntfy", "email", "weekly"):
            if isinstance(body.get(ch), dict):
                for k, v in body[ch].items():
                    if k in cfg[ch] and not (k in ("password", "token") and v == ""):
                        cfg[ch][k] = v
        return alerts.public_config() if alerts.save_config(cfg) else None


def lan_ip():
    """This computer's address on the home network, for the startup message. Connecting a
    UDP socket only picks a route; it sends nothing."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("192.0.2.1", 9))  # a reserved documentation address, never contacted
            return s.getsockname()[0]
        finally:
            s.close()
    except OSError:
        return None


class Server(ThreadingHTTPServer):
    """The dashboard server. Set ssl_ctx to serve HTTPS; plain HTTP on the same port is
    then redirected. Dropped connections and failed handshakes are not errors worth
    printing (browsers do this all the time with self-signed certificates)."""
    ssl_ctx = None
    daemon_threads = True

    def handle_error(self, request, client_address):
        import sys
        if isinstance(sys.exc_info()[1], (OSError, ssl.SSLError)):
            return
        super().handle_error(request, client_address)
