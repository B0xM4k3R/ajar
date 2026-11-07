"""Runs scans in the background, one at a time, and on a schedule."""
import threading
import time

from .config import set_step, AUDIT_EVERY, AUDIT_STEPS, SCAN_EVERY, SCAN_STEPS, scan_lock, state, wifi, wifi_lock
from .db import set_net_setting
from .events import record
from .wifi_analyze import wifi_changes, wifi_snapshot
from .discovery import scan
from .audit import audit
from . import exposure
from . import alerts
from . import netcheck
from . import schedule
from .wifi_scan import wifi_scan


def net_name(net):
    from .db import db
    c = db()
    r = c.execute("SELECT name, subnet FROM networks WHERE id=?", (net,)).fetchone()
    c.close()
    return (r["name"] or r["subnet"] or net) if r else net


def file_wifi(raw):
    """Saves a WiFi scan under the network it belongs to, and records WiFi changes. Only
    the network identified in this session counts: right after a portable ajar boots
    somewhere new, the remembered network is the old one, so it waits for the first
    device scan to say where it is."""
    net = state.get("net")
    if not net or not raw or raw.get("filed") == net:
        return
    raw["filed"] = net
    set_net_setting(net, "wifi_last", raw)
    for kind, level, text in wifi_changes(net, wifi_snapshot(net)["result"]):
        record(net, kind, level, text)


def wifi_cycle():
    """One WiFi scan, synchronously. Caller holds wifi_lock."""
    try:
        source, aps = wifi_scan()
        raw = {"scanned": time.time(), "source": source, "aps": aps, "note": wifi.get("note")}
        wifi["raw"] = raw
        file_wifi(raw)
    except Exception as e:
        wifi["error"] = str(e)


def start_wifi():
    if not wifi_lock.acquire(blocking=False):
        return False
    wifi.update(scanning=True, error=None)

    def work():
        try:
            wifi_cycle()
        finally:
            wifi["scanning"] = False
            wifi_lock.release()

    threading.Thread(target=work, daemon=True).start()
    return True


def start_scan(deep=False, full=False):
    if not scan_lock.acquire(blocking=False):
        return False
    state["stop_requested"] = False  # Clear any leftover stop flag from a previous run
    now = time.time()
    state.update(scanning=True, error=None, phase="Scanning devices", deep=deep, full=full, started=now,
                 steps=SCAN_STEPS + (AUDIT_STEPS if deep else []), step=0, step_started=now, progress=None)

    def work():
        try:
            scan_cycle(deep=deep, full=full)
        finally:
            state.update(scanning=False, phase=None, progress=None,
                         finished={"at": time.time(), "took": time.time() - state["started"], "deep": deep})
            scan_lock.release()

    threading.Thread(target=work, daemon=True).start()
    return True


def scan_cycle(deep=False, full=False):
    """A full scan (and, when deep, the services/exposure/DHCP-DNS checks), synchronously.
    The caller sets up state and holds scan_lock."""
    try:
        scan()
        state["last_scan"] = time.time()
        file_wifi(wifi.get("raw"))  # a WiFi scan that finished before we knew the network
        if state.get("net"):
            try:
                netcheck.record_health(state["net"], net_name(state["net"]), state.get("gateway"))
            except Exception:
                pass  # health is best-effort
        if deep:
            state["phase"] = "Checking services and shares"
            ssdp = audit(full=full)
            if state.get("net") and ssdp is not None:
                set_step(12, "Check what the router opens to the internet")
                try:
                    exposure.run(state["net"], ssdp, state.get("gateway"))
                except Exception as e:  # never lose the rest of the check over this step
                    state["audit_note"] = "; ".join(filter(None, [state.get("audit_note"),
                                                                   f"Internet exposure check: {e}"]))
            state["last_audit"] = time.time()
        net = state.get("net")
        if net:
            try:
                alerts.dispatch(net, net_name(net))
            except Exception:
                pass  # alerts are best-effort; never let them break a scan
    except Exception as e:  # report the problem in the dashboard
        if state.get("stop_requested"):
            state["error"] = "Scan was stopped. Click Scan now to try again."
        else:
            state["error"] = str(e)


def run_once(progress=None):
    """Runs every check once, synchronously, and returns the network id. For the one-shot
    audit report (python ajar.py --report). progress is an optional callback(text)."""
    def say(t):
        if progress:
            progress(t)
    now = time.time()
    state.update(scanning=True, error=None, deep=True, full=True, started=now,
                 steps=SCAN_STEPS + AUDIT_STEPS, step=0, step_started=now, progress=None)
    try:
        say("Scanning WiFi")
        wifi_cycle()
        say("Scanning for devices and checking services (this takes a few minutes)")
        scan_cycle(deep=True, full=True)
    finally:
        state.update(scanning=False, phase=None, progress=None)
    return state.get("net")


_tries = {}  # when each kind of scheduled scan was last started


def schedule_tick(now=None, start=None):
    """One look at the clock. Sends the weekly report if it's time, and starts a scan if the
    schedule says one is due. Returns what it started ('scan', 'audit') or None."""
    now = now or time.time()
    start = start or start_scan
    net = state.get("net")
    if net:
        try:
            alerts.maybe_send_weekly(net, net_name(net), now)
        except Exception:
            pass  # best-effort, like every alert
    if state.get("scanning"):
        return None
    kind = schedule.due(now, state.get("last_scan"), state.get("last_audit"), _tries, schedule.get_schedule())
    if not kind:
        return None
    _tries["scan"] = now
    if kind == "audit":
        _tries["audit"] = now
    return kind if start(deep=(kind == "audit")) else None


def auto_scan_loop():
    """Runs the schedule. Does nothing unless it's turned on in Settings, so it is always safe
    to start. The first look comes a minute after startup, never during it."""
    time.sleep(60)
    while True:
        try:
            schedule_tick()
        except Exception:
            pass  # a bad tick must never end the schedule
        time.sleep(30)
