"""Pings the router for the dashboard's connection check, on Linux, macOS and Windows.

Why this is its own module: the three systems differ. Windows sends one ping a second whatever
you ask for, and prints its replies in the user's language ("Zeit=" in German). Linux and macOS
can ping fast, but not every account may use a short interval, so there is a slower fallback.
"""
import ipaddress
import platform
import re
import statistics
import subprocess

FAST_COUNT, SLOW_COUNT, WINDOWS_COUNT = 20, 8, 10
# "time=0.5 ms", "time<1ms", "Zeit=3ms", "temps=3 ms": the number before "ms" after "=" or "<".
MS = re.compile(r"[=<]\s*([\d.]+)\s*ms", re.I)
INTERVAL_REFUSED = ("interval", "super-user", "superuser", "only root", "operation not permitted")


def build_cmd(system, gw, fast=True):
    """Returns (argv, number of pings it sends, seconds to allow)."""
    if system == "Windows":
        return ["ping", "-n", str(WINDOWS_COUNT), "-w", "1000", gw], WINDOWS_COUNT, 30
    if system == "Darwin":  # -W is milliseconds here; -t is the whole run's limit in seconds
        if fast:
            return ["ping", "-c", str(FAST_COUNT), "-i", "0.2", "-t", "10", gw], FAST_COUNT, 15
        return ["ping", "-c", str(SLOW_COUNT), "-t", "15", gw], SLOW_COUNT, 20
    if fast:
        return ["ping", "-c", str(FAST_COUNT), "-i", "0.2", "-W", "1", gw], FAST_COUNT, 15
    return ["ping", "-c", str(SLOW_COUNT), "-W", "1", gw], SLOW_COUNT, 20


def parse_times(out):
    """Round-trip times in ms. Only reply lines count (they all contain TTL, in any language);
    the summary lines ("Minimum = 1ms ...") and "unreachable" lines don't."""
    times = []
    for line in (out or "").splitlines():
        if "ttl=" not in line.lower():
            continue
        m = MS.search(line)
        if m:
            try:
                times.append(float(m.group(1)))
            except ValueError:
                pass
    return times


def summarize(times, sent):
    times = times[:sent]  # duplicate replies (DUP!) can't make more than were sent
    return {"avg": round(statistics.mean(times), 1),
            "jitter": round(statistics.stdev(times), 1) if len(times) > 1 else 0,
            "loss": max(0, sent - len(times)), "max": round(max(times), 1), "sent": sent}


def _run(cmd, timeout):
    p = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout)
    return (p.stdout or "") + "\n" + (p.stderr or "")


def ping_gateway(gw, system=None, run=_run):
    """Pings the router and returns {avg, jitter, loss, max, sent} or {error}. `run` is injectable for tests."""
    system = system or platform.system()
    try:
        if ipaddress.ip_address(str(gw)).version != 4:
            return {"error": "Only IPv4 routers can be pinged here."}
    except ValueError:
        return {"error": "That doesn't look like a router address."}
    try:
        cmd, sent, limit = build_cmd(system, gw, fast=True)
        out = run(cmd, limit)
        times = parse_times(out)
        if not times and system != "Windows" and any(w in out.lower() for w in INTERVAL_REFUSED):
            cmd, sent, limit = build_cmd(system, gw, fast=False)  # not allowed to ping this fast
            out = run(cmd, limit)
            times = parse_times(out)
    except FileNotFoundError:
        return {"error": "The ping command isn't available on this computer."}
    except subprocess.TimeoutExpired:
        return {"error": "Ping took too long to finish."}
    except OSError as e:
        return {"error": str(e)}
    if not times:
        return {"error": "No replies from router."}
    return summarize(times, sent)
