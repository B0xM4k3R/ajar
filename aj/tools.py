"""Running commands and nmap, with progress reports passed to the dashboard."""
import os
import re
import subprocess
import threading
import urllib.request
import xml.etree.ElementTree as ET

from .config import SYSTEM, state

ACTIVE_NMAP_PROC = None


NMAP_HINT = {
    "Linux": "Run: sudo apt install nmap",
    "Darwin": "Run: brew install nmap",
    "Windows": "Install it from nmap.org (the installer includes Npcap) and reopen PowerShell.",
}


def sh(cmd, timeout=180):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=timeout).stdout
    except FileNotFoundError:
        raise RuntimeError(f"The {cmd[0]} command isn't available on this computer, and ajar needs it.")


def run_cmd(cmd, timeout=60):
    """Runs a command and returns (exit code, stdout, stderr). A missing program gives 127."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", ""


CAP_NET_ADMIN, CAP_NET_RAW = 12, 13  # Linux capability numbers


def net_caps():
    """On Linux, whether this process holds the two network permissions nmap needs
    (raw sockets and network admin) without being root. The Pi service runs this way."""
    try:
        with open("/proc/self/status") as f:
            eff = next(int(l.split()[1], 16) for l in f if l.startswith("CapEff:"))
    except (OSError, StopIteration, ValueError):
        return False
    return bool(eff & (1 << CAP_NET_RAW)) and bool(eff & (1 << CAP_NET_ADMIN))


def is_admin():
    """True when nmap can do privileged scans (read MAC addresses, guess operating systems)."""
    if SYSTEM == "Windows":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.geteuid() == 0 or (SYSTEM == "Linux" and net_caps())


def nmap_privileged():
    """Not root, but holding the network capabilities: nmap must be told it may use them."""
    return SYSTEM == "Linux" and os.geteuid() != 0 and net_caps()


TASK_NAMES = {"ARP Ping Scan": "finding devices", "Ping Scan": "finding devices",
              "Parallel DNS resolution of": "looking up names", "SYN Stealth Scan": "port scan",
              "Connect Scan": "port scan", "Service scan": "identifying services", "NSE": "running checks",
              "Script Scan": "running checks", "OS detection": "guessing systems"}


def nmap_progress(line):
    """Reads one <taskprogress> line, which nmap writes into its XML output every few
    seconds with --stats-every. Returns {"task", "percent", "remaining"} or None."""
    if "<taskprogress" not in line:
        return None
    task = re.search(r'task="([^"]*)"', line)
    pct = re.search(r'percent="([\d.]+)"', line)
    left = re.search(r'remaining="(\d+)"', line)
    name = (task.group(1) if task else "").strip()
    return {"task": TASK_NAMES.get(name, name.lower() or "working"),
            "percent": float(pct.group(1)) if pct else None,
            "remaining": int(left.group(1)) if left else None}


def run_nmap(args, timeout=180):
    """Runs nmap with XML output, passing its progress reports to the dashboard."""
    if state.get("stop_requested"):
        raise RuntimeError("Scan stopped by user.")
    cmd = ["nmap"] + (["--privileged"] if nmap_privileged() else []) + args + ["--stats-every", "3s", "-oX", "-"]
    global ACTIVE_NMAP_PROC
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                             encoding="utf-8", errors="replace")
        ACTIVE_NMAP_PROC = p
    except FileNotFoundError:
        raise RuntimeError("nmap is not installed. " + NMAP_HINT.get(SYSTEM, "Install nmap from nmap.org."))
    timer = threading.Timer(timeout, p.kill)  # a watchdog, since output arrives line by line
    timer.start()
    lines = []
    try:
        for line in p.stdout:
            prog = nmap_progress(line)
            if prog:
                state["progress"] = prog
            else:
                lines.append(line)
        p.wait()
    finally:
        timer.cancel()
        p.stdout.close()
        ACTIVE_NMAP_PROC = None
    if p.returncode and p.returncode < 0:  # killed by the watchdog
        raise subprocess.TimeoutExpired(cmd, timeout)
    try:
        return ET.fromstring("".join(lines))
    except ET.ParseError:
        raise RuntimeError("nmap gave no usable output. Check that it runs: nmap --version")


def host_ip(h):
    for a in h.findall("address"):
        if a.get("addrtype") == "ipv4":
            return a.get("addr")
    return None


def find_script(h, script_id):
    for s in h.iter("script"):
        if s.get("id") == script_id:
            return s
    return None


def fetch(url, timeout=3, limit=200000):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # never via a proxy
    with opener.open(url, timeout=timeout) as r:
        return r.read(limit).decode("utf-8", "replace")


def kill_active_nmap():
    """Forcefully kill the running nmap process. Returns True if something was killed."""
    global ACTIVE_NMAP_PROC
    if ACTIVE_NMAP_PROC is not None:
        try:
            ACTIVE_NMAP_PROC.kill()
            ACTIVE_NMAP_PROC.wait(timeout=2)
        except Exception:
            pass
        ACTIVE_NMAP_PROC = None
        return True
    return False
