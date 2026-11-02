"""Settings and shared state: paths, timings, and what the dashboard shows is running."""
import os
import platform
import threading
import time

SYSTEM = platform.system()  # Linux, Darwin (macOS) or Windows
PORT = 8080
SCAN_EVERY = 600        # seconds between automatic device scans
AUDIT_EVERY = 6 * 3600  # seconds between automatic services and shares checks

# The program lives in HERE. Your data (device history, password, certificate) lives in
# DATA: the project folder by default, or AJAR_DATA when set (the Pi service uses
# /var/lib/ajar, so the program folder can stay read-only).
HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # the project folder
WEB = os.path.join(HERE, "web")
DATA = os.environ.get("AJAR_DATA") or HERE
DB = os.path.join(DATA, "ajar.db")
AUTH_FILE = os.path.join(DATA, "ajar.auth")
CERT_FILE = os.path.join(DATA, "ajar.crt")
KEY_FILE = os.path.join(DATA, "ajar.key")

scan_lock = threading.Lock()

SCAN_STEPS = ["Find devices"]

AUDIT_STEPS = ["Check common ports", "Check file sharing (SMB, FTP, NFS)", "Guess operating systems",
               "Deep-check smart-home and unknown devices", "Check logins and camera streams",
               "Read the names devices announce", "Check what the router opens to the internet",
               "Check DHCP and DNS for tampering"]


def set_step(i, phase=None):
    state.update(step=i, step_started=time.time(), progress=None)
    if phase:
        state["phase"] = phase

state = {"scanning": False, "stop_requested": False, "phase": None, "last_scan": None, "last_audit": None,
         "error": None, "audit_note": None, "subnet": None, "gateway": None, "own_ip": None}

wifi_lock = threading.Lock()

wifi = {"scanning": False, "error": None, "raw": None}
