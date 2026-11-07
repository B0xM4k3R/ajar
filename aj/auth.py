"""The dashboard password(s): setup, hashing and checking.

There are two logins. The main password can do everything. An optional view-only password lets
someone look at the dashboard and reports (a family member, a friend helping you) without being
able to start scans, change settings, or see the alert settings (which hold passwords and URLs)."""
import getpass
import hashlib
import hmac
import os
import sys
import threading
import time

from . import config


auth = {"hash": None, "viewer": None}  # hash None means no password (only with --no-password)


LOCK_AFTER = 5         # wrong passwords from one address before it is locked out...
LOCK_WINDOW = 300      # ...within this many seconds (and for as long as they stay in the window)
GOOD_TTL = 12 * 3600   # a verified login is trusted this long before the password is checked again
GOOD_MAX = 500         # most verified logins remembered at once

_lock = threading.Lock()
_stripes = [threading.Lock() for _ in range(64)]   # see verify_lock()
good_auth = {}         # sha256 of the Authorization header -> (expiry time, role), so the 5 second refresh stays cheap
fails = {}             # ip -> times of recent password attempts (wrong, or still being checked)


def verify_lock(ip):
    """A lock to hold while checking a password for this address. A page load sends several
    requests at once with the same new login; with the lock the first one does the check and the
    rest find it remembered, instead of all of them counting as separate attempts. It also means
    a flood of parallel guesses is checked one at a time, so the limit really is the limit.
    (A fixed set of locks, so the memory used never grows with the number of addresses.)"""
    return _stripes[hash(ip) % len(_stripes)]


def is_good(key, now=None):
    """The role ("admin" or "viewer") this Authorization header was verified for recently, or None."""
    now = now or time.time()
    with _lock:
        hit = good_auth.get(key)
        if hit is None:
            return None
        if hit[0] < now:
            del good_auth[key]
            return None
        return hit[1]


def remember(key, role="admin", now=None):
    now = now or time.time()
    with _lock:
        if len(good_auth) >= GOOD_MAX:
            for k in [k for k, (e, _) in good_auth.items() if e < now]:
                del good_auth[k]
            while len(good_auth) >= GOOD_MAX:  # still full: drop the oldest
                del good_auth[min(good_auth, key=lambda k: good_auth[k][0])]
        good_auth[key] = (now + GOOD_TTL, role)


def forget_all():
    """Drops every remembered login, e.g. after the password changes."""
    with _lock:
        good_auth.clear()


def _recent(ip, now):
    """The attempts still inside the lockout window. Caller holds _lock."""
    recent = [t for t in fails.get(ip, []) if now - t < LOCK_WINDOW]
    if recent:
        fails[ip] = recent
    else:
        fails.pop(ip, None)  # no entry left behind for addresses that behaved
    return recent


def is_locked(ip, now=None):
    now = now or time.time()
    with _lock:
        return len(_recent(ip, now)) >= LOCK_AFTER


def reserve_attempt(ip, now=None):
    """Counts a password check BEFORE it runs, so a burst of parallel guesses can't all slip
    past the limit before the first failure is recorded. Returns a token, or None if locked."""
    now = now or time.time()
    with _lock:
        recent = _recent(ip, now)
        if len(recent) >= LOCK_AFTER:
            return None
        recent.append(now)
        fails[ip] = recent
        return now


def release_attempt(ip, token):
    """The password was right: this attempt doesn't count against the address."""
    with _lock:
        recent = fails.get(ip, [])
        if token in recent:
            recent.remove(token)
        if not recent:
            fails.pop(ip, None)


def hash_pw(pw, salt=None):
    salt = salt or os.urandom(16)
    dk = hashlib.scrypt(pw.encode("utf-8"), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)
    return salt.hex() + "$" + dk.hex()


def check_pw(pw, stored):
    try:
        salt_hex, dk_hex = stored.split("$")
        dk = hashlib.scrypt(pw.encode("utf-8"), salt=bytes.fromhex(salt_hex), n=2 ** 14, r=8, p=1, dklen=32)
    except ValueError:
        return False
    return hmac.compare_digest(dk.hex(), dk_hex)


def check_login(pw):
    """Which login this password is: "admin", "viewer", or None."""
    if auth["hash"] and check_pw(pw, auth["hash"]):
        return "admin"
    if auth["viewer"] and check_pw(pw, auth["viewer"]):
        return "viewer"
    return None


def _write_private(path, text):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def set_viewer_password(pw):
    """Turns on (or changes) the view-only login. Returns None, or a message saying why not."""
    if len(pw or "") < 8:
        return "The view-only password needs 8 or more characters."
    if auth["hash"] and check_pw(pw, auth["hash"]):
        return "That is the main password. Choose a different one for view-only access."
    auth["viewer"] = hash_pw(pw)
    _write_private(config.VIEWER_FILE, auth["viewer"])
    forget_all()  # anyone already signed in as a viewer must sign in again with the new password
    return None


def clear_viewer():
    auth["viewer"] = None
    try:
        os.remove(config.VIEWER_FILE)
    except OSError:
        pass
    forget_all()


def load_viewer():
    """Reads the view-only password (from AJAR_VIEWER_PASSWORD or the saved file), if there is one."""
    if os.environ.get("AJAR_VIEWER_PASSWORD"):
        auth["viewer"] = hash_pw(os.environ["AJAR_VIEWER_PASSWORD"])
    elif os.path.exists(config.VIEWER_FILE):
        with open(config.VIEWER_FILE) as f:
            auth["viewer"] = f.read().strip() or None


def prompt_password():
    while True:
        a = getpass.getpass("Choose a dashboard password (8 or more characters): ")
        if len(a) < 8:
            print("Too short. Try again.")
            continue
        if a != getpass.getpass("Type it again: "):
            print("They did not match. Try again.")
            continue
        return a


def setup_auth():
    """Decides how the dashboard is protected before the server starts."""
    if "--no-password" in sys.argv:
        print("WARNING: running with no password. Anyone on your network can open the dashboard.")
        return
    if "--set-viewer-password" in sys.argv:
        if not sys.stdin.isatty():
            sys.exit("Run this in a terminal: python3 ajar.py --set-viewer-password")
        if os.path.exists(config.AUTH_FILE):
            with open(config.AUTH_FILE) as f:
                auth["hash"] = f.read().strip()
        err = set_viewer_password(prompt_password())
        sys.exit(err or "View-only password saved. Restart Ajar if it is running.")
    if os.environ.get("AJAR_PASSWORD"):
        auth["hash"] = hash_pw(os.environ["AJAR_PASSWORD"])
        load_viewer()
        return
    if "--set-password" in sys.argv or not os.path.exists(config.AUTH_FILE):
        if not sys.stdin.isatty():
            sys.exit("No password is set. Run it once in a terminal: python3 ajar.py --set-password\n"
                     "(or set AJAR_PASSWORD, or use --no-password).")
        digest = hash_pw(prompt_password())
        # Create the file private from the start, instead of chmod-ing it after the hash is written.
        fd = os.open(config.AUTH_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(digest)
        try:
            os.chmod(config.AUTH_FILE, 0o600)  # also tightens a file left over from an older version
        except OSError:
            pass
        print("Password saved.")
        if "--set-password" in sys.argv:
            sys.exit(0)
    with open(config.AUTH_FILE) as f:
        auth["hash"] = f.read().strip()
    load_viewer()
