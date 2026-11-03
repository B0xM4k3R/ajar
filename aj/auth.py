"""The dashboard password: setup, hashing and checking."""
import getpass
import hashlib
import hmac
import os
import sys

from . import config


auth = {"hash": None}  # None means no password (only with --no-password)


good_auth = set()      # logins already verified, so the 5 second refresh stays cheap
# Cap the set to prevent memory leaks from bot spamming
def cap_good_auth():
    global good_auth
    if len(good_auth) > 1000:
        good_auth = set(list(good_auth)[-500:])


fails = {}             # ip -> times of recent wrong passwords


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
    if os.environ.get("AJAR_PASSWORD"):
        auth["hash"] = hash_pw(os.environ["AJAR_PASSWORD"])
        return
    if "--set-password" in sys.argv or not os.path.exists(config.AUTH_FILE):
        if not sys.stdin.isatty():
            sys.exit("No password is set. Run it once in a terminal: python3 ajar.py --set-password\n"
                     "(or set AJAR_PASSWORD, or use --no-password).")
        with open(config.AUTH_FILE, "w") as f:
            f.write(hash_pw(prompt_password()))
        try:
            os.chmod(config.AUTH_FILE, 0o600)
        except OSError:
            pass
        print("Password saved.")
        if "--set-password" in sys.argv:
            sys.exit(0)
    with open(config.AUTH_FILE) as f:
        auth["hash"] = f.read().strip()
