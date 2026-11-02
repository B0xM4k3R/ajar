"""HTTPS for the dashboard: a self-signed certificate made with openssl on first run.

Python's standard library can use certificates but can't create them, so ajar asks
openssl, which comes with Linux, Raspberry Pi OS and macOS, and with Git for Windows.
If none is found, the dashboard falls back to plain HTTP and says so."""
import hashlib
import os
import shutil
import socket
import ssl

from . import config
from .config import SYSTEM
from .tools import run_cmd

WINDOWS_OPENSSL = [  # native builds first: Git's usr/bin one is an MSYS build
    r"C:\Program Files\Git\mingw64\bin\openssl.exe",
    r"C:\Program Files\OpenSSL-Win64\bin\openssl.exe",
    r"C:\Program Files\Git\usr\bin\openssl.exe",
    r"C:\Program Files (x86)\Git\mingw32\bin\openssl.exe",
]
NO_OPENSSL = {
    "Windows": "Install Git for Windows (winget install --id Git.Git -e), which includes openssl, then restart ajar.",
    "Darwin": "macOS normally includes openssl. Check that the openssl command works in Terminal.",
    "Linux": "Install it with: sudo apt install openssl",
}


def find_openssl():
    exe = shutil.which("openssl")
    if exe:
        return exe
    if SYSTEM == "Windows":
        return next((p for p in WINDOWS_OPENSSL if os.path.exists(p)), None)
    return None


def cert_names(lan=None):
    """The names and addresses the certificate should cover."""
    host = socket.gethostname().split(".")[0]
    names = ["localhost"] + ([host, host + ".local"] if host and host != "localhost" else [])
    ips = ["127.0.0.1"] + ([lan] if lan else [])
    return names, ips


def ensure_cert(lan=None):
    """Makes sure ajar.crt and ajar.key exist. Returns (True, "existing" or
    "created") when HTTPS can be used, or (False, reason) when it can't."""
    if os.path.exists(config.CERT_FILE) and os.path.exists(config.KEY_FILE):
        return True, "existing"
    exe = find_openssl()
    if not exe:
        return False, "openssl was not found. " + NO_OPENSSL.get(SYSTEM, "Install openssl.")
    names, ips = cert_names(lan)
    san = ",".join([f"DNS:{n}" for n in names] + [f"IP:{i}" for i in ips])
    base = [exe, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "825",
            "-keyout", config.KEY_FILE, "-out", config.CERT_FILE, "-subj", "/CN=ajar"]
    code, _, err = run_cmd(base + ["-addext", "subjectAltName=" + san], 60)
    if code != 0:  # older openssl and some LibreSSL builds don't know -addext
        code, _, err = run_cmd(base, 60)
    if code != 0 or not os.path.exists(config.CERT_FILE):
        for f in (config.CERT_FILE, config.KEY_FILE):
            if os.path.exists(f):
                os.remove(f)
        return False, "openssl could not make a certificate: " + (err.strip()[:200] or "unknown error")
    try:
        os.chmod(config.KEY_FILE, 0o600)
    except OSError:
        pass
    return True, "created"


def fingerprint(path=None):
    """The certificate's SHA-256 fingerprint, as browsers show it (AB:CD:...)."""
    with open(path or config.CERT_FILE) as f:
        der = ssl.PEM_cert_to_DER_cert(f.read())
    h = hashlib.sha256(der).hexdigest().upper()
    return ":".join(h[i:i + 2] for i in range(0, len(h), 2))


def server_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(config.CERT_FILE, config.KEY_FILE)
    return ctx
