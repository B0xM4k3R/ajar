"""Ajar: finds every device on your network, checks what each one shares,
looks at the WiFi networks around you, and serves a map on port 8080.

Linux / Raspberry Pi:  sudo apt install nmap   then   sudo python3 ajar.py
macOS:                 brew install nmap       then   sudo python3 ajar.py
Windows 11:            install nmap from nmap.org (includes Npcap), then run
                       python ajar.py in a PowerShell opened as Administrator.
Admin rights are needed so nmap can read MAC addresses.
The first run asks you to choose a dashboard password. Other options:
  python ajar.py --set-password   change the password
  python ajar.py --no-password    run without a password (not recommended)
  python ajar.py --http           use plain HTTP instead of HTTPS (not recommended)
  python ajar.py --report         audit this network once, save an HTML report, and exit
  AJAR_PASSWORD=...               set the password from the environment
The dashboard uses HTTPS. On first run ajar makes a self-signed certificate
(ajar.crt and ajar.key) with openssl; browsers warn about it once.
Only scan networks you own or administer.
"""
import sys
import threading

if sys.version_info < (3, 8):
    sys.exit("ajar needs Python 3.8 or newer.")

from aj import config
from aj.auth import setup_auth
from aj.certs import ensure_cert, fingerprint, server_context
from aj.db import init_db, migrate_legacy_files
from aj.jobs import auto_scan_loop
from aj.web import Server, Handler, lan_ip


def report_once(out_path=None):
    """Runs every check once on the current network and writes an audit report, then exits.
    For a portable one-shot: python ajar.py --report [--out FILE]."""
    import os
    import time
    from aj.jobs import run_once
    from aj.web import snapshot
    from aj.report import build_report
    migrate_legacy_files()
    init_db()
    if os.geteuid() != 0 and config.SYSTEM != "Windows":
        try:
            from aj.tools import net_caps
            if not net_caps():
                print("Note: not running as root, so MAC addresses and some checks may be limited. "
                      "For a full report, run with sudo.")
        except Exception:
            pass
    print("Auditing this network. This runs every check once and takes a few minutes...")
    run_once(progress=lambda t: print("  " + t))
    data = snapshot()
    name = (data.get("network") or {}).get("name") or (data.get("network") or {}).get("subnet") or "network"
    if not out_path:
        safe = "".join(ch if ch.isalnum() or ch in "._-" else "-" for ch in name).strip("-") or "network"
        out_path = os.path.join(config.DATA, f"ajar-audit-{safe}-{time.strftime('%Y%m%d-%H%M')}.html")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(build_report(data))
    sec = data.get("security") or {}
    print()
    print(f"Done. Audited {name}: {len(data.get('devices', []))} devices, "
          f"grade {sec.get('grade', '?')}" + (f", score {sec['score']}/100" if sec.get("score") is not None else "") + ".")
    print("Report saved to: " + out_path)
    return 0


def main():
    if "--report" in sys.argv:
        out = None
        if "--out" in sys.argv:
            i = sys.argv.index("--out")
            out = sys.argv[i + 1] if i + 1 < len(sys.argv) else None
        sys.exit(report_once(out))
    migrate_legacy_files()  # carry over data from when Ajar was called wifimap
    init_db()
    setup_auth()
    lan = lan_ip()
    server = Server(("0.0.0.0", config.PORT), Handler)
    tls = {"on": False, "fingerprint": None, "why": None}
    if "--http" in sys.argv:
        tls["why"] = "HTTPS was turned off with --http."
    else:
        ok, why = ensure_cert(lan)
        if ok:
            try:
                server.ssl_ctx = server_context()
                tls.update(on=True, fingerprint=fingerprint(), created=why == "created")
            except (OSError, ValueError) as e:
                tls["why"] = f"The certificate files could not be used ({e}). Delete ajar.crt and ajar.key to make new ones."
        else:
            tls["why"] = why
    config.state["tls"] = tls
    # threading.Thread(target=auto_scan_loop, daemon=True).start()  # DISABLED: no auto-scan on startup
    scheme = "https" if tls["on"] else "http"
    print(f"Ajar running. On this computer open {scheme}://localhost:{config.PORT}")
    if lan:
        print(f"From your phone (same WiFi) open {scheme}://{lan}:{config.PORT}")
    if tls["on"]:
        if tls.get("created"):
            print("Made a new HTTPS certificate. Browsers will warn once because it's self-signed.")
        print("Certificate fingerprint (SHA-256), to compare with your browser's warning page:")
        print("  " + tls["fingerprint"])
    else:
        print("WARNING: plain HTTP. Anyone on your WiFi could read the dashboard password. " + (tls["why"] or ""))
    server.serve_forever()


if __name__ == "__main__":
    main()
