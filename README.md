# Ajar

A cross-platform network mapper and security scanner. It runs natively on **Windows 11, Linux (including Raspberry Pi OS), and macOS**. It finds every device on your network, draws a map, and flags anything you haven't approved. Built with the Python standard library, `nmap`, and a plain HTML/JS dashboard. No frameworks, no build step.

> Only scan networks you own or administer.

## Status

Ajar has evolved from a simple mapper into a comprehensive security auditing tool. It performs deep introspection, CVE matching, and gated credential testing.

| Feature | State |
| --- | --- |
| **Cross-platform:** Runs natively on Windows 11, Linux, and macOS | Works (Tested on Win 11 & Linux) |
| Device discovery (IP, MAC, vendor, hostname, device type) | Works |
| Radial network map, new-device flagging, approve button, device names | Works |
| Self-announced names, models and TV screen sizes (UPnP, Bonjour, Samsung TV API) | Works |
| Open services and shared files (SMB shares, anonymous FTP, NFS exports) | Works |
| **Deep introspection:** Fingerprints services (HTTP titles, TLS certs, SSH banners, SNMP) to identify exactly what is behind an open port | Works |
| **CVE matching:** Cross-references open services with known vulnerabilities via `nmap --script vulners` and flags Critical/High risks | Works |
| **MITM detection:** Monitors the local ARP table to catch ARP spoofing (Man-in-the-Middle) attacks | Works |
| **Factory-default checks (Tier C):** Explicitly opt-in, per-device, logged testing to find devices still using default logins (e.g. `admin/admin`). Off by default. | Works |
| Deep scan (ports 1 to 10,000) for smart-home and router devices: Android debugging, Telnet on 2323, MQTT, TP-Link Kasa, etc. | Works |
| Plain-English flags for Telnet, FTP, Remote Desktop, VNC, plain-HTTP pages | Works |
| WiFi channel analysis, best-channel pick, and security checks (open, WEP, WPA, WPS, look-alikes) | Works |
| Security score out of 100 with a grade, fixes ranked by points, a checks list and history | Works |
| Dashboard password, self-signed HTTPS, protection against DNS rebinding | Works |
| Changes timeline: new devices, ports, CVEs, and score changes, with separate history per network | Works |
| What the router opens to the internet through UPnP (read-only), with risky openings scored | Works |
| Lists what's inside guest-accessible SMB shares and anonymous FTP (read-only), flags sensitive files | Works |
| Selectable alerts (phone push via ntfy, email) with a per-channel trigger level, and a weekly report | Works |
| Catches network tampering: a rogue/second DHCP server, DNS hijacking, and an internet health log | Works |
| One-shot audit: run every check once and get a self-contained HTML report via `python ajar.py --report` | Works |
| IPv6 discovery: scans local link (`ff02::1`) for active neighbors | Works |
| Raspberry Pi and Debian setup script: a locked-down systemd service that starts on boot | Works |

## Requirements

- **OS:** Windows 11, Linux (Debian, Ubuntu, Raspberry Pi OS, etc.), or macOS.
- **Python:** 3.8 or newer.
- **Nmap:** The network scanner (On Windows, the installer includes Npcap, which is required).
- **SNMP Tools:** (e.g., `apt install snmp` on Linux) for SNMP fingerprinting.
- **Admin Rights:** Required so nmap can read MAC addresses and run deep scans (Run as Administrator on Windows, `sudo` on Linux/macOS).

## Run it

**Windows 11:**
1. Install Python and [nmap](https://nmap.org/download.html).
2. Open PowerShell **as Administrator**.
3. Run: 
   ```powershell
   python ajar.py
   ```

**Linux (Debian/Ubuntu/Raspberry Pi):**
```bash
sudo apt install nmap snmp
sudo python3 ajar.py
```

**macOS (install [Homebrew](https://brew.sh) first):**
```bash
brew install nmap
sudo python3 ajar.py
```

### Run it as an always-on service (Linux / Raspberry Pi)
If you want Ajar to start on boot and run continuously in the background:
```bash
sudo ./setup.sh
```
This sets up a locked-down systemd service (it drops root privileges and keeps only the two network capabilities nmap needs). See the build guide, Part 7.

### First Run
The first time you run Ajar, it will ask you to choose a dashboard password (8 or more characters). Then open `https://localhost:8080`, or the address Ajar prints for your phone, and sign in with any username and that password.

**Ajar does not scan automatically.** You control exactly when it runs:
- **Find devices:** A quick sweep to find IPs, MACs, and hostnames.
- **Quick scan:** Checks services, CVEs, and logins. It reuses deep-scan results from the last 7 days to finish fast.
- **Deep scan:** Forces a fresh, exhaustive scan of every port on every device, ignoring the cache. Takes a few minutes.

New devices show in amber until you approve them. Devices with problems get a red ring on the map. Tap any device name to expand everything Ajar knows, including "Behind the port" (probes), CVEs, and Credential Test results.

The **Security** tab scores your network out of 100, lists every fix with the points it's worth, and tracks the score over time. 

## Security notes

- **Credential Testing (Tier C):** Ajar can try a curated list of documented factory default passwords (e.g., `admin/password` for Netgear). This is **off by default**. It requires you to turn on the global toggle in Settings and explicitly click "Authorize Test" on a specific device. Every attempt is logged in the `default_cred_audit` database table. **Only use this on devices you own.**
- The dashboard asks for the password you chose on first run. Change it any time with `python3 ajar.py --set-password`.
- The dashboard uses HTTPS by default with a self-signed certificate. Browsers warn once; compare the fingerprint Ajar prints with the browser's.
- Failed logins are slowed down, and five wrong passwords from one device lock it out for five minutes.
- Do not expose port 8080 to the internet.
- `ajar.db`, `ajar.auth`, and the HTTPS key hold private information. They are in `.gitignore`; keep them out of the repo.

## The best hardware for an always-on box

While Ajar runs perfectly on your laptop (Windows, macOS, or Linux), it's most useful when it runs 24/7 on a dedicated device. 

**1. The Raspberry Pi (Recommended)**
A Raspberry Pi 4 (2 GB+) or Pi 5 is the gold standard. Connect it via Ethernet to leave the WiFi radio free for scanning. A Pi Zero 2 W also works but is slower and 2.4 GHz only.
*   **Storage:** Use a 32 GB High Endurance microSD card (the kind meant for dashcams). A 24/7 Pi writes to the card constantly, and cheap cards will fail. For maximum reliability, boot the Pi from a small USB SSD.

**2. The Mini PC (Best Alternative)**
If Pis are sold out, a cheap Mini PC (like an Intel N100, or a used Lenovo/Dell/HP micro) running Debian is actually the most reliable box. It idles at ~6W, has built-in gigabit ethernet, and you never have to worry about SD card wear. Add a USB WiFi adapter (MediaTek MT7612U) if you want to use the WiFi analyzer.

## Project layout

```
ajar.py             start here: python3 ajar.py
setup.sh            Linux/Pi: install as a systemd service (sudo ./setup.sh)
aj/                 the program, one module per job
  config.py         settings, paths, and what's running right now
  db.py             the local database
  networks.py       telling networks apart, so a portable ajar keeps separate history
  events.py         the Changes timeline
  exposure.py       what the router opens to the internet (UPnP, read-only)
  shares.py         what's inside open shares and anonymous FTP (read-only)
  weakauth.py       exposed/unencrypted logins and default-password reminders (read-only)
  probe.py          deep introspection (TLS, SSH, SNMP, HTTP) for open ports
  defaults.py       factory-default credential checks (opt-in, logged)
  mitm.py           ARP spoofing detection (Man-in-the-Middle)
  cve.py            parses nmap vulners output for CVEs
  ipv6.py           IPv6 local-link discovery
  alerts.py         selectable alerts (ntfy, email) and the weekly report
  netcheck.py       rogue DHCP, DNS sanity, and the internet health log
  report.py         the one-shot audit report (self-contained HTML)
  tools.py          running commands and nmap (with live progress)
  netinfo.py        finding this computer's network on each system
  discovery.py      finding devices
  identify.py       devices' own names and models (UPnP, Bonjour, Samsung TV)
  audit.py          the services check, including the deep check
  wifi_scan.py      WiFi scanning on Linux, Windows and macOS
  wifi_analyze.py   channel picks, WiFi findings, identifying networks
  score.py          the security score
  jobs.py           background and scheduled scans
  auth.py           the dashboard password
  web.py            the web server and API
web/                the dashboard: index.html, app.css, app.js
tests/              tests, one file per area
```

## Roadmap

- [x] Device discovery and map
- [x] Shared-files discovery (guest access)
- [x] WiFi channel analyzer
- [x] Security checks and score
- [x] systemd service and setup script
- [x] Change tracking and timeline, and separate history per network
- [x] What the router exposes to the internet (UPnP port mappings)
- [x] Alerts (dashboard, email or ntfy) and a weekly report
- [x] Internet health log (outages, router vs provider)
- [x] DNS sanity check and rogue-DHCP detection
- [x] Deep introspection and CVEs
- [x] ARP Spoofing / MITM detection
- [x] Gated factory-default credential testing
- [x] Cross-platform testing (Windows 11 & Linux)

## License

MIT. See `LICENSE`.
