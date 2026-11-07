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
| **CVE matching:** Cross-references open services with known vulnerabilities via `nmap --script vulners`, per port. Results are reused for a week while a device's open ports are unchanged | Works |
| **Actively exploited flaws:** CVEs on CISA's Known Exploited Vulnerabilities list are flagged as urgent, whatever their score | Works |
| **Distro-patch awareness:** a match on Ubuntu, Debian, Raspberry Pi OS or similar packages is marked "may already be patched" and rated one band lower, since those distributions fix flaws without changing version numbers | Works |
| **Offline mode:** one switch turns off every internet lookup. Results already found are kept, and the score shows the check as "not checked" | Works |
| **End-of-life software:** flags operating systems and software that no longer get security fixes (old Windows, Apache 2.2, PHP 5/7, OpenSSL 1.x, IIS 6/7/8, Python 2), from a short list of well-documented dates. An operating system that only nmap's *guess* says is old is shown as information and never costs points: guesses are unreliable (nmap often reports "Linux 2.6" for much newer kernels). Ajar's own computer reports its real OS | Works |
| **MITM detection:** Watches the ARP table and warns when your router's address starts answering with a different MAC than before (a real impersonation sign). Devices that merely share a MAC, like VMs and Docker hosts, are shown as information, not alarms | Works |
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
| IPv6: scans the local link for neighbors, shows each device's IPv6 addresses, and notes public ones (not hidden behind NAT) | Works |
| **Scheduled scans (opt-in):** a quick sweep every few minutes and a full check daily, so new devices alert you without opening the page. Off by default | Works |
| **Accept a risk:** mark a finding you've decided to live with. It stops costing points, stays listed with your reason, and can be undone | Works |
| **Isolation check:** run Ajar on your guest or smart-home network, list the networks it should not reach, and it tells you if it can reach them | Works |
| **Extra subnets:** also scan other routed private networks (up to 3, `/24` or smaller). Devices there are tracked by IP address | Works |
| **Report tab, export and webhooks:** the audit report, everything as JSON and devices as CSV all in one place; send alerts as signed JSON to Home Assistant, n8n or your own script | Works |
| **View-only login:** a second password that can look at everything except alert settings, and change nothing | Works |
| Docker image, `docker-compose.yml`, and GitHub Actions tests (Linux required to pass; macOS and Windows reported) | Works (Linux) |
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

### Run it in Docker (Linux)

Ajar has to see your real network, so the container uses host networking (this does not work on Docker Desktop for Mac or Windows).

```
docker build -t ajar .
docker run --rm -it --net=host -v ajar-data:/data ajar --set-password   # once
docker run -d --name ajar --restart unless-stopped --net=host --cap-add=NET_RAW --cap-add=NET_ADMIN -v ajar-data:/data ajar
```

Or put `AJAR_PASSWORD=...` in a `.env` file and run `docker compose up -d`.

### First Run
The first time you run Ajar, it will ask you to choose a dashboard password (8 or more characters). Then open `https://localhost:8080`, or the address Ajar prints for your phone, and sign in with any username and that password.

**Ajar does not scan automatically unless you turn it on.** Out of the box you control exactly when it runs (Settings, Scheduled scans, is off). The buttons:
- **Find devices:** A quick sweep to find IPs, MACs, and hostnames.
- **Quick scan:** Checks services, CVEs, and logins. It reuses deep-scan results, and CVE results for devices whose open ports haven't changed, from the last 7 days to finish fast.
- **Deep scan:** Forces a fresh, exhaustive scan of every port on every device, ignoring the cache. Takes a few minutes.

New devices show in amber until you approve them. Devices with problems get a red ring on the map. Tap any device name to expand everything Ajar knows, including "Behind the port" (probes), CVEs, and Credential Test results.

The **Security** tab scores your network out of 100, lists every fix with the points it's worth, and tracks the score over time. 

## Security notes

- **Credential Testing (Tier C):** Ajar can try a curated list of documented factory default passwords (e.g., `admin/password` for Netgear). This is **off by default**. It requires you to turn on the global toggle in Settings and explicitly click "Authorize Test" on a specific device. Every attempt is logged in the `default_cred_audit` database table. **Only use this on devices you own.**
- The dashboard asks for the password you chose on first run. Change it any time with `python3 ajar.py --set-password`. For a view-only login (someone who can look but not touch), use Settings, View-only access, or `python3 ajar.py --set-viewer-password`, or set `AJAR_VIEWER_PASSWORD`.
- The dashboard uses HTTPS by default with a self-signed certificate. Browsers warn once; compare the fingerprint Ajar prints with the browser's.
- Failed logins are slowed down, and five wrong passwords from one device lock it out for five minutes.
- **CVE lookups use the internet.** To match services against known vulnerabilities, nmap's `vulners` script sends the software names and versions it detected (for example, "Apache 2.4.49") to vulners.com. Everything else about your network stays local. Without internet access the lookup finds nothing, and Ajar tries again on the next scan instead of remembering "no CVEs".
- **The view-only login** can read the dashboard, reports and exports (device names, addresses and findings), but not your alert settings (which hold passwords, tokens and webhook URLs), and it cannot start scans or change anything. The server enforces this; hiding the buttons is only cosmetic.
- **The isolation check and extra-subnet scan only probe networks you list yourself**, limited to private ranges of up to 256 addresses each.
- **Webhooks:** if you set a secret, each message carries `X-Ajar-Signature: sha256=<HMAC-SHA256 of the body>`. Check it on the receiving side.
- **Exports** are only served to a logged-in user. CSV cells that begin with `=`, `+`, `-` or `@` are prefixed so a device named like a spreadsheet formula can't run in Excel.
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
Dockerfile, docker-compose.yml   run it in a container (Linux)
.github/workflows/  tests on every push
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
  ipv6.py           IPv6 local-link discovery and neighbor addresses
  alerts.py         selectable alerts (ntfy, email, webhook) and the weekly report
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
  schedule.py       opt-in scheduled scans (settings and timing)
  accept.py         accepted risks
  kev.py            CISA's actively-exploited list
  prefs.py          global preferences (e.g. online CVE lookups)
  eol.py            end-of-life software rules
  segmentation.py   the isolation check
  subnets.py        validating the networks you list
  export.py         JSON and CSV exports
  ping.py           the connection-stability test
  auth.py           the dashboard passwords (main and view-only)
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
- [x] Opt-in scheduled scans with new-device alerts
- [x] Accept-a-risk, and CVE handling (offline switch, actively-exploited list, distro-patch awareness)
- [x] JSON/CSV export and signed webhooks
- [x] Isolation check, end-of-life software, extra subnets, IPv6 addresses
- [x] View-only login, Docker image and CI
- [ ] Proving out macOS and Windows in CI (they run, but aren't required to pass yet)
- [ ] Reading firmware versions to flag end-of-life routers and cameras by model

## License

MIT. See `LICENSE`.
