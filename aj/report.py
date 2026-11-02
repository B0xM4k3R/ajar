"""The one-shot audit report: a single self-contained HTML document you can save, print
or hand to the network's owner. Built from a dashboard snapshot, so it says exactly what
Ajar found, with the fixes, and nothing it didn't check.

It is a read-only record. Ajar changed nothing on the network and never tried a password.
"""
import html
import time

KIND_NAMES = {"iot": "smart-home", "tv": "smart TV", "personal": "phone or computer",
              "pi": "Raspberry Pi", "router": "router", "printer": "printer",
              "other": "unknown", "this device": "Ajar itself"}
LEVEL_NAMES = {"high": "High", "medium": "Medium", "info": "Info"}


def esc(x):
    return html.escape(str(x if x is not None else ""))


def when(ts):
    # Built without strftime's %-d / %-I (those are a Linux-only extension; on Windows
    # strftime raises ValueError), so the report renders the same on every OS.
    if not ts:
        return ""
    t = time.localtime(ts)
    hour = t.tm_hour % 12 or 12
    return (time.strftime("%A, %B ", t) + str(t.tm_mday) + time.strftime(", %Y at ", t)
            + str(hour) + time.strftime(":%M %p", t))


def device_label(d):
    inf = (d.get("audit") or {}).get("info") or {} if isinstance(d.get("audit"), dict) else {}
    host = (d.get("hostname") or "").split(".")[0]
    return d.get("name") or host or inf.get("name") or d.get("vendor") or d.get("ip") or "a device"


def device_note(d):
    a = d.get("audit")
    if not a:
        return "not checked"
    bits = []
    ports = [p["name"] for p in a.get("ports", [])]
    if ports:
        bits.append("open: " + ", ".join(dict.fromkeys(ports)))
    for s in a.get("shares", []):
        if s.get("access") in ("read", "read/write"):
            bits.append(f"share '{s['name']}' ({s['access']}, no password)")
    web = a.get("web") or {}
    if web.get("auth") == "open":
        bits.append("admin page open with no login")
    if a.get("rtsp", {}).get("open"):
        bits.append("camera stream with no password")
    if a.get("smb1"):
        bits.append("SMBv1 on")
    return "; ".join(bits) or "nothing exposed"


# Colour tokens for light (default), dark (follows the reader's OS) and print (always
# light, so a handed-over or printed copy stays legible no matter the reader's theme).
TOKENS_LIGHT = ("--bg:#fff; --ink:#1a2b30; --soft:#30474c; --muted:#5d7072; --line:#e2e8e5; "
                "--panel:#f7f9f8; --note:#f2f6f4; --accent:#2b7a6b; --brand:#c9741b; --on:#fff; "
                "--high:#b4402b; --med:#8f6b00; --gA:#2b7a6b; --gC:#8f6b00; --gF:#b4402b;")
TOKENS_DARK = ("--bg:#111d1d; --ink:#e4ece8; --soft:#c3d2ce; --muted:#93a8a4; --line:#2f4a47; "
               "--panel:#182827; --note:#152523; --accent:#5bbfa8; --brand:#e8923a; --on:#111d1d; "
               "--high:#f08a73; --med:#e0be4a; --gA:#5bbfa8; --gC:#e0be4a; --gF:#f08a73;")

STYLE = """
:root { %LIGHT% color-scheme: light dark; }
@media (prefers-color-scheme: dark) { :root { %DARK% } }
* { box-sizing: border-box; }
body { font: 15px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; color: var(--ink); background: var(--bg);
  max-width: 820px; margin: 0 auto; padding: 32px 24px 64px; }
.brand { display: flex; align-items: center; gap: 12px; margin: 0 0 2px; }
.brand h1 { margin: 0; }
.logo line { stroke: var(--muted); stroke-width: 2; }
.logo .nd { fill: var(--ink); }
.logo .acc { fill: var(--brand); }
h1 { font-size: 1.6rem; margin: 0 0 2px; }
h2 { font-size: 1.15rem; margin: 30px 0 6px; padding-bottom: 4px; border-bottom: 2px solid var(--line); }
.sub { color: var(--muted); }
.note { background: var(--note); border-left: 4px solid var(--accent); padding: 10px 14px; margin: 16px 0; font-size: 0.9rem; }
.score { display: flex; align-items: center; gap: 18px; margin: 18px 0; padding: 16px; border-radius: 10px;
  background: var(--panel); border-left: 6px solid var(--g); }
.grade { font-size: 2.6rem; font-weight: 800; color: var(--g); line-height: 1; }
.gA, .gB { --g: var(--gA); } .gC { --g: var(--gC); } .gD, .gF { --g: var(--gF); }
table { width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 0.9rem; }
th, td { text-align: left; padding: 7px 8px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { color: var(--muted); font-weight: 600; }
.fix { padding: 12px 0; border-bottom: 1px solid var(--line); }
.fix:last-child { border-bottom: 0; }
.pts { display: inline-block; font-weight: 700; color: var(--high); margin-right: 8px; }
.lvl { font-size: 0.72rem; font-weight: 700; padding: 1px 7px; border-radius: 10px; color: var(--on); }
.lvl.high { background: var(--high); } .lvl.medium { background: var(--med); } .lvl.info { background: var(--muted); }
.how { color: var(--soft); font-size: 0.88rem; margin: 4px 0 0; }
ul.plain { list-style: none; padding: 0; margin: 8px 0 0; }
ul.plain li { padding: 4px 0; }
.ok::before { content: "\\2713 "; color: var(--accent); font-weight: 700; }
footer { margin-top: 40px; padding-top: 14px; border-top: 2px solid var(--line); color: var(--muted); font-size: 0.82rem; }
@media print { :root { %LIGHT% } body { padding: 0; } h2 { break-after: avoid; } .fix, tr { break-inside: avoid; } }
""".replace("%LIGHT%", TOKENS_LIGHT).replace("%DARK%", TOKENS_DARK)

# The Ajar mark (network of nodes, one amber) for the report header. Themed via the vars above.
LOGO = ('<svg class="logo" viewBox="0 0 48 48" width="34" height="34" aria-hidden="true">'
        '<line x1="24" y1="24" x2="13" y2="13"/><line x1="24" y1="24" x2="35" y2="14"/>'
        '<line x1="24" y1="24" x2="13" y2="35"/><line x1="24" y1="24" x2="35" y2="35"/>'
        '<circle cx="13" cy="13" r="3.4" class="nd"/><circle cx="35" cy="14" r="3.4" class="nd"/>'
        '<circle cx="13" cy="35" r="3.4" class="nd"/><circle cx="35" cy="35" r="4" class="acc"/>'
        '<circle cx="24" cy="24" r="5.4" class="nd"/></svg>')


def build_report(data, now=None):
    """Returns the audit report as one self-contained HTML string."""
    now = now or time.time()
    net = data.get("network") or {}
    sec = data.get("security") or {}
    devices = data.get("devices") or []
    wifi = (data.get("wifi") or {}).get("result")
    health = data.get("health") or {}
    name = net.get("name") or net.get("subnet") or "this network"
    grade = sec.get("grade", "?")
    out = []

    favicon = ("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 48 48'%3E"
               "%3Crect width='48' height='48' rx='11' fill='%2314201f'/%3E%3Cg stroke='%2345605c' "
               "stroke-width='2.6'%3E%3Cline x1='24' y1='24' x2='13' y2='13'/%3E%3Cline x1='24' y1='24' "
               "x2='35' y2='14'/%3E%3Cline x1='24' y1='24' x2='13' y2='35'/%3E%3Cline x1='24' y1='24' "
               "x2='35' y2='35'/%3E%3C/g%3E%3Ccircle cx='13' cy='13' r='4' fill='%23e4ece8'/%3E%3Ccircle "
               "cx='35' cy='14' r='4' fill='%23e4ece8'/%3E%3Ccircle cx='13' cy='35' r='4' fill='%23e4ece8'/%3E"
               "%3Ccircle cx='35' cy='35' r='4.6' fill='%23e8923a'/%3E%3Ccircle cx='24' cy='24' r='6' "
               "fill='%23e4ece8'/%3E%3C/svg%3E")
    out.append(f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="icon" href="{favicon}">
<title>Ajar audit — {esc(name)}</title><style>{STYLE}</style></head><body>""")
    out.append(f'<div class="brand">{LOGO}<h1>Network audit: {esc(name)}</h1></div>')
    out.append(f'<p class="sub">{esc(net.get("subnet",""))} &middot; {esc(when(now))}</p>')
    out.append('<div class="note">This audit only observed the network. Ajar changed nothing and never tried a '
               'password. Run it only on a network you own or have the owner\'s permission to check.</div>')

    # score
    if sec.get("unscored"):
        out.append('<div class="score gF"><div class="grade">&ndash;</div><div><b>Not fully checked.</b><br>'
                   f'<span class="sub">{esc("; ".join(sec.get("missing", [])))}</span></div></div>')
    else:
        total = sum(i["points"] for i in sec.get("issues", []))
        summary = (f"{len(sec['issues'])} fix{'es' if len(sec['issues']) != 1 else ''} worth {total} points"
                   if sec.get("issues") else "Nothing to fix in what was checked")
        partial = (". Partial: " + "; ".join(sec.get("missing", []))) if sec.get("partial") else ""
        out.append(f'<div class="score g{grade}"><div class="grade">{esc(grade)}</div>'
                   f'<div><b>Security score: {sec.get("score")}/100.</b><br>'
                   f'<span class="sub">{esc(summary)}{esc(partial)}</span></div></div>')

    # fixes
    issues = sec.get("issues", [])
    if issues:
        out.append("<h2>What to fix</h2>")
        for i in issues:
            where = f' <span class="sub">({esc(i["where"])})</span>' if i.get("where") else ""
            out.append(f'<div class="fix"><span class="pts">+{i["points"]}</span>'
                       f'<span class="lvl {i["level"]}">{LEVEL_NAMES.get(i["level"], i["level"])}</span> '
                       f'<b>{esc(i["title"])}</b>{where}'
                       f'<div class="how">{esc(i["problem"])}</div>'
                       f'<div class="how"><i>How:</i> {esc(i["fix"])}</div></div>')

    if sec.get("optional"):
        out.append("<h2>Worth checking</h2><ul class='plain'>")
        out += [f"<li>{esc(t)}</li>" for t in sec["optional"]]
        out.append("</ul>")

    # checks
    checks = sec.get("checks", [])
    if checks:
        out.append("<h2>Checks</h2><ul class='plain'>")
        mark = {"pass": "ok", "fail": "", "unknown": ""}
        for c in checks:
            pre = "✓ " if c["status"] == "pass" else "✗ " if c["status"] == "fail" else "? "
            cls = {"pass": "", "fail": "", "unknown": "sub"}[c["status"]]
            tail = " (not checked)" if c["status"] == "unknown" else ""
            out.append(f'<li class="{cls}">{pre}{esc(c["label"])}{tail}</li>')
        out.append("</ul>")

    # internet exposure
    ex = sec.get("exposure")
    if ex and ex.get("mappings"):
        out.append("<h2>Open to the internet</h2><table><tr><th>Port</th><th>Device</th><th>Service</th><th>Risk</th></tr>")
        for m in ex["mappings"]:
            if not m.get("enabled"):
                continue
            risk = "High" if (m.get("risky") and ex.get("reachable")) else "—"
            out.append(f'<tr><td>{esc(m["proto"])} {m["ext"]}</td><td>{esc(m["device"])}</td>'
                       f'<td>{esc(m.get("service") or "")}</td><td>{risk}</td></tr>')
        out.append("</table>")

    # WiFi
    if wifi and wifi.get("conn"):
        c = wifi["conn"]
        out.append("<h2>WiFi</h2>")
        out.append(f'<p>Connected to <b>{esc(c.get("ssid") or "a network")}</b> on {esc(c.get("band"))} GHz '
                   f'channel {esc(c.get("ch"))}, signal {esc(c.get("dbm"))} dBm ({esc(c.get("quality"))}).</p>')
        if wifi.get("weak_nearby"):
            out.append(f'<p class="sub">{wifi["weak_nearby"]} nearby network(s) have weak or no security.</p>')

    # internet health
    if health and health.get("status") != "unknown":
        out.append("<h2>Internet</h2>")
        if health["status"] == "down":
            out.append(f'<p>Down at the time of the audit. Looks like {esc(health.get("cause",""))}.</p>')
        else:
            up = health.get("uptime_7d")
            out.append(f'<p>Up. {("%s%% uptime over the last 7 days. " % up) if up is not None else ""}'
                       f'{("Latency %s ms." % health["latency"]) if health.get("latency") else ""}</p>')

    # devices
    out.append(f"<h2>Devices ({len(devices)})</h2>")
    out.append("<table><tr><th>Name</th><th>Address</th><th>Type</th><th>What's exposed</th></tr>")
    for d in devices:
        out.append(f"<tr><td>{esc(device_label(d))}</td><td>{esc(d.get('ip',''))}</td>"
                   f"<td>{esc(KIND_NAMES.get(d.get('kind'), d.get('kind') or ''))}</td>"
                   f"<td>{esc(device_note(d))}</td></tr>")
    out.append("</table>")

    out.append(f"""<footer>Generated by Ajar, a private, local network auditor. This report reflects only what
could be observed from inside the network at the time above; a clean result means nothing was found, not that a
device is guaranteed safe. Ajar made no changes and tried no passwords.<br>{esc(when(now))}</footer></body></html>""")
    return "".join(out)
