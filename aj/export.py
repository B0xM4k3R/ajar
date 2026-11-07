"""Machine-readable exports of what Ajar knows: JSON for scripts and dashboards (Home Assistant,
Grafana, your own tooling), CSV for spreadsheets."""
import csv
import io
import json
import re
import time

SCHEMA = "ajar-export/1"
CSV_COLUMNS = ["name", "ip", "mac", "vendor", "type", "online", "approved", "first_seen", "last_seen",
               "open_ports", "problems", "worst_problem", "cves", "accepted_risks"]


def iso(t):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t)) if t else ""


def csv_safe(value):
    """Spreadsheets run text that starts with = + - @ as a formula, and device names come from
    the network, so anyone on it could plant one. A leading apostrophe makes it plain text."""
    s = "" if value is None else str(value)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def device_name(d):
    inf = ((d.get("audit") or {}).get("info") or {}) if isinstance(d.get("audit"), dict) else {}
    return d.get("name") or d.get("hostname") or inf.get("name") or inf.get("host") or d.get("vendor") or d.get("ip") or ""


def device_row(d):
    a = d.get("audit") if isinstance(d.get("audit"), dict) else {}
    problems = [f for f in a.get("findings", []) if f.get("level") != "info" and f.get("id") not in (d.get("accepted") or [])]
    worst = "high" if any(f["level"] == "high" for f in problems) else ("medium" if problems else "")
    return [device_name(d), d.get("ip"), d.get("mac") if not str(d.get("mac", "")).startswith("ip:") else "", d.get("vendor"),
            d.get("kind"), "yes" if d.get("online") else "no", "yes" if d.get("approved") else "no",
            iso(d.get("first_seen")), iso(d.get("last_seen")),
            ";".join(str(p["port"]) for p in a.get("ports", [])), len(problems), worst,
            ";".join(c["id"] for c in a.get("cves", [])), ";".join(d.get("accepted") or [])]


def build_csv(snap):
    out = io.StringIO()
    w = csv.writer(out, lineterminator="\r\n")
    w.writerow(CSV_COLUMNS)
    for d in snap["devices"]:
        w.writerow([csv_safe(c) for c in device_row(d)])
    return out.getvalue().encode("utf-8-sig")  # the BOM makes Excel read accents correctly


def build_json(snap, events=(), now=None):
    sec = snap.get("security") or {}
    net = snap.get("network") or {}
    doc = {"schema": SCHEMA, "exported_at": iso(now or time.time()),
           "network": {k: net.get(k) for k in ("id", "name", "subnet", "last_seen")},
           "security": {k: sec.get(k) for k in ("score", "grade", "issues", "accepted", "checks", "missing", "partial")},
           "devices": snap["devices"],
           "events": [{k: e.get(k) for k in ("at", "kind", "level", "mac", "text")} for e in events]}
    return json.dumps(doc, indent=2, default=str).encode("utf-8")


def filename(snap, ext, now=None):
    name = ((snap.get("network") or {}).get("name") or "network")
    slug = re.sub(r"[^A-Za-z0-9]+", "-", name).strip("-")[:40] or "network"
    return f"ajar-{slug}-{time.strftime('%Y-%m-%d', time.localtime(now or time.time()))}.{ext}"
