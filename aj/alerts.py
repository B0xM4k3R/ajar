"""Alerts and the weekly report, through channels you turn on one at a time.

The dashboard is always the baseline (the Changes badge and banner). On top of that you
can enable any of these, independently, each with its own trigger level:
  - ntfy: a free phone push. Point it at ntfy.sh or your own server; no account needed.
  - email: through your own mail account (SMTP).

Nothing leaves the Pi unless you switch a channel on and say where to send it. Levels:
"high" sends only High changes (a camera left open, a risky port opened to the internet,
the router replaced); "medium" sends High and Medium; presence (devices coming and going)
never alerts.
"""
import smtplib
import ssl
import urllib.error
import urllib.request
from email.message import EmailMessage

from .db import get_setting, net_setting, set_net_setting, set_setting
from .events import recent, since

LEVELS = {"high": {"high"}, "medium": {"high", "medium"}}
PRIORITY = {"high": "high", "medium": "default"}


def default_config():
    return {
        "ntfy": {"enabled": False, "server": "https://ntfy.sh", "topic": "", "token": "", "min_level": "high"},
        "email": {"enabled": False, "host": "", "port": 587, "security": "starttls",
                  "user": "", "password": "", "to": "", "min_level": "high"},
        "weekly": {"enabled": False, "day": 6, "hour": 8, "ntfy": False, "email": True},
    }


def get_config():
    cfg = default_config()
    saved = get_setting("alerts") or {}
    for k, v in saved.items():
        if k in cfg and isinstance(v, dict):
            cfg[k].update(v)
    return cfg


def save_config(cfg):
    clean = default_config()
    for k in clean:
        if isinstance(cfg.get(k), dict):
            clean[k].update({kk: vv for kk, vv in cfg[k].items() if kk in clean[k]})
    clean["email"]["port"] = int(clean["email"]["port"] or 587)
    set_setting("alerts", clean)
    return clean


def public_config():
    """The config for the dashboard, with the secrets blanked (but a flag that they're set)."""
    cfg = get_config()
    cfg["email"]["password"] = ""
    cfg["email"]["has_password"] = bool(get_config()["email"]["password"])
    cfg["ntfy"]["token"] = ""
    cfg["ntfy"]["has_token"] = bool(get_config()["ntfy"]["token"])
    return cfg


# ---------------------------------------------------------------- composing messages

def summarize(events):
    """A short title and body for a batch of change events."""
    highs = [e for e in events if e["level"] == "high"]
    n = len(events)
    title = (f"{len(highs)} urgent change" + ("s" if len(highs) != 1 else "")) if highs \
        else (f"{n} change" + ("s" if n != 1 else ""))
    lines = []
    for e in events[:12]:
        mark = "[!] " if e["level"] == "high" else ""
        lines.append(mark + e["text"])
    if n > 12:
        lines.append(f"...and {n - 12} more. Open Ajar to see them all.")
    return title, "\n".join(lines), "high" if highs else "default"


# ---------------------------------------------------------------- channels

def send_ntfy(cfg, title, body, priority="default", tags=None):
    """Posts a notification to an ntfy server. Raises on failure."""
    server = (cfg.get("server") or "https://ntfy.sh").rstrip("/")
    topic = (cfg.get("topic") or "").strip()
    if not topic:
        raise ValueError("No ntfy topic set.")
    headers = {"Title": title, "Priority": priority}
    if tags:
        headers["Tags"] = tags
    if cfg.get("token"):
        headers["Authorization"] = "Bearer " + cfg["token"]
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    req = urllib.request.Request(f"{server}/{topic}", data=body.encode("utf-8"), headers=headers, method="POST")
    with opener.open(req, timeout=10) as r:
        return 200 <= r.status < 300


def send_email(cfg, subject, body):
    """Sends an email through the configured SMTP server. Raises on failure."""
    for field in ("host", "user", "to"):
        if not (cfg.get(field) or "").strip():
            raise ValueError(f"Email is missing its {field}.")
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = cfg["user"]
    msg["To"] = cfg["to"]
    msg.set_content(body)
    host, port, sec = cfg["host"], int(cfg.get("port") or 587), cfg.get("security", "starttls")
    if sec == "ssl":
        with smtplib.SMTP_SSL(host, port, context=ssl.create_default_context(), timeout=20) as s:
            s.login(cfg["user"], cfg.get("password") or "")
            s.send_message(msg)
    else:
        with smtplib.SMTP(host, port, timeout=20) as s:
            if sec == "starttls":
                s.starttls(context=ssl.create_default_context())
            if cfg.get("password"):
                s.login(cfg["user"], cfg["password"])
            s.send_message(msg)
    return True


def deliver(cfg, channel, title, body, priority="default"):
    if channel == "ntfy":
        return send_ntfy(cfg["ntfy"], title, body, priority, tags="warning" if priority == "high" else "bell")
    if channel == "email":
        return send_email(cfg["email"], "Ajar: " + title, body)
    raise ValueError("unknown channel " + channel)


# ---------------------------------------------------------------- dispatch after a scan

def dispatch(net, net_name=None, cfg=None):
    """Sends any new changes on this network through each enabled channel, respecting its
    level. Each channel remembers the last event it sent, so nothing is sent twice.
    Returns {channel: sent_count}. Never raises: a channel that fails is left for next time."""
    cfg = cfg or get_config()
    name = net_name or net
    out = {}
    for channel in ("ntfy", "email"):
        c = cfg[channel]
        if not c.get("enabled"):
            continue
        mark = net_setting(net, f"alert_seen_{channel}", 0)
        fresh = since(net, mark)
        if not fresh:
            continue
        wanted = [e for e in fresh if e["level"] in LEVELS.get(c.get("min_level", "high"), {"high"})]
        newest = max(e["id"] for e in fresh)
        if wanted:
            title, body, priority = summarize(wanted)
            body += f"\n\nNetwork: {name}"
            try:
                deliver(cfg, channel, f"{name}: {title}", body, priority)
                out[channel] = len(wanted)
                set_net_setting(net, f"alert_seen_{channel}", newest)
            except Exception:
                pass  # leave the watermark; try again after the next scan
        else:
            set_net_setting(net, f"alert_seen_{channel}", newest)  # nothing worth sending, but don't recheck these
    return out


def send_test(channel, cfg=None):
    """Sends a test notification. Returns (ok, message)."""
    cfg = cfg or get_config()
    try:
        deliver(cfg, channel, "Test alert", "This is a test from Ajar. If you got this, alerts are working.", "default")
        return True, "Sent. Check your " + ("phone" if channel == "ntfy" else "inbox") + "."
    except Exception as e:
        return False, str(e)


# ---------------------------------------------------------------- weekly report

def weekly_report(net, net_name, now):
    """A plain-English summary of the last 7 days on one network: score, new devices,
    what changed, and the top fixes still open."""
    week = [e for e in recent(net, 500, presence=False) if e["at"] > now - 7 * 86400]
    hist = net_setting(net, "score_history", [])
    score = hist[-1][1] if hist else None
    grade = _grade(score) if score is not None else "?"
    new_devices = [e for e in week if e["kind"] == "new_device"]
    highs = [e for e in week if e["level"] == "high"]
    fixed = [e for e in week if e["kind"] in ("problem_fixed", "internet_closed")]
    lines = [f"Your network \"{net_name}\" this week.", ""]
    lines.append(f"Security score: {score if score is not None else 'not scored yet'} ({grade})."
                 if score is not None else "Security score: not scored yet. Open Ajar and run Check services.")
    if len(hist) >= 2 and hist[-1][1] != hist[0][1]:
        lines.append(f"  (was {hist[0][1]} at the start of the records)")
    lines.append("")
    lines.append(f"New devices: {len(new_devices)}." + (" " + "; ".join(e["text"].split(".")[0] for e in new_devices[:5]) if new_devices else ""))
    lines.append(f"Urgent items this week: {len(highs)}." )
    for e in highs[:6]:
        lines.append("  [!] " + e["text"])
    lines.append(f"Fixed this week: {len(fixed)}.")
    if not highs and not new_devices:
        lines.append("")
        lines.append("Nothing urgent, and no new devices. A quiet week.")
    lines.append("")
    lines.append("Open Ajar for the full picture.")
    title = f"Weekly report: {net_name} ({grade})"
    return title, "\n".join(lines)


def _grade(score):
    return "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 60 else "F"


def maybe_send_weekly(net, net_name, now):
    """Sends the weekly report if it's due (the configured day and hour) and this week's
    hasn't gone out yet. Returns the channels it sent to."""
    cfg = get_config()
    w = cfg["weekly"]
    if not w.get("enabled"):
        return []
    import time
    lt = time.localtime(now)
    if lt.tm_wday != int(w.get("day", 6)) or lt.tm_hour != int(w.get("hour", 8)):
        return []
    week_key = time.strftime("%Y-%W", lt)
    if net_setting(net, "weekly_sent", "") == week_key:
        return []
    title, body = weekly_report(net, net_name, now)
    sent = []
    for channel in ("ntfy", "email"):
        if w.get(channel) and cfg[channel].get("enabled"):
            try:
                deliver(cfg, channel, title, body, "default")
                sent.append(channel)
            except Exception:
                pass
    set_net_setting(net, "weekly_sent", week_key)
    return sent
