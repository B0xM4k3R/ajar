"""The Changes timeline: records what changed on each network, and when.

Levels:
  high, medium   security changes worth a look (new device, risky port opened, ...)
  info           other changes (an address changed, something was fixed, the score moved)
  presence       devices coming and going, hidden in the timeline unless asked for
"""
import time

from .db import db

KEEP_DAYS = 180
KEEP_MAX = 5000  # per network


def device_label(d):
    """The friendliest name ajar knows for a device row."""
    inf = (d.get("audit") or {}).get("info") or {} if isinstance(d.get("audit"), dict) else {}
    host = (d.get("hostname") or "").split(".")[0]
    return (d.get("name") or host or inf.get("name") or (inf.get("host") or "").split(".")[0]
            or d.get("vendor") or d.get("ip") or d.get("mac") or "a device")


def record(net, kind, level, text, mac=None, at=None, c=None):
    """Adds one event. Pass an open connection c to batch with other writes."""
    own = c is None
    c = c or db()
    c.execute("INSERT INTO events (net, at, kind, level, mac, text) VALUES (?,?,?,?,?,?)",
              (net, at or time.time(), kind, level, mac, text))
    if own:
        c.commit()
        c.close()


def recent(net, limit=200, before=None, presence=True):
    """Newest first, by when it happened. before= a time, to page further back."""
    c = db()
    q = "SELECT * FROM events WHERE net=?"
    args = [net]
    if before:
        q += " AND at<?"
        args.append(before)
    if not presence:
        q += " AND level!='presence'"
    q += " ORDER BY at DESC, id DESC LIMIT ?"
    args.append(limit)
    rows = [dict(r) for r in c.execute(q, args)]
    c.close()
    return rows


def since(net, after_id, levels=None):
    """Events newer than after_id, oldest first. Optionally only the given levels."""
    c = db()
    rows = [dict(r) for r in c.execute("SELECT * FROM events WHERE net=? AND id>? ORDER BY id ASC", (net, after_id))]
    c.close()
    if levels is not None:
        rows = [r for r in rows if r["level"] in levels]
    return rows


def latest_id(net):
    c = db()
    r = c.execute("SELECT MAX(id) AS m FROM events WHERE net=?", (net,)).fetchone()
    c.close()
    return r["m"] or 0


def prune(net):
    c = db()
    c.execute("DELETE FROM events WHERE net=? AND at<?", (net, time.time() - KEEP_DAYS * 86400))
    c.execute("""DELETE FROM events WHERE net=? AND id NOT IN
                 (SELECT id FROM events WHERE net=? ORDER BY id DESC LIMIT ?)""", (net, net, KEEP_MAX))
    c.commit()
    c.close()
