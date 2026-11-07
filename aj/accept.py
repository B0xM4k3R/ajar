"""'Accept this risk': a finding you've looked at and decided to live with (a camera you can't
update, a share that's meant to be open). Accepted findings stop counting against the score and
stop showing as problems, but stay listed so they can be undone and are never forgotten.

Each is remembered per network as (device MAC or "net", finding id) with an optional reason."""
import time

from .db import net_setting, set_net_setting
from .events import record

KEY = "accepted"
MAX_ITEMS = 500


def get(net):
    items = net_setting(net, KEY, []) if net else []
    return [i for i in items if isinstance(i, dict) and i.get("mac") and i.get("id")]


def as_map(items):
    return {(i["mac"], i["id"]): i for i in items}


def accept(net, mac, fid, reason="", now=None, known_ids=None):
    """Returns True if saved. Refuses ids ajar doesn't produce, so junk can't pile up."""
    mac, fid = str(mac or "")[:64], str(fid or "")[:64]
    if not net or not mac or not fid or (known_ids is not None and fid not in known_ids):
        return False
    items = [i for i in get(net) if (i["mac"], i["id"]) != (mac, fid)]
    now = now or time.time()
    items.append({"mac": mac, "id": fid, "reason": str(reason or "").strip()[:200], "at": now})
    set_net_setting(net, KEY, items[-MAX_ITEMS:])
    record(net, "risk_accepted", "info", f"You accepted a risk ({fid.replace('_', ' ')})."
           + (f" Reason: {str(reason).strip()[:200]}" if str(reason or "").strip() else ""), None if mac == "net" else mac, now)
    return True


def unaccept(net, mac, fid):
    items = get(net)
    keep = [i for i in items if (i["mac"], i["id"]) != (str(mac), str(fid))]
    if len(keep) == len(items):
        return False
    set_net_setting(net, KEY, keep)
    return True
