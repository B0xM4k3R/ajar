"""Telling networks apart, so a portable ajar keeps separate history for each.

A network is recognized by its router's MAC address: every home router is 192.168.1.1,
but no two routers share a MAC. Without admin rights there are no MACs, so the address
range and router address stand in.

If the router's MAC changes but most of the devices are the same, it's the same place
with a different router (or something pretending to be the router). ajar keeps the
history and records it as a high-level change, instead of starting a new network.
"""
import secrets
import time

from .config import state, wifi
from .db import LEGACY, db, get_setting, set_setting
from .events import record

PER_NETWORK_KEYS = ["my_ssids", "not_my_ssids", "score_history", "wifi_last", "wifi_sec_keys"]


def current_net():
    """The network ajar is on now (or was on when it last scanned)."""
    return state.get("net") or get_setting("current_net")


def overlap(c, net, macs):
    """How many of these MACs this network has seen before."""
    if not macs:
        return 0
    have = {r["mac"] for r in c.execute("SELECT mac FROM devices WHERE net=?", (net,))}
    return len(have & macs)


def strong(shared, total):
    """Enough shared devices to call it the same place."""
    return shared >= 3 or (total and shared * 2 >= total and shared >= 2)


def default_name(subnet):
    """The WiFi network this computer is on, if known, otherwise the address range."""
    raw = wifi.get("raw") or {}
    ssid = next((a["ssid"] for a in raw.get("aps", []) if a.get("in_use") and a.get("ssid")), None)
    return ssid or f"Network at {subnet}"


def resolve(found, gw_ip, subnet, own_mac=None, now=None):
    """Works out which network this scan belongs to. Returns (net_id, baseline), where
    baseline means this is a brand-new network: its devices are recorded quietly
    instead of each one being reported as new."""
    now = now or time.time()
    gw_mac = next((mac for mac, ip, *_ in found if ip == gw_ip and not mac.startswith("ip:")), None)
    macs = {mac for mac, *_ in found if not mac.startswith("ip:") and mac != own_mac}
    c = db()
    try:
        net, baseline = None, False
        if gw_mac:
            r = c.execute("SELECT id FROM networks WHERE gateway_mac=?", (gw_mac,)).fetchone()
            net = r["id"] if r else None
        else:
            r = c.execute("SELECT id FROM networks WHERE gateway_mac IS NULL AND subnet=? AND gateway_ip=?",
                          (subnet, gw_ip)).fetchone()
            net = r["id"] if r else None

        if not net and gw_mac:
            # Same devices, different router MAC: a new router, or an impersonator.
            for r in c.execute("SELECT id, gateway_mac FROM networks WHERE subnet=? AND gateway_ip=?",
                               (subnet, gw_ip)).fetchall():
                if strong(overlap(c, r["id"], macs), len(macs)):
                    net = r["id"]
                    if not r["gateway_mac"]:  # first time we can see the router's MAC: nothing changed
                        c.execute("UPDATE networks SET gateway_mac=? WHERE id=?", (gw_mac, net))
                        break
                    record(net, "router_changed", "high",
                           f"The router's address ({gw_ip}) now answers with a different device: MAC {gw_mac} "
                           f"instead of {r['gateway_mac'] or 'unknown'}. If you didn't replace or reset your "
                           "router, something on the network may be impersonating it.", gw_mac, now, c)
                    c.execute("UPDATE networks SET gateway_mac=? WHERE id=?", (gw_mac, net))
                    break

        if not net:
            net = "n" + secrets.token_hex(4)
            legacy = {r["mac"] for r in c.execute("SELECT mac FROM devices WHERE net=?", (LEGACY,))}
            adopt = bool(legacy) and (gw_mac in legacy or strong(len(legacy & macs), len(macs)))
            c.execute("""INSERT INTO networks (id, name, gateway_mac, gateway_ip, subnet, first_seen, last_seen)
                         VALUES (?,?,?,?,?,?,?)""", (net, default_name(subnet), gw_mac, gw_ip, subnet, now, now))
            if adopt:
                # Data from before networks existed belongs here: move it, settings too.
                c.execute("UPDATE devices SET net=? WHERE net=?", (net, LEGACY))
                for key in PER_NETWORK_KEYS:
                    r = c.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
                    if r:
                        c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?,?)", (f"{key}@{net}", r["value"]))
                        c.execute("DELETE FROM settings WHERE key=?", (key,))
                record(net, "adopted", "info", "Your device history from before networks were tracked "
                       "was matched to this network.", None, now, c)
            else:
                baseline = True
                record(net, "first_scan", "info", f"First scan of this network: {len(found)} devices found. "
                       "From now on, ajar reports what changes.", None, now, c)
        c.execute("UPDATE networks SET last_seen=?, gateway_ip=?, subnet=? WHERE id=?", (now, gw_ip, subnet, net))
        c.commit()
    finally:
        c.close()
    if state.get("net") != net:
        state["net"] = net
    set_setting("current_net", net)
    return net, baseline


def all_networks():
    c = db()
    rows = [dict(r) for r in c.execute("""SELECT n.*, (SELECT COUNT(*) FROM devices d WHERE d.net=n.id) AS devices
                                          FROM networks n ORDER BY last_seen DESC""")]
    c.close()
    return rows


def rename_network(net, name):
    name = (name or "").strip()[:60]
    if not name:
        return False
    c = db()
    c.execute("UPDATE networks SET name=? WHERE id=?", (name, net))
    c.commit()
    c.close()
    return True
