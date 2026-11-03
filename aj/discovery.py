"""Finds devices on the network with nmap and keeps the device list up to date."""
import time

from .config import state
from .db import db
from .tools import run_nmap
from .netinfo import net_info
from .networks import current_net, resolve
from .events import device_label, prune, record


KINDS = [
    ("router", ("netgear", "tp-link", "tp link", "asus", "ubiquiti", "cisco", "arris",
                "technicolor", "d-link", "linksys", "zyxel", "mikrotik", "eero", "sagemcom")),
    ("pi", ("raspberry",)),
    ("printer", ("brother", "canon", "epson", "xerox", "lexmark", "ricoh")),
    ("iot", ("espressif", "tuya", "amazon", "ring", "sonos", "roku", "nest", "philips",
             "shelly", "wyze", "tp-link smart", "ecobee", "chamberlain")),
    ("personal", ("apple", "samsung", "google", "oneplus", "xiaomi", "huawei", "intel",
                  "dell", "hewlett", "lenovo", "microsoft", "liteon", "azurewave", "murata")),
]


def guess_kind(mac, vendor, ip, gw, hostname=""):
    if ip == gw:
        return "router"
    # Check if the hostname gives it away (e.g., "Samsung-TV")
    h = (hostname or "").lower()
    if "tv" in h or "television" in h:
        return "tv"
        
    v = (vendor or "").lower()
    for kind, words in KINDS:
        if any(w in v for w in words):
            return kind
    # phones often use a private (locally administered) MAC with no vendor
    if mac and not vendor and mac[1] in "26ae":
        return "personal"
    return "other"


def parse_hosts(root, own_ip, own_mac):
    found = []
    for h in root.findall("host"):
        if h.find("status").get("state") != "up":
            continue
        ip = mac = vendor = None
        for a in h.findall("address"):
            if a.get("addrtype") == "ipv4":
                ip = a.get("addr")
            elif a.get("addrtype") == "mac":
                mac, vendor = a.get("addr").lower(), a.get("vendor")
        name = h.find("hostnames/hostname")
        host = name.get("name") if name is not None else None
        if mac is None and ip == own_ip and own_mac:  # nmap does not report its own MAC
            mac, vendor = own_mac, vendor or "This device"
        if mac is None:
            mac = "ip:" + ip  # no MAC (not running as admin): track by IP
        found.append((mac, ip, host, vendor, ip == own_ip))
    return found


def second_chance(found, own_ip, own_mac, net=None):
    """Phones doze and can miss the quick sweep. Before calling a known device
    offline, ask for it directly a few more times (ARP, patient)."""
    seen = {f[0] for f in found}
    c = db()
    since = time.time() - 7 * 86400
    missing = [r["ip"] for r in c.execute(
        "SELECT mac, ip FROM devices WHERE last_seen>? AND net=?", (since, net or current_net() or ""))
        if r["mac"] not in seen and r["ip"]]
    c.close()
    if not missing:
        return found
    state["phase"] = "Re-checking %d quiet device(s)" % len(missing)
    for _ in range(2):
        try:
            root = run_nmap(["-sn", "-PR", "-T4", "--max-retries", "5",
                             "--host-timeout", "20s"] + missing, timeout=90)
        except Exception:
            break
        for f in parse_hosts(root, own_ip, own_mac):
            if f[0] not in seen:
                found.append(f)
                seen.add(f[0])
        missing = [ip for ip in missing if ip not in {f[1] for f in found}]
        if not missing:
            break
        time.sleep(3)
    return found


def scan():
    gw, subnet, own_ip, own_mac = net_info()
    state.update(gateway=gw, subnet=subnet, own_ip=own_ip)
    # -PS sends TCP SYN to common ports, -PA sends TCP ACK. 
    # This finds devices (like Windows machines) that block ICMP pings but have open ports.
    root = run_nmap(["-sn", "-T4", "-PS22,80,443,445,3389,8080", "-PA80,443", subnet])
    found = parse_hosts(root, own_ip, own_mac)
    net, baseline = resolve(found, gw, subnet, own_mac)
    found = second_chance(found, own_ip, own_mac, net)
    save(found, gw, net, baseline)
    prune(net)


AWAY_BEFORE_NOTED = 30 * 60  # a device offline for less than this coming back isn't news


def save(found, gw, net, baseline=False, now=None):
    """Updates this network's device list, and records what changed."""
    now = now or time.time()
    c = db()
    prev = {r["mac"]: dict(r) for r in c.execute("SELECT * FROM devices WHERE net=?", (net,))}
    seen = set()
    for mac, ip, host, vendor, is_self in found:
        seen.add(mac)
        kind = "this device" if is_self else guess_kind(mac, vendor, ip, gw)
        p = prev.get(mac)
        if p:
            c.execute("""UPDATE devices SET ip=?, hostname=COALESCE(?, hostname),
                         vendor=COALESCE(?, vendor), kind=CASE WHEN kind='tv' THEN kind ELSE ? END,
                         last_seen=?, online=1 WHERE net=? AND mac=?""",
                      (ip, host, vendor, kind, now, net, mac))
            name = device_label(p)
            if not p["online"] and now - (p["last_seen"] or now) > AWAY_BEFORE_NOTED:
                record(net, "back", "presence", f"{name} is back online ({ip}), after "
                       f"{away(now - p['last_seen'])} away.", mac, now, c)
            if p["ip"] and p["ip"] != ip and not mac.startswith("ip:"):
                record(net, "ip_changed", "info", f"{name} moved from {p['ip']} to {ip}.", mac, now, c)
        else:
            # The router is not auto-approved on purpose: a new device taking the
            # router's address is exactly what you want to be flagged.
            c.execute("""INSERT INTO devices (net, mac, ip, hostname, vendor, kind,
                         first_seen, last_seen, approved, online)
                         VALUES (?,?,?,?,?,?,?,?,?,1)""",
                      (net, mac, ip, host, vendor, kind, now, now, 1 if is_self else 0))
            if not baseline and not is_self:
                label = host or vendor or "an unknown device"
                details = ", ".join(x for x in (vendor if vendor != label else None, ip,
                                                 "private address" if mac[1:2] in ("2", "6", "a", "e") else None) if x)
                record(net, "new_device", "medium", f"New device joined: {label} ({details}). "
                       "Approve it on the Devices tab if you recognize it.", mac, now, c)
    for mac, p in prev.items():
        if p["online"] and mac not in seen:
            record(net, "gone", "presence", f"{device_label(p)} went offline.", mac, now, c)
    c.execute("UPDATE devices SET online=0 WHERE net=? AND mac NOT IN (%s)" % ",".join("?" * len(seen)),
              (net, *seen)) if seen else c.execute("UPDATE devices SET online=0 WHERE net=?", (net,))
    c.commit()
    c.close()


def away(sec):
    if sec < 3600:
        return f"{round(sec / 60)} minutes"
    if sec < 86400:
        return f"{round(sec / 3600)} hours"
    return f"{round(sec / 86400)} days"
