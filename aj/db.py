"""The local SQLite database.

Tables:
  networks  each network ajar has scanned, recognized by its router's MAC address
  devices   devices per network: the same phone on two networks is two rows
  events    the Changes timeline: what changed on each network, and when
  settings  small values stored as JSON. Per-network values use the key "name@network"
"""
import json
import sqlite3

from . import config

LEGACY = "legacy"  # devices saved before networks existed, until a network claims them

DEVICE_COLS = """mac TEXT, ip TEXT, hostname TEXT, vendor TEXT, kind TEXT,
        first_seen REAL, last_seen REAL, approved INTEGER DEFAULT 0,
        online INTEGER DEFAULT 0, name TEXT, audit TEXT"""


def db():
    c = sqlite3.connect(config.DB)
    c.row_factory = sqlite3.Row
    return c


LEGACY_FILES = [("ajar.db", "wifimap.db"), ("ajar.auth", "wifimap.auth"),
                ("ajar.crt", "wifimap.crt"), ("ajar.key", "wifimap.key")]


def migrate_legacy_files():
    """Ajar was once called wifimap. If a data folder still has the old wifimap.db,
    wifimap.auth or certificate and not the new ajar-named ones, rename them so an
    upgrade keeps every device, name, approval, the password and the HTTPS certificate.
    Runs once; after the rename there is nothing left to do."""
    import os
    for new, old in LEGACY_FILES:
        np, op = os.path.join(config.DATA, new), os.path.join(config.DATA, old)
        if os.path.exists(op) and not os.path.exists(np):
            try:
                os.replace(op, np)
            except OSError:
                pass  # best effort: a fresh run just starts clean


def init_db():
    c = db()
    c.execute(f"""CREATE TABLE IF NOT EXISTS devices (net TEXT NOT NULL, {DEVICE_COLS},
        PRIMARY KEY (net, mac))""")
    have = {r["name"] for r in c.execute("PRAGMA table_info(devices)")}
    if "net" not in have:
        # Before networks existed, devices were keyed by MAC alone. Rebuild the table with
        # a network column, parking the old rows as "legacy" until their network claims them.
        for col in ("name", "audit"):  # columns added by even older versions
            if col not in have:
                c.execute(f"ALTER TABLE devices ADD COLUMN {col} TEXT")
        c.execute(f"CREATE TABLE devices_new (net TEXT NOT NULL, {DEVICE_COLS}, PRIMARY KEY (net, mac))")
        c.execute("""INSERT INTO devices_new SELECT ?, mac, ip, hostname, vendor, kind, first_seen, last_seen,
                     approved, online, name, audit FROM devices""", (LEGACY,))
        c.execute("DROP TABLE devices")
        c.execute("ALTER TABLE devices_new RENAME TO devices")
    c.execute("""CREATE TABLE IF NOT EXISTS networks (
        id TEXT PRIMARY KEY, name TEXT, gateway_mac TEXT, gateway_ip TEXT, subnet TEXT,
        ssid TEXT, first_seen REAL, last_seen REAL)""")
    c.execute("""CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT, net TEXT NOT NULL, at REAL NOT NULL,
        kind TEXT NOT NULL, level TEXT NOT NULL, mac TEXT, text TEXT NOT NULL)""")
    c.execute("CREATE INDEX IF NOT EXISTS events_by_net ON events (net, id)")
    c.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)")
    c.commit()
    c.close()


def get_setting(key, default=None):
    c = db()
    r = c.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    c.close()
    if r is None:
        return default
    try:
        return json.loads(r["value"])
    except ValueError:
        return default


def set_setting(key, value):
    c = db()
    c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, json.dumps(value)))
    c.commit()
    c.close()


def net_setting(net, key, default=None):
    """A setting that belongs to one network, such as which WiFi is yours there."""
    return get_setting(f"{key}@{net}", default)


def set_net_setting(net, key, value):
    set_setting(f"{key}@{net}", value)
