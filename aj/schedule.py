"""Opt-in scheduled scans. Off by default: Ajar only scans when you press a button until you
turn this on in Settings. When on, a quick device sweep runs every so often (new devices, devices
coming and going) and a full services check runs less often. Alerts, if you set them up, go out
after each scan, and the weekly report goes out at its set time."""
from .db import get_setting, set_setting

KEY = "schedule"
DEFAULTS = {"enabled": False, "scan_min": 15, "audit_hours": 24}
LIMITS = {"scan_min": (5, 1440), "audit_hours": (1, 168)}


def get_schedule():
    cfg = dict(DEFAULTS)
    saved = get_setting(KEY, None)
    if isinstance(saved, dict):
        cfg.update({k: saved[k] for k in DEFAULTS if k in saved})
    return normalize(cfg)


def normalize(cfg):
    """Fills in anything missing and clamps numbers to sensible bounds."""
    out = {"enabled": bool(cfg.get("enabled"))}
    for k, (lo, hi) in LIMITS.items():
        try:
            v = int(cfg.get(k, DEFAULTS[k]))
        except (TypeError, ValueError):
            v = DEFAULTS[k]
        out[k] = max(lo, min(hi, v))
    return out


def save_schedule(body):
    cfg = get_schedule()
    for k in DEFAULTS:
        if isinstance(body, dict) and k in body:
            cfg[k] = body[k]
    cfg = normalize(cfg)
    set_setting(KEY, cfg)
    return cfg


def due(now, last_scan, last_audit, tries, cfg):
    """'audit', 'scan' or None. `tries` holds when each kind was last started, so a scan that
    failed isn't retried every few seconds: it waits a full interval like a successful one."""
    if not cfg.get("enabled"):
        return None
    audit_age = now - max(last_audit or 0, tries.get("audit", 0))
    scan_age = now - max(last_scan or 0, tries.get("scan", 0))
    if audit_age >= cfg["audit_hours"] * 3600:
        return "audit"
    if scan_age >= cfg["scan_min"] * 60:
        return "scan"
    return None
