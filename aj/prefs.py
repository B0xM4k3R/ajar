"""Settings that apply to the whole of Ajar rather than one network."""
from .db import get_setting, set_setting

KEY = "prefs"
DEFAULTS = {"cve_lookup": True}  # look up known vulnerabilities online (sends software versions to vulners.com)


def get_prefs():
    saved = get_setting(KEY, None)
    out = dict(DEFAULTS)
    if isinstance(saved, dict):
        out.update({k: bool(saved[k]) for k in DEFAULTS if k in saved})
    return out


def save_prefs(body):
    prefs = get_prefs()
    if isinstance(body, dict):
        prefs.update({k: bool(body[k]) for k in DEFAULTS if k in body})
    set_setting(KEY, prefs)
    return prefs
