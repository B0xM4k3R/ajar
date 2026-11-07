"""CISA's Known Exploited Vulnerabilities list: CVEs that attackers are using right now. A
vulnerability on this list matters far more than its raw score suggests, so Ajar marks them.

The list is downloaded from CISA (a public file, nothing about your network is sent), kept on this
computer, and refreshed every few days. If it can't be downloaded, the saved copy is used."""
import json
import time
import urllib.request

from .db import get_setting, set_setting

URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEY = "kev"
MAX_AGE = 3 * 86400
MAX_BYTES = 8 * 1024 * 1024


def fetch_json(url=URL, timeout=20):
    req = urllib.request.Request(url, headers={"User-Agent": "ajar-network-audit"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read(MAX_BYTES).decode("utf-8"))


def parse(doc):
    """The set of CVE ids in CISA's JSON."""
    return {v["cveID"].strip().upper() for v in (doc or {}).get("vulnerabilities", [])
            if isinstance(v, dict) and str(v.get("cveID", "")).upper().startswith("CVE-")}


def get_ids(now=None, refresh=True, fetch=None):
    """The known-exploited CVE ids. Downloads a fresh copy if the saved one is old. Never raises."""
    now = now or time.time()
    saved = get_setting(KEY, None)
    saved = saved if isinstance(saved, dict) and isinstance(saved.get("ids"), list) else {"at": 0, "ids": []}
    if refresh and now - saved["at"] > MAX_AGE:
        try:
            ids = parse((fetch or fetch_json)())
            if ids:  # an empty list means something is wrong with the file; keep what we had
                saved = {"at": now, "ids": sorted(ids)}
                set_setting(KEY, saved)
        except Exception:
            pass  # offline or CISA unreachable: use the copy we have
    return set(saved["ids"])
