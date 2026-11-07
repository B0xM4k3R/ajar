"""Turns WiFi scans into channel picks, security findings and network identification."""
import re
from collections import Counter

from .config import state, wifi
from .db import net_setting, set_net_setting, get_setting
from .networks import current_net
from .wifi_scan import oui_vendor


GRADES = ["bad", "weak", "ok", "good"]  # worst to best


# 5 GHz 20 MHz channels most routers offer (US / FCC defaults). 52-144 are DFS.
CH5 = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128,
       132, 136, 140, 144, 149, 153, 157, 161, 165]


BLOCKS5 = {
    20: [(c, c) for c in CH5],
    40: [(c, c + 4) for c in (36, 44, 52, 60, 100, 108, 116, 124, 132, 140, 149, 157)],
    80: [(c, c + 12) for c in (36, 52, 100, 116, 132, 149)],
    160: [(36, 64), (100, 128)],
}


def signal_word(dbm):
    if dbm >= -55:
        return "excellent"
    if dbm >= -67:
        return "good"
    if dbm >= -75:
        return "fair"
    return "weak"


def weight(dbm):
    """How much a neighbor's signal interferes: doubles every 3 dB, -95 dBm counts as 1."""
    return 10 ** ((max(dbm, -95) + 95) / 10)


def span(ap):
    """The 20 MHz channels a network occupies, as (lowest, highest)."""
    ch, w = ap["ch"], ap["width"] or 20
    if ap["band"] == "2.4":
        if ap.get("sec2"):
            return (min(ch, ap["sec2"]), max(ch, ap["sec2"]))
        return (ch, ch)
    if ap["band"] == "5" and w > 20:
        for lo, hi in BLOCKS5.get(w, []):
            if lo <= ch <= hi:
                return (lo, hi)
    return (ch, ch)


def overlap24(ap, c):
    """Share of a 2.4 GHz network's energy that lands on channel c (channels are 5 MHz
    apart but 20 MHz wide, so neighbors up to 3 channels away overlap)."""
    lo, hi = span(ap)
    d = 0 if lo <= c <= hi else min(abs(c - lo), abs(c - hi))
    return [1.0, 0.7, 0.4, 0.15][d] if d < 4 else 0.0  # 4+ apart (20 MHz) barely touch


def channel_report(aps, band, mine_aps):
    """Rates each channel choice on one band and picks the quietest."""
    others = [a for a in aps if a["band"] == band and a["ch"] and a["dbm"] > -92]
    mine_here = sorted((a for a in mine_aps if a["band"] == band and a["ch"]), key=lambda a: -a["dbm"])
    assumed = False
    if band == "2.4":
        width, cands = 20, [(c, c) for c in (1, 6, 11)]
    else:
        widths = [a["width"] for a in mine_here if a["width"]]
        width = max(widths) if widths else 80  # most routers default to 80 MHz on 5 GHz
        assumed = not widths
        width = width if width in BLOCKS5 else 80
        cands = BLOCKS5[width]

    def rate(lo, hi):
        if band == "2.4":
            hits = [(a, overlap24(a, lo)) for a in others]
            hits = [(a, f) for a, f in hits if f > 0]
        else:
            hits = [(a, 1.0) for a in others if span(a)[0] <= hi and span(a)[1] >= lo]
        return {"lo": lo, "hi": hi, "label": str(lo) if lo == hi else f"{lo}-{hi}",
                "score": round(sum(weight(a["dbm"]) * f for a, f in hits), 1),
                "count": len({a["ssid"] or a["bssid"] for a, _ in hits}),
                "strongest": max([a["dbm"] for a, _ in hits], default=None),
                "dfs": band == "5" and lo <= 144 and hi >= 52}

    rated = [rate(lo, hi) for lo, hi in cands]
    # Prefer normal channels. DFS ones go quiet for a minute at start-up or when radar is
    # detected, and some older devices can't use them, so only pick DFS when the normal
    # choice is clearly busy (a neighbor stronger than about -75 dBm) and DFS is far quieter.
    plain = [r for r in rated if not r["dfs"]]
    dfs = [r for r in rated if r["dfs"]]
    best = min(plain or rated, key=lambda r: (r["score"], r["lo"]))
    if dfs:
        d = min(dfs, key=lambda r: (r["score"], r["lo"]))
        if best["score"] > weight(-75) and d["score"] < best["score"] / 4:
            best = d
    cur = None
    if mine_here:
        m = mine_here[0]
        if band == "2.4":
            cur = rate(m["ch"], m["ch"])
            cur["label"] = str(m["ch"])
        else:
            lo, hi = span(m)
            cur = next((r for r in rated if r["lo"] <= m["ch"] <= r["hi"]), None) or rate(lo, hi)
            cur = dict(cur, primary=m["ch"])
    # Signals below -85 dBm come and go between scans. Treat choices that differ only by
    # those as equally quiet, then keep yours if it's one of them, else take the lowest,
    # so the advice doesn't flip-flop from one scan to the next.
    if not best["dfs"]:
        near = [r for r in (plain or rated) if r["score"] <= best["score"] + weight(-85)]
        keep = next((r for r in near if cur and r["label"] == cur["label"]), None)
        best = keep or min(near, key=lambda r: r["lo"])
    # Only suggest a move that matters: twice as busy, and busier than one neighbor at -85 dBm.
    suggest = bool(cur and best["label"] != cur["label"] and cur["score"] > max(best["score"] * 2, weight(-85)))
    return {"band": band, "width": width, "width_assumed": assumed, "channels": rated,
            "best": best, "current": cur,
            "suggest": suggest, "networks": len({a["ssid"] or a["bssid"] for a in others})}


def wifi_findings(nets, conn):
    out = []

    def add(level, who, text, fid, cat="security"):
        out.append({"level": level, "who": who, "text": text, "id": fid, "cat": cat})

    for n in nets:
        if not n["mine"]:
            continue
        s, aps = n["ssid"], n["aps"]
        # 6 GHz requires WPA3, so it only decides the "usual" security when there's nothing else.
        usual = [a for a in aps if a["band"] != "6"] or aps
        counts = Counter(a["sec"]["label"] for a in usual)
        main_label = max(counts, key=lambda l: (counts[l], GRADES.index(
            next(a["sec"]["grade"] for a in usual if a["sec"]["label"] == l))))
        sec = next(a["sec"] for a in aps if a["sec"]["label"] == main_label)
        if sec["open"]:
            add("high", s, "Your network has no password. Anyone nearby can join it and see unencrypted "
                           "traffic. Turn on WPA2 or WPA3 in the router's WiFi settings.", "wifi_open")
        elif sec["wep"]:
            add("high", s, "Your network uses WEP, which can be cracked in minutes. Switch the router to "
                           "WPA2 (AES) or WPA3.", "wifi_wep")
        elif sec["grade"] == "bad":
            add("high", s, "Your network uses WPA or TKIP, which are retired and weak. Set the router to "
                           "WPA2 (AES/CCMP) or WPA2/WPA3.", "wifi_wpa")
        elif sec["grade"] == "weak":
            add("medium", s, "Your network allows old WPA/TKIP alongside WPA2, so the weakest device sets the "
                             "bar. Set the router to WPA2 (AES) only, or WPA2/WPA3.", "wifi_mixed")
        elif sec["owe"]:
            add("info", s, "Enhanced Open encrypts traffic but anyone can still join. Use WPA2 or WPA3 for a "
                           "private network.", "wifi_owe")
        elif not sec["wpa3"] and not sec["ent"]:
            add("info", s, "WPA2 is fine. WPA2/WPA3 mode is stronger and still lets older devices join, if "
                           "your router offers it.", "wifi_wpa3")
        if any(a["sec"].get("wps") for a in aps):
            add("medium", s, "WPS is switched on. Its PIN method can be cracked, so turn WPS off in the router "
                             "unless you rely on its push button.", "wifi_wps")
        # A copy of your network name with different security can be a fake ("evil twin").
        for a in aps:
            if a["sec"]["label"] == main_label:
                continue
            where = f"{a['band']} GHz channel {a['ch']}" + (f", {a['bssid']}" if a["bssid"] else "")
            if a["sec"]["grade"] == "bad" and sec["grade"] != "bad":
                add("high", s, f"A copy of your network with {a['sec']['label']} security is broadcasting "
                               f"({where}, {a['dbm']} dBm). If it isn't an old extender of yours, someone may "
                               "be imitating your network to catch logins.", "wifi_twin")
            elif a["band"] != "6" and GRADES.index(a["sec"]["grade"]) < GRADES.index(sec["grade"]):
                add("medium", s, f"An access point with your network's name uses {a['sec']['label']} instead of "
                                 f"{main_label} ({where}). Check it's yours: mesh nodes and extenders should "
                                 "match, and a mismatched copy can be a fake.", "wifi_mismatch")
        for a in aps:
            if a["band"] == "2.4" and a["ch"] not in (1, 6, 11):
                add("medium", s, f"Your 2.4 GHz network is on channel {a['ch']}, which overlaps neighbors on "
                                 "two sides. Use 1, 6 or 11.", "wifi_channel24", "performance")
                break
        for a in aps:
            if a["band"] == "2.4" and (a["width"] or 20) >= 40:
                add("medium", s, "Your 2.4 GHz network uses 40 MHz, which covers most of the band and "
                                 "collides with neighbors. Set it to 20 MHz.", "wifi_width24", "performance")
                break
    if conn and conn["mine"]:
        if conn["dbm"] < -75:
            add("medium", conn["ssid"], f"This computer's connection is weak ({conn['dbm']} dBm). Devices "
                                        "here will be slow; move the router or add a mesh node.", "wifi_weak", "performance")
        elif conn["dbm"] < -67:
            add("info", conn["ssid"], f"This computer's connection is fair ({conn['dbm']} dBm).", "wifi_fair", "performance")
        if conn["band"] == "2.4":
            five = [a for n in nets if n["ssid"] == conn["ssid"] for a in n["aps"]
                    if a["band"] in ("5", "6") and a["dbm"] > -70]
            if five:
                add("info", conn["ssid"], "This computer is on 2.4 GHz, but the same network's faster "
                                          "5 GHz signal is strong here.", "wifi_band", "performance")
    order = {"high": 0, "medium": 1, "info": 2}
    return sorted(out, key=lambda f: order[f["level"]])


def wifi_gen(a):
    """WiFi generation from what the system reported: 4, 5, 6, 6E or 7, or ''."""
    g = a["info"].get("gen")
    if not g:
        r = (a["info"].get("radio") or "").lower()
        m = re.search(r"802\.11\s*(be|ax|ac|n|a|g|b)\b", r)
        g = {"be": 7, "ax": 6, "ac": 5, "n": 4}.get(m.group(1), 3) if m else 0
    if not g:
        return ""
    if g == 3:
        return "older (802.11a/b/g)"
    return "WiFi 6E" if g == 6 and a["band"] == "6" else f"WiFi {g}"


PUBLIC_SSIDS = {"xfinitywifi", "xfinity mobile", "cablewifi", "attwifi", "spectrumwifi", "spectrum wifi",
                "spectrumwifi plus", "optimumwifi", "twcwifi", "coxwifi", "boingo hotspot",
                "google starbucks", "starbucks wifi", "mcdonalds free wifi"}


PHONE_RE = re.compile(r"iphone|ipad|galaxy|pixel|androidap|android_|'s phone|\bmoto\b|oneplus|redmi", re.I)


SETUP_RE = re.compile(r"^(hp-setup|esp[_-]|espressif|shelly|tasmota|tuya|smartlife|wyze|ring setup|"
                      r"roku-|chromecast|google-home|nest-|meross|govee|sonos_)|setup|_cfg|-config", re.I)


def similar_bssid(x, y):
    """Routers give each radio and each extra network an address that differs from the
    others only in the first or last byte. Matching the middle four bytes links them."""
    if not x or not y or x == y:
        return False
    p, q = x.split(":"), y.split(":")
    return len(p) == len(q) == 6 and p[1:5] == q[1:5]


def classify(n, named, mine):
    """Explains what kind of network this is, from its name and address."""
    s = n["ssid"]
    low = s.lower()
    kind = label = note = device = None
    m = re.match(r"^DIRECT-(?:[0-9A-Za-z]{2}-)?(.*)$", s)
    if m:
        kind, label = "direct", "Wi-Fi Direct device"
        device = m.group(1).strip(" -_") or None
        note = ("A printer, TV or similar device running its own small network so phones can connect to it "
                "directly, without a router. It is a separate network from any router's.")
    elif low in PUBLIC_SSIDS:
        kind, label = "public", "Public hotspot"
        note = ("Run by an internet provider and open by design: you join, then sign in on a web page. Often "
                "broadcast by a neighbor's provider-supplied router. Anything not using HTTPS can be seen by "
                "others nearby.")
    elif s and PHONE_RE.search(s):
        kind, label = "phone", "Phone or tablet hotspot"
        note = "Someone's phone or tablet sharing its mobile data. These come and go as people move around."
    elif s and SETUP_RE.search(s):
        kind, label = "setup", "Device setup network"
        note = ("A smart device that hasn't been set up yet, or has lost its WiFi settings, broadcasting a "
                "temporary network so its app can configure it. These are often open. If it's yours, finish "
                "setting it up or reset it.")
    elif not s:
        kind, label = "hidden", "Hidden network"
        note = ("This network doesn't broadcast its name. Usually a link between mesh nodes or a network meant "
                "for one device. Hiding a name isn't a security feature.")
        for other in named:
            if any(similar_bssid(a["bssid"], b["bssid"]) for a in n["aps"] for b in other["aps"]):
                n["related"] = other["ssid"]
                if other["ssid"] in mine:
                    kind, label = "backhaul", "Probably yours"
                    note = (f"Its address matches your router's ({other['ssid']}), so it's almost certainly part "
                            "of your own setup: the hidden link between mesh nodes, or a second radio. ajar "
                            "doesn't count it as interference.")
                else:
                    note = (f"Its address matches {other['ssid']}'s router, so it's probably that router's mesh "
                            "link or a second radio.")
                break
    n.update(kind=kind, kind_label=label, kind_note=note, device=device)


def analyze(raw, mine_set, not_mine):
    aps = [dict(a, info=dict(a.get("info") or {})) for a in raw["aps"] if a.get("ch") and a.get("band")]
    for a in aps:
        if a["bssid"]:
            a["vendor"] = oui_vendor(a["bssid"])
        a["gen_label"] = wifi_gen(a)
    connected = next((a for a in aps if a["in_use"]), None)
    mine = (set(mine_set) | ({connected["ssid"]} if connected and connected["ssid"] else set())) - set(not_mine)
    groups = {}
    for a in aps:
        groups.setdefault(a["ssid"] or ("hidden:" + (a["bssid"] or str(id(a)))), []).append(a)
    nets = []
    for key, members in groups.items():
        members.sort(key=lambda a: -a["dbm"])
        ssid = members[0]["ssid"]
        gens = [a["gen_label"] for a in members if a["gen_label"].startswith("WiFi")]
        nets.append({"key": key, "ssid": ssid, "mine": bool(ssid) and ssid in mine, "aps": members,
                     "dbm": members[0]["dbm"], "connected": any(a["in_use"] for a in members),
                     "grade": min((a["sec"]["grade"] for a in members), key=GRADES.index),
                     "labels": sorted({a["sec"]["label"] for a in members}),
                     "gen": max(gens, key=lambda g: g.replace("6E", "6.5")) if gens else "",
                     "related": None})
    named = [n for n in nets if n["ssid"]]
    for n in nets:
        classify(n, named, mine)
    likely = lambda n: n["mine"] or n["kind"] == "backhaul"
    nets.sort(key=lambda n: (not n["mine"], n["kind"] != "backhaul", -n["dbm"]))
    mine_aps = [a for n in nets if n["mine"] for a in n["aps"]]
    other_aps = [a for n in nets if not likely(n) for a in n["aps"]]
    bands = [channel_report(other_aps, b, mine_aps) for b in ("2.4", "5")
             if any(a["band"] == b for a in aps)]
    six = [a for a in aps if a["band"] == "6"]
    conn = None
    if connected:
        conn = {k: connected[k] for k in ("ssid", "bssid", "band", "ch", "width", "dbm")}
        conn.update(mine=connected["ssid"] in mine, quality=signal_word(connected["dbm"]),
                    rate=connected["info"].get("rate"), gen=connected["gen_label"])
    around = Counter(n["kind"] for n in nets if not likely(n) and n["kind"])
    return {"scanned": raw["scanned"], "source": raw["source"], "note": raw.get("note"),
            "nets": nets, "bands": bands, "six": len({a["ssid"] or a["bssid"] for a in six}),
            "conn": conn, "findings": wifi_findings(nets, conn), "mine_known": bool(mine),
            "weak_nearby": sum(1 for n in nets if not likely(n) and n["grade"] == "bad" and n["kind"] != "public"),
            "around": dict(around), "neighbors": sum(1 for n in nets if not likely(n))}


def wifi_snapshot(net=None):
    """The WiFi picture for a network: live for the one you're on, saved for others."""
    here = state.get("net") or get_setting("current_net")
    net = net or here
    # A scan from this session is shown for the network we're on. That includes the case where we
    # don't know yet which network that is (no device scan has run): the scan is real, it just
    # can't be saved under a network until the first device scan says where we are.
    live = wifi["raw"] if net == here else None
    raw = live or (net_setting(net, "wifi_last") if net else None)
    result = None
    if raw:
        try:
            result = analyze(raw, net_setting(net, "my_ssids", []) if net else [], net_setting(net, "not_my_ssids", []) if net else [])
        except Exception as e:  # never let a bad scan break the whole dashboard
            wifi["error"] = "Could not analyze the last WiFi scan: " + str(e)
    return {"scanning": wifi["scanning"] and net == here, "error": wifi["error"] if net == here else None,
            "result": result, "unsaved": bool(live and not here)}


def set_mine(ssid, on, net=None):
    net = net or current_net()
    if not net:
        return
    mine, not_mine = set(net_setting(net, "my_ssids", [])), set(net_setting(net, "not_my_ssids", []))
    (mine.add if on else mine.discard)(ssid)
    (not_mine.discard if on else not_mine.add)(ssid)
    set_net_setting(net, "my_ssids", sorted(mine))
    set_net_setting(net, "not_my_ssids", sorted(not_mine))


BSSID_RE = re.compile(r"\b([0-9a-f]{2}(?::[0-9a-f]{2}){5})\b")


def wifi_changes(net, result):
    """Security changes to your WiFi since the last scan: new or fixed problems, such as
    a look-alike network appearing. The first scan is the baseline and reports nothing."""
    if not result or not result.get("mine_known"):
        return []
    now = {}
    for f in result["findings"]:
        if f.get("cat") == "security" and f["level"] in ("high", "medium"):
            m = BSSID_RE.search(f["text"])  # a look-alike is identified by its address, not its signal
            now[f"{f['id']}|{f['who']}|{m.group(1) if m else ''}"] = f
    before = net_setting(net, "wifi_sec_keys")
    set_net_setting(net, "wifi_sec_keys", sorted(now))
    if before is None:
        return []
    out = [("wifi_problem_new", f["level"], f"WiFi {f['who']}: {f['text']}") for k, f in now.items() if k not in before]
    out += [("wifi_problem_fixed", "info", f"Fixed on WiFi {k.split('|')[1]}: {k.split('|')[0].replace('wifi_', '').replace('_', ' ')} "
             "no longer found.") for k in before if k not in now]
    return out
