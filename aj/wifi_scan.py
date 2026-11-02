"""Scans nearby WiFi with each system's own tool (nmcli, iw, netsh, system_profiler).

Every scanner returns access points in the same shape, so the analysis never
needs to know which operating system the data came from."""
import json
import os
import re
import shutil
import time

from .config import SYSTEM, wifi
from .tools import run_cmd


def chan_from_freq(f):
    if not f:
        return None
    if 2412 <= f <= 2472:
        return (f - 2407) // 5
    if f == 2484:
        return 14
    if 5150 <= f <= 5895:
        return (f - 5000) // 5
    if 5955 <= f <= 7115:
        return (f - 5950) // 5
    return None


def band_of(freq=None, ch=None):
    if freq:
        return "2.4" if freq < 3000 else "6" if freq >= 5925 else "5"
    if ch:
        return "2.4" if ch <= 14 else "5"
    return None


def pct_to_dbm(pct):
    """NetworkManager and Windows report signal as 0-100 %. Both map it roughly
    linearly from -100 dBm (0 %) to -50 dBm (100 %)."""
    return round(int(pct) / 2 - 100)


def first_int(text):
    m = re.search(r"\d+", text or "")
    return int(m.group()) if m else None


def make_sec(open_=False, wep=False, wpa=False, wpa2=False, wpa3=False, ent=False,
             owe=False, tkip=False, ccmp=False, wps=None):
    """Builds a plain label and a grade (bad, weak, ok, good) for a network's security."""
    s = {"open": open_ and not owe, "wep": wep, "wpa": wpa, "wpa2": wpa2, "wpa3": wpa3,
         "ent": ent, "owe": owe, "tkip": tkip, "ccmp": ccmp, "wps": wps}
    if owe:
        label, grade = "Enhanced Open (OWE)", "ok"
    elif open_:
        label, grade = "Open, no password", "bad"
    elif wep:
        label, grade = "WEP", "bad"
    else:
        label = "/".join(n for n, on in (("WPA", wpa), ("WPA2", wpa2), ("WPA3", wpa3)) if on) or "WPA2"
        if ent:
            label += " Enterprise"
        if tkip and not ccmp:
            grade = "bad"
        elif wpa and not (wpa2 or wpa3):
            grade = "bad"
        elif wpa or tkip:
            grade = "weak"
        elif wpa3 or ent:
            grade = "good"
        else:
            grade = "ok"
        if tkip:
            label += " (TKIP)"
    s["label"], s["grade"] = label, grade
    return s


def new_ap(bssid, ssid, band, ch, width, dbm, sec, in_use=False, sec2=None, info=None):
    return {"bssid": bssid, "ssid": ssid or "", "band": band, "ch": ch, "width": width,
            "sec2": sec2, "dbm": dbm, "sec": sec, "in_use": bool(in_use), "info": info or {}}


NMCLI_FIELDS = ["IN-USE", "BSSID", "SSID", "CHAN", "FREQ", "SIGNAL", "SECURITY",
                "WPA-FLAGS", "RSN-FLAGS", "BANDWIDTH"]


def split_terse(line):
    """Splits one line of `nmcli -t` output. Colons inside values arrive as \\: ."""
    out, cur, i = [], "", 0
    while i < len(line):
        ch = line[i]
        if ch == "\\" and i + 1 < len(line):
            cur += line[i + 1]
            i += 2
            continue
        if ch == ":":
            out.append(cur)
            cur = ""
        else:
            cur += ch
        i += 1
    out.append(cur)
    return out


def parse_nmcli(text, fields):
    aps = []
    for line in text.splitlines():
        vals = split_terse(line)
        if len(vals) != len(fields):
            continue
        r = dict(zip(fields, vals))
        sec_t = r["SECURITY"].upper().split()
        flags = (r["WPA-FLAGS"] + " " + r["RSN-FLAGS"]).lower().split()
        wpa2 = "WPA2" in sec_t
        sec = make_sec(
            open_=not sec_t or sec_t == ["--"], wep="WEP" in sec_t, wpa="WPA1" in sec_t,
            wpa2=wpa2, wpa3="WPA3" in sec_t, ent="802.1X" in sec_t, owe="OWE" in sec_t,
            tkip="pair_tkip" in flags, ccmp=any(f.startswith(("pair_ccmp", "pair_gcmp")) for f in flags))
        freq = first_int(r["FREQ"])
        ch = first_int(r["CHAN"]) or chan_from_freq(freq)
        ssid = r["SSID"] if r["SSID"] != "--" else ""
        aps.append(new_ap(r["BSSID"].lower(), ssid, band_of(freq, ch), ch,
                          first_int(r.get("BANDWIDTH", "")), pct_to_dbm(first_int(r["SIGNAL"]) or 0),
                          sec, r["IN-USE"].strip() == "*"))
    return aps


def wifi_scan_nmcli():
    """Returns access points, or None when NetworkManager is not available."""
    err = ""
    for fields in (NMCLI_FIELDS, NMCLI_FIELDS[:-1]):  # BANDWIDTH needs NetworkManager 1.44+
        for rescan in ("yes", "no"):  # "yes" is refused right after another scan
            code, out, err = run_cmd(["nmcli", "-t", "-e", "yes", "-f", ",".join(fields),
                                      "dev", "wifi", "list", "--rescan", rescan], 60)
            if code == 127 or "not running" in err.lower():
                return None
            if code == 0:
                aps = parse_nmcli(out, fields)
                if not aps:
                    _, radio, _ = run_cmd(["nmcli", "radio", "wifi"], 10)
                    if "disabled" in radio:
                        raise RuntimeError("The WiFi radio is off. Turn it on with: sudo nmcli radio wifi on")
                    _, devs, _ = run_cmd(["nmcli", "-t", "-f", "TYPE,STATE", "dev"], 10)
                    if "wifi:" not in devs:
                        raise RuntimeError("No WiFi adapter found.")
                    if "wifi:unavailable" in devs:
                        raise RuntimeError(WIFI_BLOCKED_HINT)
                return aps
            if "field" in err.lower():
                break
    raise RuntimeError("nmcli could not scan: " + (err.strip()[:200] or "unknown error"))


WIFI_BLOCKED_HINT = ("The WiFi adapter is unavailable, often because it is blocked. On a Raspberry Pi, "
                     "set the WiFi country with sudo raspi-config (Localisation Options, WLAN Country), "
                     "then run: sudo rfkill unblock wifi")


def iw_sec(ap):
    rsn, wpa = ap.pop("_rsn"), ap.pop("_wpa")
    privacy, wps = ap.pop("_privacy"), ap.pop("_wps")
    auth = set(" ".join(rsn["auth"]).replace("/", " ").split()) if rsn else set()
    wpa_auth = " ".join(wpa["auth"]) if wpa else ""
    ciphers = " ".join((rsn["pair"] if rsn else []) + (wpa["pair"] if wpa else []))
    owe_only = auth == {"OWE"}
    return make_sec(
        open_=not privacy and not rsn and not wpa,
        wep=privacy and not rsn and not wpa,
        wpa=bool(wpa),
        wpa2=bool(rsn) and not owe_only and ("PSK" in auth or "802.1X" in auth or not auth & {"SAE", "SAE-EXT-KEY"}),
        wpa3=bool(auth & {"SAE", "SAE-EXT-KEY"}),
        ent="802.1X" in auth or "802.1X" in wpa_auth,
        owe=owe_only,
        tkip="TKIP" in ciphers, ccmp="CCMP" in ciphers or "GCMP" in ciphers, wps=wps)


def parse_iw(text):
    aps, cur, block = [], None, None
    for raw in text.splitlines():
        m = re.match(r"^BSS ([0-9a-fA-F:]{17})", raw)
        if m:
            cur = {"bssid": m.group(1).lower(), "ssid": "", "freq": None, "ch": None, "dbm": None,
                   "width": 20, "sec2": None, "in_use": "associated" in raw, "info": {},
                   "_privacy": False, "_rsn": None, "_wpa": None, "_wps": False}
            aps.append(cur)
            block = None
            continue
        if cur is None:
            continue
        top = raw.startswith("\t") and not raw.startswith("\t\t")
        line = raw.strip()
        item = re.sub(r"^\*\s*", "", line.split("\t*", 1)[-1].strip()) if line.startswith(("RSN:", "WPA:", "WPS:")) \
            else re.sub(r"^\*\s*", "", line)
        if top:
            block = None
            if line.startswith("freq:"):
                cur["freq"] = int(float(line.split(":", 1)[1]))
            elif line.startswith("signal:"):
                cur["dbm"] = round(float(line.split(":", 1)[1].split()[0]))
            elif line.startswith("SSID:"):
                v = raw.split("SSID:", 1)[1].strip()
                cur["ssid"] = "" if not v or set(v.replace("\\x00", "")) <= {""} else v
            elif line.startswith("capability:"):
                cur["_privacy"] = "Privacy" in line
            elif line.startswith("DS Parameter set:"):
                cur["ch"] = first_int(line.split(":", 1)[1])
            elif line.startswith("RSN:"):
                block, cur["_rsn"] = "rsn", {"auth": [], "pair": []}
            elif line.startswith("WPA:"):
                block, cur["_wpa"] = "wpa", {"auth": [], "pair": []}
            elif line.startswith("WPS:"):
                block, cur["_wps"] = "wps", True
            elif line.startswith("HT operation:"):
                block = "ht"
            elif line.startswith("VHT operation:"):
                block = "vht"
            for level, tag in ((4, "HT capabilities"), (5, "VHT capabilities"), (6, "HE capabilities"),
                               (7, "EHT capabilities")):
                if line.startswith(tag):
                    cur["_gen"] = max(cur.get("_gen", 0), level)
            if block not in ("rsn", "wpa", "wps"):
                continue
        key, _, val = item.partition(":")
        key, val = key.strip(), val.strip()
        if block in ("rsn", "wpa"):
            b = cur["_" + block]
            if key == "Authentication suites":
                b["auth"].append(val)
            elif key == "Pairwise ciphers":
                b["pair"].append(val)
        elif block == "wps" and key in ("Manufacturer", "Model", "Model Number", "Device name"):
            if val and val not in ("0", " "):
                cur["info"][{"Manufacturer": "maker", "Model": "model", "Model Number": "model_no",
                             "Device name": "name"}[key]] = val
        elif block == "ht":
            if key == "primary channel":
                cur["ch"] = first_int(val)
            elif key == "secondary channel offset":
                if val == "above":
                    cur["width"], cur["sec2"] = 40, 1
                elif val == "below":
                    cur["width"], cur["sec2"] = 40, -1
        elif block == "vht" and key == "channel width":
            w = {"1": 80, "2": 160, "3": 160}.get(val.split()[0] if val else "")
            if w:
                cur["width"] = w
    out = []
    for a in aps:
        ch = a["ch"] or chan_from_freq(a["freq"])
        if a["freq"] and a["freq"] >= 5925:
            ch = chan_from_freq(a["freq"])  # 6 GHz numbering differs from DS Parameter set
        sec = iw_sec(a)
        if a.get("_gen"):
            a["info"]["gen"] = a["_gen"]
        sec2 = a["ch"] + 4 * a["sec2"] if a["sec2"] and a["ch"] else None
        out.append(new_ap(a["bssid"], a["ssid"], band_of(a["freq"], ch), ch, a["width"],
                          a["dbm"] if a["dbm"] is not None else -100, sec, a["in_use"], sec2, a["info"]))
    return out


def wifi_scan_iw():
    code, out, _ = run_cmd(["iw", "dev"], 10)
    if code == 127:
        return None
    ifaces = re.findall(r"Interface\s+(\S+)", out)
    if not ifaces:
        raise RuntimeError("No WiFi adapter found.")
    dev = ifaces[0]
    for attempt in range(3):
        code, out, err = run_cmd(["iw", "dev", dev, "scan"], 60)
        if code == 0:
            return parse_iw(out)
        if "busy" in err.lower() and attempt < 2:
            time.sleep(3)
            continue
        break
    if "Network is down" in err:
        raise RuntimeError(f"The WiFi adapter {dev} is switched off. Turn it on with: sudo ip link set {dev} up")
    if "not permitted" in err.lower():
        raise RuntimeError("Scanning WiFi needs admin rights. Start ajar with sudo.")
    if "rfkill" in err.lower() or "blocked" in err.lower():
        raise RuntimeError(WIFI_BLOCKED_HINT)
    raise RuntimeError("iw could not scan: " + (err.strip()[:200] or "unknown error"))


WINDOWS_LOCATION_HINT = ("Windows hides nearby WiFi networks until Location is on. Open Settings, then Privacy "
                         "and security, then Location. Turn on Location services and \"Let desktop apps "
                         "access your location\", then press Scan WiFi.")


def netsh_sec(auth, enc):
    a, e = auth.lower(), enc.lower()
    return make_sec(
        open_=a == "open" and e in ("none", ""), wep=e == "wep" or a == "shared",
        wpa=a.startswith("wpa-"), wpa2=a.startswith("wpa2"), wpa3=a.startswith("wpa3"),
        ent="enterprise" in a, owe="owe" in a, tkip="tkip" in e, ccmp="ccmp" in e or "gcmp" in e)


def parse_netsh(text):
    aps, ssid, auth, enc, cur = [], "", "", "", None
    for raw in text.splitlines():
        if ":" not in raw:
            continue
        k, v = raw.split(":", 1)
        k, v = k.strip(), v.strip()
        if re.match(r"^SSID \d+$", k):
            ssid, auth, enc, cur = v, "", "", None
        elif k == "Authentication":
            auth = v
        elif k == "Encryption":
            enc = v
        elif re.match(r"^BSSID \d+$", k):
            cur = new_ap(v.lower(), ssid, None, None, None, -100, netsh_sec(auth, enc))
            aps.append(cur)
        elif cur is None:
            continue
        elif k == "Signal":
            cur["dbm"] = pct_to_dbm(first_int(v) or 0)
        elif k == "Channel":
            cur["ch"] = first_int(v)
        elif k == "Band":
            cur["band"] = "2.4" if v.startswith("2.4") else v.split()[0]
        elif k == "Radio type":
            cur["info"]["radio"] = v
    for a in aps:
        a["band"] = a["band"] or band_of(None, a["ch"])
    return aps


def parse_netsh_iface(text):
    d = {}
    for raw in text.splitlines():
        if ":" in raw:
            k, v = raw.split(":", 1)
            d.setdefault(k.strip(), v.strip())
    return d


def windows_trigger_scan(wait=4.0):
    """Asks Windows to scan now. netsh only reports Windows' last cached scan, which while
    connected can hold little more than the current network. Microsoft gives drivers
    4 seconds to finish a scan. Returns True if a scan was started."""
    try:
        import ctypes
        from ctypes import wintypes
        wlan = ctypes.windll.wlanapi
    except (ImportError, AttributeError, OSError):
        return False

    class GUID(ctypes.Structure):
        _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
                    ("Data3", wintypes.WORD), ("Data4", ctypes.c_ubyte * 8)]

    class IfaceInfo(ctypes.Structure):
        _fields_ = [("guid", GUID), ("desc", ctypes.c_wchar * 256), ("state", ctypes.c_uint)]

    class IfaceList(ctypes.Structure):
        _fields_ = [("count", wintypes.DWORD), ("index", wintypes.DWORD), ("first", IfaceInfo * 1)]

    handle, version, started = wintypes.HANDLE(), wintypes.DWORD(), 0
    if wlan.WlanOpenHandle(2, None, ctypes.byref(version), ctypes.byref(handle)) != 0:
        return False
    try:
        plist = ctypes.POINTER(IfaceList)()
        if wlan.WlanEnumInterfaces(handle, None, ctypes.byref(plist)) != 0:
            return False
        try:
            infos = ctypes.cast(ctypes.addressof(plist.contents.first), ctypes.POINTER(IfaceInfo))
            for i in range(plist.contents.count):
                if wlan.WlanScan(handle, ctypes.byref(infos[i].guid), None, None, None) == 0:
                    started += 1
        finally:
            wlan.WlanFreeMemory(plist)
    finally:
        wlan.WlanCloseHandle(handle, None)
    if started:
        time.sleep(wait)
    return started > 0


def mark_connected_windows(aps, me):
    """Marks the access point this computer is using. Newer Windows 11 labels the line
    "AP BSSID", older builds "BSSID"; if neither matches, fall back to name and channel."""
    if me.get("State", "").lower() != "connected":
        return
    bssid = (me.get("AP BSSID") or me.get("BSSID") or "").lower()
    hit = next((a for a in aps if bssid and a["bssid"] == bssid), None)
    if hit is None:
        same = [a for a in aps if a["ssid"] == me.get("SSID") and
                (not me.get("Channel") or a["ch"] == first_int(me["Channel"]))]
        hit = max(same, key=lambda a: a["dbm"], default=None)
    if hit:
        hit["in_use"] = True
        rate = me.get("Receive rate (Mbps)")
        if rate:
            hit["info"]["rate"] = rate + " Mbps"


def wifi_scan_windows():
    scanned = windows_trigger_scan()
    code, out, err = run_cmd(["netsh", "wlan", "show", "networks", "mode=bssid"], 30)
    text = out + err
    if "location" in text.lower() and "permission" in text.lower():
        raise RuntimeError(WINDOWS_LOCATION_HINT)
    if "wlansvc" in text.lower() or "no wireless interface" in text.lower():
        raise RuntimeError("No WiFi adapter found, or the WLAN AutoConfig service is stopped.")
    aps = parse_netsh(out)
    _, iout, _ = run_cmd(["netsh", "wlan", "show", "interfaces"], 30)
    mark_connected_windows(aps, parse_netsh_iface(iout))
    if not aps and code != 0:
        raise RuntimeError("netsh could not scan: " + (text.strip()[:200] or "unknown error"))
    if not scanned and len(aps) <= 1:
        wifi["note"] = ("Windows only reported its last cached scan, which can miss nearby networks. "
                        "Open the WiFi list from the taskbar, then press Scan WiFi again.")
    return aps


def sp_sec(mode):
    m = (mode or "").lower().replace("spairport_security_mode_", "")
    if m in ("none", "") or m.startswith("none"):
        return make_sec(open_=True)
    if "owe" in m:
        return make_sec(owe=True)
    if "wep" in m:
        return make_sec(wep=True)
    ent = "enterprise" in m
    wpa3 = "wpa3" in m
    wpa2 = "wpa2" in m or "transition" in m or (ent and not wpa3)
    wpa = bool(re.search(r"(^|_)wpa(_|$)", m)) or "mixed" in m
    return make_sec(wpa=wpa, wpa2=wpa2 or "mixed" in m, wpa3=wpa3, ent=ent)


def parse_system_profiler(data):
    aps = []

    def one(n, in_use):
        chs = str(n.get("spairport_network_channel", ""))
        band = "6" if "6GHz" in chs else "5" if "5GHz" in chs else "2.4" if "2GHz" in chs else None
        w = re.search(r"(\d+)\s*MHz", chs)
        ch = first_int(chs)
        sig = re.search(r"(-\d+)\s*dBm", str(n.get("spairport_signal_noise", "")))
        name = n.get("_name", "")
        hidden_by_mac = name in ("", "<redacted>")
        a = new_ap(None, "" if hidden_by_mac else name, band or band_of(None, ch), ch,
                   int(w.group(1)) if w else None, int(sig.group(1)) if sig else -100,
                   sp_sec(n.get("spairport_security_mode")), in_use)
        if hidden_by_mac and name:
            a["info"]["redacted"] = True
        if n.get("spairport_network_phymode"):
            a["info"]["radio"] = n["spairport_network_phymode"]
        aps.append(a)

    for item in data.get("SPAirPortDataType", []):
        for iface in item.get("spairport_airport_interfaces", []):
            if iface.get("spairport_current_network_information"):
                one(iface["spairport_current_network_information"], True)
            for n in iface.get("spairport_airport_other_local_wireless_networks") or []:
                one(n, False)
    return aps


def wifi_scan_mac():
    code, out, err = run_cmd(["system_profiler", "SPAirPortDataType", "-json"], 90)
    try:
        aps = parse_system_profiler(json.loads(out))
    except ValueError:
        raise RuntimeError("system_profiler gave no usable output: " + (err.strip()[:200] or "no output"))
    if aps and all(not a["ssid"] for a in aps):
        wifi["note"] = ("macOS hid the network names. Give Terminal Location access in System Settings, "
                        "Privacy and Security, Location Services, then scan again.")
    return aps


_oui = {}


def oui_vendor(mac):
    if not mac or len(mac) < 8:
        return ""
    if int(mac[1], 16) & 2:
        return ""  # locally administered: routers use these for extra SSIDs, phones for hotspots
    if not _oui:
        exe = shutil.which("nmap")
        paths = []
        if exe:
            d = os.path.dirname(os.path.realpath(exe))
            paths += [os.path.join(d, "nmap-mac-prefixes"),
                      os.path.join(d, "..", "share", "nmap", "nmap-mac-prefixes")]
        paths += ["/usr/share/nmap/nmap-mac-prefixes", "/usr/local/share/nmap/nmap-mac-prefixes",
                  "/opt/homebrew/share/nmap/nmap-mac-prefixes",
                  r"C:\Program Files (x86)\Nmap\nmap-mac-prefixes", r"C:\Program Files\Nmap\nmap-mac-prefixes"]
        for p in paths:
            try:
                with open(p, encoding="utf-8", errors="replace") as f:
                    for line in f:
                        k, _, v = line.strip().partition(" ")
                        if k and not k.startswith("#"):
                            _oui[k.upper()] = v.strip()
                break
            except OSError:
                continue
        _oui.setdefault("", "")  # marks the table as loaded, even when no file was found
    h = mac.replace(":", "").replace("-", "").upper()
    for n in (9, 7, 6):
        if h[:n] in _oui:
            return _oui[h[:n]]
    return ""


def wifi_scan():
    """Scans with whatever this system has. Returns (source name, access points)."""
    wifi["note"] = None
    if SYSTEM == "Windows":
        return "netsh", wifi_scan_windows()
    if SYSTEM == "Darwin":
        return "system_profiler", wifi_scan_mac()
    if SYSTEM == "Linux":
        aps = wifi_scan_nmcli()
        if aps is not None:
            return "nmcli", aps
        aps = wifi_scan_iw()
        if aps is not None:
            return "iw", aps
        raise RuntimeError("Can't scan WiFi: install NetworkManager or iw. Run: sudo apt install iw")
    raise RuntimeError("WiFi scanning is not supported on " + SYSTEM)
