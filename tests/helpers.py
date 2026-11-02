"""Shared test fixtures: sample scanner output from each system, and small builders.
Importing this module also points ajar at a throwaway database, so tests never
touch your real ajar.db."""
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # the project folder

from aj import config as aj_config  # noqa: E402
from aj import db as aj_db  # noqa: E402
from aj import audit as aj_audit  # noqa: E402
from aj import wifi_scan as aj_wifi_scan  # noqa: E402

aj_config.DB = os.path.join(tempfile.mkdtemp(), "test.db")
aj_db.init_db()

NMCLI = r"""*:AA\:BB\:CC\:00\:00\:01:HomeNet:6:2437 MHz:78:WPA2:(none):pair_ccmp group_ccmp psk:20 MHz
:AA\:BB\:CC\:00\:00\:02:HomeNet:36:5180 MHz:64:WPA2 WPA3:(none):pair_ccmp group_ccmp psk sae:80 MHz
:11\:22\:33\:44\:55\:66:Neighbor\:5G:6:2437 MHz:70:WPA1 WPA2:pair_tkip pair_ccmp group_tkip psk:pair_tkip pair_ccmp group_tkip psk:20 MHz
:11\:22\:33\:44\:55\:77:CoffeeShop:11:2462 MHz:40::(none):(none):20 MHz
:11\:22\:33\:44\:55\:88::1:2412 MHz:20:WPA2:(none):pair_ccmp group_ccmp psk:20 MHz
:11\:22\:33\:44\:55\:99:Neighbor2:44:5220 MHz:50:WPA2:(none):pair_ccmp group_ccmp psk:80 MHz
"""

IW = """BSS aa:bb:cc:00:00:01(on wlan0) -- associated
\tlast seen: 120 ms ago
\tfreq: 2437.0
\tbeacon interval: 100 TUs
\tcapability: ESS Privacy ShortSlotTime (0x0411)
\tsignal: -48.00 dBm
\tSSID: HomeNet
\tDS Parameter set: channel 6
\tRSN:\t * Version: 1
\t\t * Group cipher: CCMP
\t\t * Pairwise ciphers: CCMP
\t\t * Authentication suites: PSK SAE
\t\t * Capabilities: 1-PTKSA-RC 1-GTKSA-RC (0x0000)
\tHT operation:
\t\t * primary channel: 6
\t\t * secondary channel offset: above
\t\t * STA channel width: any
\tWPS:\t * Version: 1.0
\t\t * Wi-Fi Protected Setup State: 2 (Configured)
\t\t * Manufacturer: NETGEAR, Inc.
\t\t * Model: RAX40
\t\t * Device name: RAX40
BSS 11:22:33:44:55:66(on wlan0)
\tfreq: 5745
\tcapability: ESS Privacy (0x0011)
\tsignal: -71.00 dBm
\tSSID: Neighbor
\tRSN:\t * Version: 1
\t\t * Group cipher: TKIP
\t\t * Pairwise ciphers: CCMP TKIP
\t\t * Authentication suites: PSK
\tWPA:\t * Version: 1
\t\t * Group cipher: TKIP
\t\t * Pairwise ciphers: TKIP
\t\t * Authentication suites: PSK
\tHT operation:
\t\t * primary channel: 149
\t\t * secondary channel offset: above
\tVHT operation:
\t\t * channel width: 1 (80 MHz)
\t\t * center freq segment 1: 155
BSS 11:22:33:44:55:77(on wlan0)
\tfreq: 2412
\tcapability: ESS ShortSlotTime (0x0401)
\tsignal: -80.00 dBm
\tSSID: FreeWiFi
\tDS Parameter set: channel 1
BSS 11:22:33:44:55:88(on wlan0)
\tfreq: 2462
\tcapability: ESS Privacy (0x0011)
\tsignal: -83.00 dBm
\tSSID: OldRouter
\tDS Parameter set: channel 11
BSS 11:22:33:44:55:99(on wlan0)
\tfreq: 6115
\tcapability: ESS Privacy (0x0011)
\tsignal: -66.00 dBm
\tSSID: Neighbor6
\tRSN:\t * Version: 1
\t\t * Pairwise ciphers: CCMP
\t\t * Authentication suites: SAE
"""

NETSH = """
Interface name : Wi-Fi
There are 3 networks currently visible.

SSID 1 : HomeNet
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : aa:bb:cc:00:00:02
         Signal             : 92%
         Radio type         : 802.11ax
         Band               : 5 GHz
         Channel            : 36
         Basic rates (Mbps) : 6 12 24
    BSSID 2                 : aa:bb:cc:00:00:01
         Signal             : 80%
         Radio type         : 802.11ax
         Band               : 2.4 GHz
         Channel            : 6

SSID 2 : Neighbor
    Network type            : Infrastructure
    Authentication          : WPA-Personal
    Encryption              : TKIP
    BSSID 1                 : 11:22:33:44:55:66
         Signal             : 40%
         Radio type         : 802.11n
         Channel            : 11

SSID 3 : Guest
    Network type            : Infrastructure
    Authentication          : Open
    Encryption              : None
    BSSID 1                 : 11:22:33:44:55:77
         Signal             : 30%
         Band               : 6 GHz
         Channel            : 37
"""

NETSH_IFACE = """
There is 1 interface on the system:

    Name                   : Wi-Fi
    Description            : Intel(R) Wi-Fi 6 AX201 160MHz
    State                  : connected
    SSID                   : HomeNet
    BSSID                  : aa:bb:cc:00:00:02
    Band                   : 5 GHz
    Channel                : 36
    Receive rate (Mbps)    : 1201
    Signal                 : 92%
"""

SP = {"SPAirPortDataType": [{"spairport_airport_interfaces": [{
    "_name": "en0",
    "spairport_current_network_information": {
        "_name": "HomeNet", "spairport_network_channel": "36 (5GHz, 80MHz)",
        "spairport_network_phymode": "802.11ax",
        "spairport_security_mode": "spairport_security_mode_wpa3_transition",
        "spairport_signal_noise": "-52 dBm / -94 dBm"},
    "spairport_airport_other_local_wireless_networks": [
        {"_name": "Neighbor", "spairport_network_channel": "6 (2GHz, 20MHz)",
         "spairport_security_mode": "spairport_security_mode_wpa_personal_mixed",
         "spairport_signal_noise": "-70 dBm / -95 dBm"},
        {"_name": "Cafe", "spairport_network_channel": 11,
         "spairport_security_mode": "spairport_security_mode_none"},
    ]}]}]}


def ap(ssid, band, ch, dbm, width=20, label="wpa2", bssid=None, in_use=False):
    sec = {"wpa2": aj_wifi_scan.make_sec(wpa2=True, ccmp=True), "open": aj_wifi_scan.make_sec(open_=True),
           "wpa3": aj_wifi_scan.make_sec(wpa2=True, wpa3=True, ccmp=True)}[label]
    return aj_wifi_scan.new_ap(bssid or f"02:00:00:{ch:02x}:{abs(dbm):02x}:{len(ssid):02x}", ssid, band, ch,
                    width, dbm, sec, in_use)


def dev(ip, ports=(), shares=(), approved=1, online=1, seen_days_ago=0, **audit):
    a = {"ports": [{"port": p, "name": aj_audit.PORT_NAMES.get(p, str(p))} for p in ports],
         "shares": [{"name": n, "access": acc} for n, acc in shares], "ftp_anon": False, "nfs": []}
    a.update(audit)
    return {"mac": "aa:" + ip, "ip": ip, "name": "dev" + ip.split(".")[-1], "hostname": None, "vendor": None,
            "approved": approved, "online": online, "last_seen": time.time() - seen_days_ago * 86400, "audit": a}


