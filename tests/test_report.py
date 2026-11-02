"""The one-shot audit report: the self-contained HTML is built from a snapshot."""
import time
import unittest
from unittest import mock

import helpers  # sets up the import path and a throwaway database
from aj import report as aj_report


def snapshot(**over):
    data = {
        "network": {"name": "Home", "subnet": "192.168.1.0/24"},
        "security": {
            "score": 67, "grade": "D", "partial": False, "unscored": False,
            "lost": {"wifi": 0, "devices": 33, "internet": 0},
            "issues": [{"id": "telnet", "level": "high", "points": 15, "where": "192.168.1.20",
                        "title": "Turn off Telnet on Garage camera", "problem": "Telnet is open.",
                        "fix": "Switch it off in the device settings."}],
            "optional": ["Check the password on the router."],
            "checks": [{"label": "Telnet is off everywhere", "status": "fail"},
                       {"label": "WPS is off", "status": "unknown"},
                       {"label": "No anonymous FTP", "status": "pass"}],
            "exposure": {"reachable": True, "mappings": [
                {"enabled": True, "proto": "TCP", "ext": 3389, "device": "Office PC", "service": "Remote Desktop", "risky": True}]},
        },
        "wifi": {"result": {"conn": {"ssid": "Home", "band": "5", "ch": 36, "dbm": -55, "quality": "excellent"},
                            "weak_nearby": 1}},
        "health": {"status": "up", "uptime_7d": 99.9, "latency": 20},
        "devices": [
            {"ip": "192.168.1.20", "name": "Garage camera", "kind": "iot",
             "audit": {"ports": [{"port": 23, "name": "Telnet"}], "shares": [], "info": {}}},
            {"ip": "192.168.1.30", "hostname": "office-pc", "kind": "personal", "audit": None},
        ],
    }
    data.update(over)
    return data


class Report(unittest.TestCase):
    def test_contains_the_key_sections(self):
        h = aj_report.build_report(snapshot(), now=0)
        self.assertTrue(h.startswith("<!doctype html>"))
        for piece in ["Network audit: Home", "Security score: 67/100", "What to fix",
                      "Turn off Telnet on Garage camera", "How:", "Worth checking", "Checks",
                      "Open to the internet", "Remote Desktop", "WiFi", "Devices (2)", "Garage camera",
                      "never tried a password"]:
            self.assertIn(piece, h, piece)

    def test_escapes_names(self):
        d = snapshot()
        d["devices"][0]["name"] = "<script>evil</script>"
        h = aj_report.build_report(d, now=0)
        self.assertNotIn("<script>evil", h)
        self.assertIn("&lt;script&gt;evil", h)

    def test_device_note_summarizes_exposure(self):
        d = {"ip": "192.168.1.9", "audit": {"ports": [{"port": 445, "name": "SMB file sharing"}],
             "shares": [{"name": "Backups", "access": "read/write"}], "smb1": True,
             "web": {"auth": "open"}, "rtsp": {"open": True}}}
        note = aj_report.device_note(d)
        self.assertIn("SMB file sharing", note)
        self.assertIn("share 'Backups' (read/write", note)
        self.assertIn("admin page open", note)
        self.assertIn("camera stream", note)
        self.assertIn("SMBv1 on", note)

    def test_builds_on_windows_strftime(self):
        # Windows' strftime rejects the %-d / %-I no-pad flags that glibc accepts, raising
        # ValueError. The report must not use them, or /api/report resets the connection on
        # Windows. Simulate that stricter strftime and confirm the report still builds.
        real = time.strftime

        def strict(fmt, *a):
            if "%-" in fmt or "%#" in fmt:
                raise ValueError("Invalid format string")
            return real(fmt, *a)

        with mock.patch("aj.report.time.strftime", strict):
            h = aj_report.build_report(snapshot(), now=1730505600)
        self.assertIn("2024", h)
        self.assertIn("Network audit: Home", h)

    def test_unscored_report_still_builds(self):
        h = aj_report.build_report(snapshot(security={"unscored": True, "missing": ["WiFi (tap Scan WiFi)"]}), now=0)
        self.assertIn("Not fully checked", h)
        self.assertIn("Devices", h)


if __name__ == "__main__":
    unittest.main(verbosity=2)
