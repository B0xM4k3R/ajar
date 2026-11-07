"""The WiFi tab said 'Not scanned yet' right after a scan finished, whenever no device scan had run yet,
because the finished scan was discarded unless Ajar already knew which network it was on."""
import os
import time
import unittest
from unittest import mock

import helpers  # noqa: F401
from helpers import ap
from aj import config, jobs, wifi_analyze
from aj.config import wifi, state


class UnsavedScan(unittest.TestCase):
    def setUp(self):
        self.saved = (dict(wifi), state.get("net"))
        state["net"] = None
        wifi.update(raw=None, scanning=False, error=None)
        self.patch = mock.patch.object(wifi_analyze, "get_setting", lambda k, d=None: None)  # no remembered network either
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        wifi.clear(); wifi.update(self.saved[0]); state["net"] = self.saved[1]

    def fake_scan(self):
        return "nmcli", [ap("ATT-WIFI-Q3LN", "5", 149, -75), ap("Neighbour", "2.4", 6, -80)]

    def test_nothing_scanned_yet(self):
        snap = wifi_analyze.wifi_snapshot()
        self.assertIsNone(snap["result"])
        self.assertFalse(snap["unsaved"])

    def test_a_finished_scan_is_shown_even_before_the_network_is_known(self):
        with mock.patch.object(jobs, "wifi_scan", self.fake_scan):
            self.assertTrue(jobs.start_wifi())
            for _ in range(100):
                if not wifi["scanning"]:
                    break
                time.sleep(0.02)
        snap = wifi_analyze.wifi_snapshot()
        self.assertIsNone(snap["error"])
        self.assertEqual(sorted(n["ssid"] for n in snap["result"]["nets"]), ["ATT-WIFI-Q3LN", "Neighbour"])
        self.assertTrue(snap["unsaved"])  # so the page can say "press Map Network to keep it"
        self.assertFalse(snap["scanning"])

    def test_once_the_network_is_known_it_is_no_longer_unsaved(self):
        wifi["raw"] = {"scanned": time.time(), "source": "nmcli", "aps": [ap("ATT", "5", 36, -60)]}
        state["net"] = "nwifi"
        snap = wifi_analyze.wifi_snapshot()
        self.assertIsNotNone(snap["result"])
        self.assertFalse(snap["unsaved"])

    def test_viewing_another_network_does_not_borrow_the_live_scan(self):
        wifi["raw"] = {"scanned": time.time(), "source": "nmcli", "aps": [ap("ATT", "5", 36, -60)]}
        state["net"] = "nwifi"
        self.assertIsNone(wifi_analyze.wifi_snapshot("some-other-net")["result"])


class Layout(unittest.TestCase):
    def test_accept_buttons_go_in_the_wide_column(self):
        """The Accept button was a third grid item and landed squeezed in the narrow points column."""
        with open(os.path.join(config.HERE, "web", "app.css"), encoding="utf-8") as f:
            css = f.read()
        self.assertIn(".fixes > li > .mini { grid-column: 2;", css)

    def test_the_old_wording_pointing_at_a_button_that_does_not_exist_is_gone(self):
        with open(os.path.join(config.HERE, "web", "app.js"), encoding="utf-8") as f:
            js = f.read()
        self.assertNotIn("Scan WiFi", js)


if __name__ == "__main__":
    unittest.main()
