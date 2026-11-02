"""Running nmap: streamed progress and the timeout watchdog."""
import os
import shutil
import tempfile
import unittest

import helpers  # sets up the import path and a throwaway database
from aj import config as aj_config
from aj import tools as aj_tools


FAKE_NMAP = """#!/bin/sh
echo '<?xml version="1.0"?>'
echo '<nmaprun>'
echo '<taskprogress task="SYN Stealth Scan" time="1" percent="42.50" remaining="80" etc="2"/>'
sleep ${FAKE_SLEEP:-0}
echo '<host><status state="up"/><address addr="192.168.1.9" addrtype="ipv4"/></host>'
echo '</nmaprun>'
"""


@unittest.skipUnless(os.name == "posix", "uses a stand-in nmap shell script")
class NmapRunner(unittest.TestCase):
    def setUp(self):
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "nmap"), "w") as f:
            f.write(FAKE_NMAP)
        os.chmod(os.path.join(d, "nmap"), 0o755)
        self.old_path = os.environ["PATH"]
        os.environ["PATH"] = d + os.pathsep + self.old_path

    def tearDown(self):
        os.environ["PATH"] = self.old_path
        os.environ.pop("FAKE_SLEEP", None)

    def test_progress_and_result(self):
        aj_config.state["progress"] = None
        root = aj_tools.run_nmap(["-sn", "x"])
        self.assertEqual(aj_tools.host_ip(root.find("host")), "192.168.1.9")
        self.assertEqual(aj_config.state["progress"], {"task": "port scan", "percent": 42.5, "remaining": 80})

    def test_watchdog(self):
        import subprocess
        os.environ["FAKE_SLEEP"] = "3"
        with self.assertRaises(subprocess.TimeoutExpired):
            aj_tools.run_nmap(["-sn", "x"], timeout=1)


@unittest.skipUnless(shutil.which("setpriv") and hasattr(os, "geteuid") and os.geteuid() == 0,
                     "needs Linux, root and setpriv")
class Capabilities(unittest.TestCase):
    """The Pi service runs as an ordinary user holding only CAP_NET_RAW and CAP_NET_ADMIN."""
    CHECK = ("import sys; sys.path.insert(0, %r); from aj import tools; "
             "print(tools.net_caps(), tools.is_admin(), tools.nmap_privileged())")

    def run_as_nobody(self, caps):
        import subprocess
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        extra = ["--inh-caps=+net_raw,+net_admin", "--ambient-caps=+net_raw,+net_admin"] if caps else []
        out = subprocess.run(["setpriv", "--reuid=nobody", "--regid=nogroup", "--clear-groups"] + extra +
                             ["python3", "-c", self.CHECK % root], capture_output=True, text=True)
        if out.returncode:
            self.skipTest("could not run as nobody here: " + out.stderr.strip()[-120:])
        return out.stdout.split()

    def test_ordinary_user_is_not_privileged(self):
        self.assertEqual(self.run_as_nobody(False), ["False", "False", "False"])

    def test_capabilities_are_enough(self):
        self.assertEqual(self.run_as_nobody(True), ["True", "True", "True"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
