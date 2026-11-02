import unittest
from aj import probe
class TestProbe(unittest.TestCase):
    def test_fingerprint_title(self): self.assertEqual(probe.fingerprint({80: {"http": {"title": "TP-LINK Router"}}}), "TP-LINK Router")
    def test_fingerprint_server(self): self.assertEqual(probe.fingerprint({80: {"http": {"server": "nginx"}}}), "nginx")
    def test_fingerprint_ssh(self): self.assertEqual(probe.fingerprint({22: {"ssh": {"software": "OpenSSH_9.6"}}}), "OpenSSH_9.6")
    def test_fingerprint_empty(self): self.assertEqual(probe.fingerprint({}), "")
