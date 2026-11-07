import subprocess
import unittest

from aj import ping

LINUX = """PING 192.168.1.1 (192.168.1.1) 56(84) bytes of data.
64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=1.20 ms
64 bytes from 192.168.1.1: icmp_seq=2 ttl=64 time=0.80 ms
64 bytes from 192.168.1.1: icmp_seq=3 ttl=64 time=2.00 ms
64 bytes from 192.168.1.1: icmp_seq=3 ttl=64 time=2.10 ms (DUP!)

--- 192.168.1.1 ping statistics ---
4 packets transmitted, 3 received, +1 duplicates, 25% packet loss
rtt min/avg/max/mdev = 0.800/1.500/2.000/0.500 ms
"""
MAC = """PING 192.168.1.1 (192.168.1.1): 56 data bytes
64 bytes from 192.168.1.1: icmp_seq=0 ttl=64 time=3.511 ms
64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=2.402 ms
round-trip min/avg/max/stddev = 2.402/2.956/3.511/0.555 ms
"""
WIN_EN = """Pinging 192.168.1.1 with 32 bytes of data:
Reply from 192.168.1.1: bytes=32 time=4ms TTL=64
Reply from 192.168.1.1: bytes=32 time<1ms TTL=64
Reply from 192.168.1.20: Destination host unreachable.
Request timed out.
Ping statistics for 192.168.1.1:
    Packets: Sent = 4, Received = 2, Lost = 2 (50% loss),
Approximate round trip times in milli-seconds:
    Minimum = 1ms, Maximum = 4ms, Average = 2ms
"""
WIN_DE = """Ping wird ausgeführt für 192.168.1.1 mit 32 Bytes Daten:
Antwort von 192.168.1.1: Bytes=32 Zeit=3ms TTL=64
Antwort von 192.168.1.1: Bytes=32 Zeit<1ms TTL=64
Ping-Statistik für 192.168.1.1:
    Minimum = 0ms, Maximum = 3ms, Mittelwert = 1ms
"""


class TestParse(unittest.TestCase):
    def test_linux(self): self.assertEqual(ping.parse_times(LINUX), [1.2, 0.8, 2.0, 2.1])
    def test_mac(self): self.assertEqual(ping.parse_times(MAC), [3.511, 2.402])
    def test_windows_english_ignores_summary_and_unreachable(self):
        self.assertEqual(ping.parse_times(WIN_EN), [4.0, 1.0])  # the old regex needed English "time"
    def test_windows_german(self): self.assertEqual(ping.parse_times(WIN_DE), [3.0, 1.0])
    def test_garbage(self): self.assertEqual(ping.parse_times("ping: unknown host"), [])

    def test_duplicates_cannot_exceed_sent(self):
        r = ping.summarize(ping.parse_times(LINUX), 3)
        self.assertEqual(r["loss"], 0)
        self.assertEqual(r["sent"], 3)


class TestCmd(unittest.TestCase):
    def test_windows_fits_its_own_pace(self):
        cmd, sent, limit = ping.build_cmd("Windows", "192.168.1.1")
        self.assertGreater(limit, sent)  # one ping a second: the time limit must outlast the count
        self.assertNotIn("-i", cmd)

    def test_mac_does_not_use_linux_flags(self):
        cmd, _, _ = ping.build_cmd("Darwin", "192.168.1.1")
        self.assertNotIn("-W", cmd)  # milliseconds on macOS, seconds on Linux
        self.assertIn("-t", cmd)

    def test_linux_slow_fallback_has_no_interval(self):
        self.assertNotIn("-i", ping.build_cmd("Linux", "192.168.1.1", fast=False)[0])


class TestPingGateway(unittest.TestCase):
    def test_ok(self):
        r = ping.ping_gateway("192.168.1.1", "Linux", run=lambda c, t: LINUX)
        self.assertEqual((r["sent"], r["loss"]), (20, 16))  # 4 replies of 20 sent
        self.assertEqual(r["max"], 2.1)

    def test_falls_back_when_interval_not_allowed(self):
        calls = []
        def run(cmd, t):
            calls.append(cmd)
            return "ping: only the super-user may use an interval this short\n" if "-i" in cmd else MAC
        r = ping.ping_gateway("192.168.1.1", "Darwin", run=run)
        self.assertEqual(len(calls), 2)
        self.assertEqual(r["sent"], ping.SLOW_COUNT)

    def test_no_replies(self):
        self.assertEqual(ping.ping_gateway("192.168.1.1", "Linux", run=lambda c, t: "100% packet loss"),
                         {"error": "No replies from router."})

    def test_timeout_and_missing_binary(self):
        def slow(c, t): raise subprocess.TimeoutExpired(c, t)
        def gone(c, t): raise FileNotFoundError()
        self.assertIn("too long", ping.ping_gateway("192.168.1.1", "Linux", run=slow)["error"])
        self.assertIn("isn't available", ping.ping_gateway("192.168.1.1", "Linux", run=gone)["error"])

    def test_rejects_non_ip_input(self):
        called = []
        for bad in ("; rm -rf /", "example.com", "fe80::1", ""):
            r = ping.ping_gateway(bad, "Linux", run=lambda c, t: called.append(c) or "")
            self.assertIn("error", r)
        self.assertEqual(called, [])  # nothing was ever run for these


if __name__ == "__main__":
    unittest.main()
