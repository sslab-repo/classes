#!/usr/bin/env python3
"""Test suite for packet_generator.py (stdlib unittest, no external deps).

Run from anywhere:
    python3 -m unittest discover -s tests
or:
    python3 tests/test_packet_generator.py

Raw-packet crafting is validated by monkeypatching scapy's send/sendp to
CAPTURE packets instead of transmitting them, and by simulating root, so the
suite needs neither sudo nor a live network. The http / http-dos paths are
tested against a real loopback HTTP server. Crafting tests are skipped
automatically if scapy is not installed.
"""
import contextlib
import http.server
import importlib.util
import io
import os
import socketserver
import sys
import threading
import unittest

# --- import the module under test by path (cwd-independent) -----------------
_HERE = os.path.dirname(os.path.abspath(__file__))
_PG_PATH = os.path.join(_HERE, os.pardir, "packet_generator.py")
_spec = importlib.util.spec_from_file_location("pg_under_test", _PG_PATH)
pg = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pg)

try:
    import scapy.all as scapy  # noqa: F401
    HAVE_SCAPY = True
except ImportError:
    HAVE_SCAPY = False


class Capture:
    """Collects packets that would have been sent."""

    def __init__(self):
        self.items = []

    def send(self, pkt, count=1, inter=0, verbose=True, **kw):
        self.items.append(("send", pkt, count, inter, kw))

    def sendp(self, pkt, count=1, inter=0, verbose=True, **kw):
        self.items.append(("sendp", pkt, count, inter, kw))


def run_main(argv, stdin_text=None):
    """Invoke pg.main(argv); return (rc, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    old_stdin = sys.stdin
    if stdin_text is not None:
        sys.stdin = io.StringIO(stdin_text)
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                rc = pg.main(argv)
            except SystemExit as exc:
                rc = exc.code
    finally:
        sys.stdin = old_stdin
    return rc, out.getvalue(), err.getvalue()


class ValidationTests(unittest.TestCase):
    """Argument validation - no scapy or root required."""

    def test_over_cap_rejected(self):
        rc, _, err = run_main(["--protocol", "icmp", "--target", "192.168.56.10",
                               "--count", "99999"])
        self.assertEqual(rc, 1)
        self.assertIn("exceeds the cap", err)

    def test_count_zero_rejected(self):
        rc, _, _ = run_main(["--protocol", "icmp", "--target", "192.168.56.10",
                             "--count", "0"])
        self.assertEqual(rc, 1)

    def test_bad_port_rejected(self):
        rc, _, _ = run_main(["--protocol", "udp", "--target", "192.168.56.10",
                             "--port", "99999"])
        self.assertEqual(rc, 1)

    def test_port_zero_rejected(self):
        rc, _, _ = run_main(["--protocol", "udp", "--target", "192.168.56.10",
                             "--port", "0"])
        self.assertEqual(rc, 1)

    def test_negative_interval_rejected(self):
        rc, _, err = run_main(["--protocol", "http", "--target", "127.0.0.1",
                               "--port", "80", "--interval", "-1", "--count", "1"])
        self.assertEqual(rc, 1)
        self.assertNotIn("Traceback", err)

    def test_ipv6_rejected(self):
        rc, _, err = run_main(["--protocol", "icmp", "--target", "::1"])
        self.assertNotEqual(rc, 0)
        self.assertIn("IPv4", err)

    def test_cap_boundary_allows_exact(self):
        with SimulatedRoot(), PatchedScapy() as cap:
            rc, _, _ = run_main(["--protocol", "icmp", "--target", "192.168.56.10",
                                 "--count", str(pg.MAX_COUNT["icmp"])])
        self.assertEqual(rc, 0)
        self.assertTrue(cap.items)

    def test_dns_requires_query_before_root(self):
        with SimulatedNonRoot():
            rc, _, err = run_main(["--protocol", "dns", "--target", "192.168.56.53"])
        self.assertEqual(rc, 1)
        self.assertIn("--query", err)
        self.assertNotIn("sudo", err)

    def test_synflood_requires_port_before_root(self):
        with SimulatedNonRoot():
            rc, _, err = run_main(["--protocol", "syn-flood", "--target",
                                   "192.168.56.10", "--yes"])
        self.assertEqual(rc, 1)
        self.assertIn("--port", err)
        self.assertNotIn("sudo", err)


class AmplificationGuardTests(unittest.TestCase):
    def test_helper_flags_multicast(self):
        self.assertIsNotNone(pg.amplification_risk("224.0.0.1"))

    def test_helper_flags_broadcast(self):
        self.assertIsNotNone(pg.amplification_risk("255.255.255.255"))

    def test_helper_allows_unicast(self):
        self.assertIsNone(pg.amplification_risk("192.168.56.10"))

    def test_icmp_multicast_refused(self):
        with SimulatedRoot(), PatchedScapy():
            rc, _, err = run_main(["--protocol", "icmp", "--target", "224.0.0.1"])
        self.assertEqual(rc, 1)
        self.assertIn("multicast", err)

    def test_udp_broadcast_refused(self):
        with SimulatedRoot(), PatchedScapy():
            rc, _, err = run_main(["--protocol", "udp", "--target",
                                   "255.255.255.255", "--port", "9"])
        self.assertEqual(rc, 1)
        self.assertIn("broadcast", err)


class HttpHelperTests(unittest.TestCase):
    def test_path_adds_leading_slash(self):
        self.assertEqual(pg._http_path("abc"), "/abc")

    def test_path_keeps_leading_slash(self):
        self.assertEqual(pg._http_path("/abc"), "/abc")

    def test_path_empty_becomes_root(self):
        self.assertEqual(pg._http_path(""), "/")

    def test_host_header_omits_default_port(self):
        self.assertEqual(pg._host_header("1.2.3.4", 80), "1.2.3.4")

    def test_host_header_includes_nondefault_port(self):
        self.assertEqual(pg._host_header("1.2.3.4", 8080), "1.2.3.4:8080")

    def test_path_rejects_crlf(self):
        # CRLF in the path would allow HTTP request-header injection.
        rc, _, err = run_main(["--protocol", "http", "--target", "127.0.0.1",
                               "--port", "80", "--path", "/a\r\nX: 1"])
        self.assertEqual(rc, 1)
        self.assertIn("--path", err)


@unittest.skipUnless(HAVE_SCAPY, "scapy not installed")
class CraftingTests(unittest.TestCase):
    def _one(self, argv):
        with SimulatedRoot(), PatchedScapy() as cap:
            rc, out, err = run_main(argv)
        return rc, cap, out, err

    def test_icmp(self):
        rc, cap, _, err = self._one(["--protocol", "icmp", "--target",
                                     "192.168.56.10", "--count", "5"])
        self.assertEqual(rc, 0, err)
        kind, pkt, cnt, _, _ = cap.items[0]
        self.assertEqual(kind, "send")
        self.assertEqual(cnt, 5)
        self.assertEqual(pkt.dst, "192.168.56.10")
        self.assertTrue(pkt.haslayer(scapy.ICMP))

    def test_icmp_payload(self):
        _, cap, _, _ = self._one(["--protocol", "icmp", "--target",
                                  "192.168.56.10", "--payload", "hello"])
        self.assertIn(b"hello", bytes(cap.items[0][1]))

    def test_arp(self):
        rc, cap, _, err = self._one(["--protocol", "arp", "--target",
                                     "192.168.56.10", "--count", "3"])
        self.assertEqual(rc, 0, err)
        kind, pkt, _, _, _ = cap.items[0]
        self.assertEqual(kind, "sendp")
        self.assertEqual(pkt.dst, "ff:ff:ff:ff:ff:ff")
        self.assertEqual(pkt[scapy.ARP].pdst, "192.168.56.10")
        self.assertEqual(pkt[scapy.ARP].op, 1)

    def test_udp(self):
        _, cap, _, _ = self._one(["--protocol", "udp", "--target",
                                  "192.168.56.10", "--port", "9999",
                                  "--count", "10", "--payload", "hi"])
        pkt = cap.items[0][1]
        self.assertEqual(pkt[scapy.UDP].dport, 9999)
        self.assertIn(b"hi", bytes(pkt))

    def test_udp_default_port(self):
        _, cap, _, _ = self._one(["--protocol", "udp", "--target", "192.168.56.10"])
        self.assertEqual(cap.items[0][1][scapy.UDP].dport, 9999)

    def test_dns(self):
        rc, cap, _, err = self._one(["--protocol", "dns", "--target",
                                     "192.168.56.53", "--query", "example.com",
                                     "--count", "2"])
        self.assertEqual(rc, 0, err)
        pkt = cap.items[0][1]
        self.assertEqual(pkt[scapy.UDP].dport, 53)
        # Assert on the wire encoding (length-prefixed labels) to avoid the
        # deprecated single-element .qd attribute access in scapy 2.7+.
        self.assertIn(b"\x07example\x03com\x00", bytes(pkt))

    def test_syn_flood(self):
        rc, cap, _, err = self._one(["--protocol", "syn-flood", "--target",
                                     "192.168.56.10", "--port", "80",
                                     "--count", "50", "--yes"])
        self.assertEqual(rc, 0, err)
        pkt = cap.items[0][1]
        self.assertEqual(str(pkt[scapy.TCP].flags), "S")
        self.assertEqual(pkt[scapy.TCP].dport, 80)

    def test_syn_flood_source_port_varies(self):
        # Educational correctness: each SYN should use a different source port.
        _, cap, _, _ = self._one(["--protocol", "syn-flood", "--target",
                                   "192.168.56.10", "--port", "80",
                                   "--count", "2", "--yes"])
        pkt = cap.items[0][1]
        ports = {int.from_bytes(bytes(pkt)[20:22], "big") for _ in range(8)}
        self.assertGreater(len(ports), 1)


class ConfirmationTests(unittest.TestCase):
    def test_prompt_no_aborts(self):
        with SimulatedRoot(), PatchedScapy():
            rc, _, _ = run_main(["--protocol", "syn-flood", "--target",
                                 "192.168.56.10", "--port", "80", "--count", "10"],
                                stdin_text="no\n")
        self.assertEqual(rc, 1)

    def test_prompt_yes_proceeds(self):
        with SimulatedRoot(), PatchedScapy():
            rc, _, err = run_main(["--protocol", "syn-flood", "--target",
                                   "192.168.56.10", "--port", "80", "--count", "10"],
                                  stdin_text="yes\n")
        self.assertEqual(rc, 0, err)

    def test_prompt_eof_aborts(self):
        with SimulatedRoot(), PatchedScapy():
            rc, _, _ = run_main(["--protocol", "syn-flood", "--target",
                                 "192.168.56.10", "--port", "80", "--count", "10"],
                                stdin_text="")
        self.assertEqual(rc, 1)


class HttpServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.recorded = []
        recorded = cls.recorded

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                recorded.append((self.path, self.headers.get("Host")))
                body = b"ok"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        cls.httpd = socketserver.TCPServer(("127.0.0.1", 0), Handler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def test_http_get(self):
        self.recorded.clear()
        rc, out, err = run_main(["--protocol", "http", "--target", "127.0.0.1",
                                 "--port", str(self.port), "--count", "3",
                                 "--verbose", "--path", "noslash"])
        self.assertEqual(rc, 0, err)
        self.assertIn("3/3", out)
        self.assertEqual(self.recorded[0][0], "/noslash")
        self.assertEqual(self.recorded[0][1], f"127.0.0.1:{self.port}")

    def test_http_dos(self):
        rc, out, err = run_main(["--protocol", "http-dos", "--target", "127.0.0.1",
                                 "--port", str(self.port), "--count", "5", "--yes"])
        self.assertEqual(rc, 0, err)
        self.assertIn("5/5", out)

    def test_http_closed_port_graceful(self):
        rc, out, _ = run_main(["--protocol", "http", "--target", "127.0.0.1",
                               "--port", "1", "--count", "2"])
        self.assertEqual(rc, 0)
        self.assertIn("0/2", out)


# --- context managers for simulating privilege / patching scapy -------------
class SimulatedRoot:
    def __enter__(self):
        self._orig = pg.os.geteuid
        pg.os.geteuid = lambda: 0

    def __exit__(self, *a):
        pg.os.geteuid = self._orig


class SimulatedNonRoot:
    def __enter__(self):
        self._orig = pg.os.geteuid
        pg.os.geteuid = lambda: 1000

    def __exit__(self, *a):
        pg.os.geteuid = self._orig


class PatchedScapy:
    """Patch scapy.all.send/sendp to capture instead of transmit."""

    def __enter__(self):
        self.cap = Capture()
        if HAVE_SCAPY:
            self._osend, self._osendp = scapy.send, scapy.sendp
            scapy.send, scapy.sendp = self.cap.send, self.cap.sendp
        return self.cap

    def __exit__(self, *a):
        if HAVE_SCAPY:
            scapy.send, scapy.sendp = self._osend, self._osendp


if __name__ == "__main__":
    unittest.main(verbosity=2)
