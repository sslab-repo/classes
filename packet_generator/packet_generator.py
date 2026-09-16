#!/usr/bin/env python3
"""
packet_generator.py - An educational packet-generation tool.

This tool is for use in a controlled classroom / lab environment against
targets you own or are explicitly authorized to test. It intentionally keeps
per-protocol packet caps low and does NOT spoof source IP addresses, so that
all traffic remains traceable within the lab.

Supported protocols:
    arp        ARP who-has request (layer 2)
    icmp       ICMP echo request (ping)
    udp        UDP datagram with an optional payload
    dns        DNS query over UDP
    http       HTTP GET request(s) over a normal TCP socket
    syn-flood  Limited TCP SYN flood (teaching demo, hard packet cap)
    http-dos   Limited HTTP request flood (teaching demo, hard request cap)

Examples:
    sudo python3 packet_generator.py --protocol icmp  --target 192.168.56.10 --count 5
    sudo python3 packet_generator.py --protocol arp   --target 192.168.56.10 --count 3
    sudo python3 packet_generator.py --protocol udp   --target 192.168.56.10 --port 9999 --count 10 --payload "hello"
    sudo python3 packet_generator.py --protocol dns   --target 192.168.56.53 --query example.com --count 5
         python3 packet_generator.py --protocol http  --target 192.168.56.10 --port 80 --count 5 --path /
    sudo python3 packet_generator.py --protocol syn-flood --target 192.168.56.10 --port 80 --count 200
         python3 packet_generator.py --protocol http-dos  --target 192.168.56.10 --port 80 --count 100
"""

import argparse
import ipaddress
import os
import socket
import sys
import time

# --- Safety configuration ---------------------------------------------------
# Per-protocol hard caps on the number of packets/requests. Adjust for your
# lab, but keep them small: this is a teaching tool, not an attack tool.
MAX_COUNT = {
    "arp": 1000,
    "icmp": 1000,
    "udp": 1000,
    "dns": 1000,
    "http": 1000,
    "syn-flood": 500,   # limited flood for demonstration only
    "http-dos": 500,    # limited HTTP flood for demonstration only
}

# Protocols that craft raw packets and therefore require root privileges.
NEEDS_ROOT = {"arp", "icmp", "udp", "dns", "syn-flood"}

# Protocols considered "aggressive": prompt for confirmation before running.
AGGRESSIVE = {"syn-flood", "http-dos"}

BANNER = r"""
+---------------------------------------------------------------+
|   packet_generator - educational lab tool                     |
|   Use ONLY against systems you own or are authorized to test. |
|   Unauthorized use may be illegal.                            |
+---------------------------------------------------------------+
"""


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def validate_ip(value):
    """argparse type: accept an IPv4 address.

    Restricted to IPv4 because the raw-packet layers used here (scapy's IP()
    and ARP) are IPv4-only; accepting IPv6 would produce confusing failures.
    """
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"'{value}' is not a valid IP address")
    if addr.version != 4:
        raise argparse.ArgumentTypeError(
            f"'{value}' is IPv6; this tool supports IPv4 targets only")
    return value


def require_root(protocol):
    if protocol in NEEDS_ROOT and os.geteuid() != 0:
        eprint(f"[x] Protocol '{protocol}' needs raw-socket access; run with sudo.")
        sys.exit(1)


def confirm(protocol, target, port, count):
    """Interactive safety confirmation for aggressive modes."""
    eprint(f"[!] '{protocol}' will send {count} packet(s) to {target}"
           f"{(':' + str(port)) if port else ''}.")
    eprint("[!] Only continue if you are authorized to test this target.")
    try:
        answer = input("    Type 'yes' to continue: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        answer = ""
    if answer != "yes":
        eprint("[x] Aborted.")
        sys.exit(1)


# --- Scapy-based protocols --------------------------------------------------
def _load_scapy():
    try:
        import scapy.all as scapy
    except ImportError:
        eprint("[x] scapy is not installed. Run ./install_deps.sh first.")
        sys.exit(1)
    return scapy


def send_arp(args):
    s = _load_scapy()
    pkt = s.Ether(dst="ff:ff:ff:ff:ff:ff") / s.ARP(op=1, pdst=args.target)
    kwargs = {"count": args.count, "inter": args.interval, "verbose": args.verbose}
    if args.iface:
        kwargs["iface"] = args.iface
    s.sendp(pkt, **kwargs)


def send_icmp(args):
    s = _load_scapy()
    pkt = s.IP(dst=args.target) / s.ICMP()
    if args.payload:
        pkt = pkt / s.Raw(load=args.payload.encode())
    s.send(pkt, count=args.count, inter=args.interval, verbose=args.verbose)


def send_udp(args):
    s = _load_scapy()
    port = args.port if args.port is not None else 9999
    payload = (args.payload or "packet_generator lab").encode()
    pkt = s.IP(dst=args.target) / s.UDP(dport=port) / s.Raw(load=payload)
    s.send(pkt, count=args.count, inter=args.interval, verbose=args.verbose)


def send_dns(args):
    s = _load_scapy()
    if not args.query:
        eprint("[x] --query NAME is required for the dns protocol.")
        sys.exit(1)
    port = args.port if args.port is not None else 53
    pkt = (s.IP(dst=args.target)
           / s.UDP(dport=port)
           / s.DNS(rd=1, qd=s.DNSQR(qname=args.query)))
    s.send(pkt, count=args.count, inter=args.interval, verbose=args.verbose)


def send_syn_flood(args):
    s = _load_scapy()
    if args.port is None:
        eprint("[x] --port is required for syn-flood.")
        sys.exit(1)
    # Random source PORT only (normal client behaviour); source IP is NOT
    # spoofed, so the traffic stays traceable to this host in the lab.
    pkt = (s.IP(dst=args.target)
           / s.TCP(sport=s.RandShort(), dport=args.port, flags="S"))
    s.send(pkt, count=args.count, inter=args.interval, verbose=args.verbose)


# --- Socket-based protocols (no root needed) --------------------------------
def _http_path(raw):
    """Normalise a URL path to always start with '/'."""
    path = raw or "/"
    if not path.startswith("/"):
        path = "/" + path
    return path


def _host_header(target, port):
    """Host header value, including the port when it is not the default 80."""
    return target if port == 80 else f"{target}:{port}"


def send_http(args):
    port = args.port if args.port is not None else 80
    path = _http_path(args.path)
    sent = 0
    for i in range(args.count):
        try:
            with socket.create_connection((args.target, port), timeout=5) as sock:
                request = (
                    f"GET {path} HTTP/1.1\r\n"
                    f"Host: {_host_header(args.target, port)}\r\n"
                    f"User-Agent: packet_generator-lab\r\n"
                    f"Connection: close\r\n\r\n"
                )
                sock.sendall(request.encode())
                data = sock.recv(256)
            sent += 1
            if args.verbose:
                first_line = data.split(b"\r\n", 1)[0].decode(errors="replace")
                print(f"[{i + 1}/{args.count}] {first_line}")
        except OSError as exc:
            eprint(f"[!] request {i + 1} failed: {exc}")
        if args.interval:
            time.sleep(args.interval)
    print(f"[*] Completed HTTP: {sent}/{args.count} request(s) sent.")


def send_http_dos(args):
    """Limited HTTP request flood for demonstrating application-layer load.

    This is deliberately single-threaded and capped; it is meant to show the
    concept, not to be an effective attack.
    """
    port = args.port if args.port is not None else 80
    path = _http_path(args.path)
    sent = 0
    start = time.time()
    for i in range(args.count):
        try:
            with socket.create_connection((args.target, port), timeout=5) as sock:
                request = (
                    f"GET {path} HTTP/1.1\r\n"
                    f"Host: {_host_header(args.target, port)}\r\n"
                    f"User-Agent: packet_generator-lab\r\n"
                    f"Connection: close\r\n\r\n"
                )
                sock.sendall(request.encode())
                sock.recv(64)
            sent += 1
        except OSError as exc:
            if args.verbose:
                eprint(f"[!] request {i + 1} failed: {exc}")
        if args.interval:
            time.sleep(args.interval)
    elapsed = max(time.time() - start, 1e-6)
    print(f"[*] Completed HTTP-DoS demo: {sent}/{args.count} request(s) "
          f"in {elapsed:.2f}s ({sent / elapsed:.1f} req/s).")


DISPATCH = {
    "arp": send_arp,
    "icmp": send_icmp,
    "udp": send_udp,
    "dns": send_dns,
    "http": send_http,
    "syn-flood": send_syn_flood,
    "http-dos": send_http_dos,
}


def build_parser():
    p = argparse.ArgumentParser(
        prog="packet_generator.py",
        description="Educational packet generator for classroom labs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--protocol", required=True, choices=sorted(DISPATCH.keys()),
                   help="Protocol / mode to generate.")
    p.add_argument("--target", required=True, type=validate_ip,
                   help="Target IP address.")
    p.add_argument("--port", type=int, default=None,
                   help="Target port (for udp/dns/http/syn-flood/http-dos).")
    p.add_argument("--count", type=int, default=1,
                   help="Number of packets/requests to send (default: 1).")
    p.add_argument("--interval", type=float, default=0.0,
                   help="Delay in seconds between packets (default: 0).")
    p.add_argument("--payload", default=None,
                   help="ASCII payload for icmp/udp.")
    p.add_argument("--query", default=None,
                   help="DNS name to query (for the dns protocol).")
    p.add_argument("--path", default="/",
                   help="URL path for http/http-dos (default: /).")
    p.add_argument("--iface", default=None,
                   help="Network interface to use (for arp).")
    p.add_argument("--yes", action="store_true",
                   help="Skip the confirmation prompt for aggressive modes.")
    p.add_argument("--verbose", action="store_true",
                   help="Verbose output.")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    print(BANNER)

    # Validate count against per-protocol caps.
    if args.count < 1:
        eprint("[x] --count must be at least 1.")
        return 1
    cap = MAX_COUNT[args.protocol]
    if args.count > cap:
        eprint(f"[x] --count {args.count} exceeds the cap for "
               f"'{args.protocol}' ({cap}). Lowering is required for this lab tool.")
        return 1
    if args.port is not None and not (0 < args.port < 65536):
        eprint("[x] --port must be between 1 and 65535.")
        return 1
    if args.interval < 0:
        eprint("[x] --interval must be zero or positive.")
        return 1

    # Protocol-specific required arguments (checked before the root check so
    # the user learns about a missing argument without needing sudo first).
    if args.protocol == "syn-flood" and args.port is None:
        eprint("[x] --port is required for syn-flood.")
        return 1
    if args.protocol == "dns" and not args.query:
        eprint("[x] --query NAME is required for the dns protocol.")
        return 1

    require_root(args.protocol)

    if args.protocol in AGGRESSIVE and not args.yes:
        confirm(args.protocol, args.target, args.port, args.count)

    print(f"[*] protocol={args.protocol} target={args.target} "
          f"port={args.port} count={args.count}")
    try:
        DISPATCH[args.protocol](args)
    except PermissionError:
        eprint("[x] Permission denied. Try running with sudo.")
        return 1
    except KeyboardInterrupt:
        eprint("\n[!] Interrupted by user.")
        return 130
    except OSError as exc:
        eprint(f"[x] Network error: {exc}")
        return 1
    print("[*] Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
