#!/usr/bin/env python3
"""
mini_kdd.py
CPSC 50600 Week 6: build KDD Cup 99 style connection records from a packet capture.

Usage:
    tshark -r slice.pcap -T fields -E separator=, -E occurrence=f \
        -e frame.time_epoch -e ip.src -e ip.dst -e ip.proto \
        -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport \
        -e tcp.flags -e tcp.len -e udp.length -e icmp.type \
        > packets.csv
    python3 mini_kdd.py packets.csv > records.csv

Output columns (a subset of the 41 KDD Cup 99 features):
    start_time, duration, protocol_type, service, flag,
    src_bytes, dst_bytes, land, count, serror_rate, src, dst

Standard library only. Python 3.6 or newer. About 150 lines, so read it:
the point of this lab is that you can see exactly how packets
become connection records, including the 2 second window.
"""

import sys
import csv

# Destination port to KDD service name (the common ones in the DARPA data).
SERVICES_TCP = {
    20: "ftp_data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "domain", 79: "finger", 80: "http", 110: "pop_3", 113: "auth",
    143: "imap4", 513: "login", 514: "shell",
}
SERVICES_UDP = {53: "domain_u", 514: "syslog_u"}
ICMP_TYPES = {0: "ecr_i", 8: "eco_i", 3: "urp_i", 11: "tim_i"}

CONN_TIMEOUT = 60.0   # seconds of silence that ends a UDP/ICMP "connection"
WINDOW = 2.0          # the KDD time based traffic window


def service_name(proto, dport, icmp_type):
    if proto == "icmp":
        return ICMP_TYPES.get(icmp_type, "oth_i")
    if proto == "udp":
        return SERVICES_UDP.get(dport, "other_u")
    if dport in SERVICES_TCP:
        return SERVICES_TCP[dport]
    return "private" if (dport is not None and dport >= 1024) else "other"


class Conn:
    """One connection: originator is whoever sent the first packet
    (for TCP, that is the SYN sender)."""

    def __init__(self, ts, src, dst, sport, dport, proto, icmp_type):
        self.start = ts
        self.end = ts
        self.src, self.dst = src, dst
        self.sport, self.dport = sport, dport
        self.proto = proto
        self.icmp_type = icmp_type
        self.src_bytes = 0
        self.dst_bytes = 0
        # TCP state bits
        self.syn = False        # originator sent SYN
        self.synack = False     # responder answered SYN,ACK
        self.rst_resp = False   # responder sent RST
        self.rst_orig = False   # originator sent RST
        self.fin_orig = False
        self.fin_resp = False

    def add(self, ts, from_orig, flags, payload):
        self.end = max(self.end, ts)
        if from_orig:
            self.src_bytes += payload
        else:
            self.dst_bytes += payload
        if self.proto != "tcp" or flags is None:
            return
        syn, ack = bool(flags & 0x02), bool(flags & 0x10)
        rst, fin = bool(flags & 0x04), bool(flags & 0x01)
        if from_orig:
            if syn and not ack:
                self.syn = True
            if rst:
                self.rst_orig = True
            if fin:
                self.fin_orig = True
        else:
            if syn and ack:
                self.synack = True
            if rst:
                self.rst_resp = True
            if fin:
                self.fin_resp = True

    def flag(self):
        """A teaching subset of the KDD flag values."""
        if self.proto != "tcp":
            return "SF"
        if self.syn and self.rst_resp and not self.synack:
            return "REJ"            # connection attempt rejected
        if self.syn and not self.synack:
            return "S0"             # SYN seen, no reply: the neptune signature
        if self.synack and (self.fin_orig or self.fin_resp):
            return "SF"             # opened and closed normally
        if self.synack and (self.rst_orig or self.rst_resp):
            return "RST"            # established, then torn down by reset
        if self.synack:
            return "S1"             # established, never closed in this slice
        return "OTH"                # we never saw the start


def parse_packets(path):
    """Yield (ts, src, dst, proto, sport, dport, flags, payload, icmp_type)."""
    with open(path, newline="") as f:
        for row in csv.reader(f):
            if len(row) < 12 or not row[0] or not row[1]:
                continue  # not an IPv4 packet tshark could flatten
            ts = float(row[0])
            src, dst = row[1], row[2]
            proto_num = row[3]
            if row[4] and row[5]:
                proto, sport, dport = "tcp", int(row[4]), int(row[5])
            elif row[6] and row[7]:
                proto, sport, dport = "udp", int(row[6]), int(row[7])
            elif proto_num == "1":
                proto, sport, dport = "icmp", 0, 0
            else:
                continue
            flags = int(row[8], 16) if row[8] else None
            if proto == "tcp":
                payload = int(row[9]) if row[9] else 0
            elif proto == "udp":
                payload = max(0, int(row[10]) - 8) if row[10] else 0
            else:
                payload = 0
            icmp_type = int(row[11]) if row[11] else None
            yield ts, src, dst, proto, sport, dport, flags, payload, icmp_type


def build_connections(packets):
    open_conns = {}   # key: frozenset of the two endpoints + proto
    done = []
    for ts, src, dst, proto, sport, dport, flags, payload, icmp_type in packets:
        key = (proto, frozenset([(src, sport), (dst, dport)]))
        conn = open_conns.get(key)
        # a long silence, or a brand new SYN, starts a new connection
        is_new_syn = (proto == "tcp" and flags is not None
                      and (flags & 0x02) and not (flags & 0x10))
        if conn is not None and (ts - conn.end > CONN_TIMEOUT
                                 or (is_new_syn and src == conn.src and conn.syn
                                     and (conn.fin_orig or conn.rst_orig
                                          or conn.rst_resp))):
            done.append(conn)
            conn = None
        if conn is None:
            conn = Conn(ts, src, dst, sport, dport, proto, icmp_type)
            open_conns[key] = conn
        conn.add(ts, from_orig=(src == conn.src), flags=flags, payload=payload)
    done.extend(open_conns.values())
    done.sort(key=lambda c: c.start)
    return done


def add_window_features(conns):
    """count and serror_rate over the past WINDOW seconds, per KDD:
    connections to the same destination host as the current one.

    A sliding left edge keeps this linear in the number of connections
    instead of rescanning all earlier connections for every row, which
    matters because a flood produces hundreds of thousands of them."""
    flags = [c.flag() for c in conns]   # compute each flag once
    out = []
    start = 0                           # left edge of the 2 second window
    for i, c in enumerate(conns):
        # Move the left edge forward until it is within WINDOW seconds of c.
        while c.start - conns[start].start > WINDOW:
            start += 1
        count = 0
        serrors = 0
        for j in range(start, i + 1):
            if conns[j].dst == c.dst:
                count += 1
                fj = flags[j]
                if fj.startswith("S") and fj != "SF":
                    serrors += 1
        out.append((c, count, serrors / count if count else 0.0))
    return out


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    conns = build_connections(parse_packets(sys.argv[1]))
    rows = add_window_features(conns)
    w = csv.writer(sys.stdout)
    w.writerow(["start_time", "duration", "protocol_type", "service", "flag",
                "src_bytes", "dst_bytes", "land", "count", "serror_rate",
                "src", "dst"])
    for c, count, serror in rows:
        w.writerow([f"{c.start:.2f}", f"{c.end - c.start:.2f}", c.proto,
                    service_name(c.proto, c.dport, c.icmp_type), c.flag(),
                    c.src_bytes, c.dst_bytes,
                    1 if (c.src == c.dst and c.sport == c.dport) else 0,
                    count, f"{serror:.2f}", c.src, c.dst])


if __name__ == "__main__":
    main()
