#!/usr/bin/env python3
"""Count Modbus function codes per source address across the three Week 5 captures.

The script takes the three capture paths as arguments (F, G, H) and prints, for each
file, the number of frames per source IP address and function code, sorted by count
descending, then by source address and function code.

The counting filter matches the tshark one used in the lab Part:
    modbus && tcp.dstport == 502
so the numbers here are the numbers the tshark check prints.

Usage:
    python3 function_codes.py "$F" "$G" "$H"

No network access, no writes: it reads the capture files and prints to stdout.
"""
import subprocess
import sys


def counts(path):
    """Return a list of (count, source, func_code) for one capture file."""
    cmd = [
        "tshark", "-r", path,
        "-Y", "modbus && tcp.dstport == 502",
        "-T", "fields",
        "-e", "ip.src",
        "-e", "modbus.func_code",
    ]
    out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    tally = {}
    for line in out.splitlines():
        if not line.strip():
            continue
        src, _, fc = line.partition("\t")
        if not src:
            continue
        key = (src, fc)
        tally[key] = tally.get(key, 0) + 1
    rows = [(n, src, fc) for (src, fc), n in tally.items()]
    rows.sort(key=lambda r: (-r[0], r[1], int(r[2]) if r[2].isdigit() else 0))
    return rows


def main():
    if len(sys.argv) != 4:
        print(__doc__)
        return 1
    labels = ["F", "G", "H"]
    for label, path in zip(labels, sys.argv[1:]):
        print(f"=== {label} {path}")
        rows = counts(path)
        total = sum(n for n, _, _ in rows)
        for n, src, fc in rows:
            print(f"{n:6d} {src}\t{fc}")
        print(f"{total:6d} total frames counted in {label}")
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
