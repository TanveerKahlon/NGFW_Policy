#!/usr/bin/env python3
"""Emit a pcap of flows whose first payload bytes are known protocol magics.

Exercises the tier-A payload matcher, which no TLS-based fixture can reach.
"""
from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

MAGICS = [b"USER anonymous\r\n", b"QUIT\r\n", b"NXD-4.0\r\n", b"WORLD OF WARCRAFT"]


def checksum(b: bytes) -> int:
    if len(b) % 2:
        b += b"\0"
    t = sum((b[i] << 8) | b[i + 1] for i in range(0, len(b), 2))
    while t >> 16:
        t = (t & 0xFFFF) + (t >> 16)
    return (~t) & 0xFFFF


def packet(i: int, payload: bytes) -> bytes:
    tcp = struct.pack(">HHIIBBHHH", 40000 + i, 21, 1, 1, 5 << 4, 0x18, 65535, 0, 0) + payload
    ip = struct.pack(">BBHHHBBH", 0x45, 0, 20 + len(tcp), 0x1234, 0x4000, 64, 6, 0)
    ip += bytes([10, 0, 0, i + 1]) + bytes([93, 184, 216, 34])
    ip = ip[:10] + struct.pack(">H", checksum(ip)) + ip[12:]
    return b"\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x02\x08\x00" + ip + tcp


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, m in enumerate(MAGICS):
            d = packet(i, m)
            f.write(struct.pack("<IIII", 1700000000 + i, 0, len(d), len(d)))
            f.write(d)
    print(f"wrote {out}  ({len(MAGICS)} protocol-magic flows)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
