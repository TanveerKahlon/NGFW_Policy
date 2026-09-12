#!/usr/bin/env python3
"""Synthesize a pcap of TLS ClientHellos for engine testing.

Real captures of 3000 applications do not exist and cannot be collected
cheaply. Synthesized flows validate the *matching path* exhaustively — decode,
flow tracking, ClientHello parsing, trie lookup — which is a different and more
tractable question than validating that a signature is correct.

Includes deliberate negatives (notnetflix.com, netflix.com.evil.tld) so a
regression in label-boundary handling shows up as a false positive here.
"""
from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

LINKTYPE_ETHERNET = 1


def ip_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def client_hello(hostname: str) -> bytes:
    """A minimal but structurally valid TLS 1.2 ClientHello carrying SNI."""
    host = hostname.encode()

    sni_entry = b"\x00" + struct.pack(">H", len(host)) + host   # type 0 + name
    sni_list = struct.pack(">H", len(sni_entry)) + sni_entry
    sni_ext = struct.pack(">HH", 0x0000, len(sni_list)) + sni_list

    # A second extension, so the parser must actually walk the list.
    alpn_body = b"\x00\x0c\x02h2\x08http/1.1"
    alpn_ext = struct.pack(">HH", 0x0010, len(alpn_body)) + alpn_body

    exts = sni_ext + alpn_ext
    body = (
        b"\x03\x03"                        # client_version TLS 1.2
        + bytes(range(32))                 # random
        + b"\x00"                          # session_id length
        + struct.pack(">H", 2) + b"\x13\x01"   # cipher suites
        + b"\x01\x00"                      # compression methods
        + struct.pack(">H", len(exts)) + exts
    )
    hs = b"\x01" + struct.pack(">I", len(body))[1:] + body      # 24-bit length
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


def tcp_packet(src_ip: str, dst_ip: str, sport: int, dport: int,
               seq: int, payload: bytes) -> bytes:
    tcp = struct.pack(
        ">HHIIBBHHH",
        sport, dport, seq, 1,
        (5 << 4), 0x18,        # data offset 5 words; PSH|ACK
        65535, 0, 0,
    ) + payload

    total_len = 20 + len(tcp)
    src = bytes(int(x) for x in src_ip.split("."))
    dst = bytes(int(x) for x in dst_ip.split("."))

    ip_no_ck = struct.pack(">BBHHHBBH", 0x45, 0, total_len, 0x1234, 0x4000,
                           64, 6, 0) + src + dst
    ck = ip_checksum(ip_no_ck)
    ip = ip_no_ck[:10] + struct.pack(">H", ck) + ip_no_ck[12:]

    eth = b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02" + b"\x08\x00"
    return eth + ip + tcp


# (hostname, should_match) — the False cases must never produce a verdict.
DEFAULT_HOSTS = [
    ("www.netflix.com", True),
    ("api.netflix.com", True),
    ("www.google.com", True),
    ("drive.google.com", True),
    ("mail.google.com", True),
    ("www.youtube.com", True),
    ("api.twitter.com", True),
    ("www.facebook.com", True),
    ("cdn.discordapp.com", True),
    ("api.spotify.com", True),
    ("teams.microsoft.com", True),
    ("zoom.us", True),
    ("github.com", True),
    ("www.dropbox.com", True),
    ("api.telegram.org", True),
    # Negatives: label-boundary traps and genuinely unknown hosts.
    ("notnetflix.com", False),
    ("netflix.com.evil.tld", False),
    ("xn--totally-not-real.invalid", False),
    ("some-random-host.example", False),
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--hosts-file", help="one hostname per line, overrides defaults")
    ap.add_argument("--dst", default="93.184.216.34",
                    help="default destination IP (per-host override: host@ip)")
    args = ap.parse_args()

    if args.hosts_file:
        hosts = [(h.strip(), True)
                 for h in Path(args.hosts_file).read_text().splitlines()
                 if h.strip() and not h.startswith("#")]
    else:
        hosts = DEFAULT_HOSTS

    # "host@dstip" pins a destination address so the IP tier can be exercised;
    # an empty host emits a flow with no ClientHello at all.
    entries = []
    for host, expect in hosts:
        dst = args.dst
        if "@" in host:
            host, dst = host.split("@", 1)
        entries.append((host, dst, expect))

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)

    with out.open("wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535,
                            LINKTYPE_ETHERNET))
        for i, (host, dst, _expect) in enumerate(entries):
            src = f"10.0.{i // 250}.{i % 250 + 1}"
            payload = client_hello(host) if host else b""
            pkt = tcp_packet(src, dst, 40000 + i, 443, 1000, payload)
            f.write(struct.pack("<IIII", 1700000000 + i, 0, len(pkt), len(pkt)))
            f.write(pkt)

    expected = sum(1 for _, e in hosts if e)
    print(f"wrote {out}  ({len(hosts)} ClientHellos, "
          f"{expected} expected to match, {len(hosts) - expected} negatives)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
