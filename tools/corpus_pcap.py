#!/usr/bin/env python3
"""Emit a pcap containing one ClientHello per domain in a compiled .sigdb.

Round-tripping the corpus through the engine is the cheapest high-signal check
available: any mismatch means the compiler and the matcher disagree about what
a rule means, which no amount of real traffic would reveal as clearly.
"""
from __future__ import annotations

import argparse
import struct
import subprocess
import sys
from pathlib import Path

HDR_FMT = "<8IQ16s"


def domains_of(db_path: Path) -> list[str]:
    blob = db_path.read_bytes()
    hs = struct.calcsize(HDR_FMT)
    _, _, _, ndom, pool_sz, _, doff, poff, _, _ = struct.unpack(HDR_FMT, blob[:hs])
    pool = blob[poff:poff + pool_sz]

    def s(off: int) -> str:
        return pool[off:pool.index(b"\0", off)].decode("utf-8", "replace")

    out = set()
    for i in range(ndom):
        rec = blob[doff + i * 12: doff + i * 12 + 12]
        out.add(s(struct.unpack("<IIBBBB", rec)[0]))
    return sorted(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    doms = domains_of(Path(args.db))
    tmp = Path(args.out).with_suffix(".hosts.txt")
    tmp.parent.mkdir(parents=True, exist_ok=True)
    tmp.write_text("\n".join(doms))

    subprocess.run([sys.executable, str(Path(__file__).parent / "mkpcap.py"),
                    "--out", args.out, "--hosts-file", str(tmp)], check=True)
    print(f"  corpus round-trip pcap: {len(doms)} domains")
    return 0


if __name__ == "__main__":
    sys.exit(main())
