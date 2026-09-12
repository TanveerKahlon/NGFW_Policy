#!/usr/bin/env python3
"""Flatten the compiled corpus to one row per signature.

The .sigdb is a binary optimized for matching, and the register page shows one
application at a time. Neither lets you read the whole corpus at once, grep it,
diff two builds, or open it in a spreadsheet. This does: 41k rows, one rule each,
fully attributed.

    python3 tools/export_rules.py --db build/ngfw.sigdb --out build/signatures
        -> build/signatures.csv  and  build/signatures.jsonl

Pass --max-license permissive to export only the redistributable subset.
"""
from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HDR_FMT = "<8IQIIII"
LICN = ["permissive", "LGPL-3.0", "GPL-2.0"]
LIC_MAX = {"permissive": 0, "lgpl": 1, "gpl": 2}
TIER = ["A", "B", "C", "D"]

# What each tier actually means, carried into the export so a reader of the CSV
# alone is not left guessing.
TIER_MEANING = {
    "A": "payload bytes at flow start - identifies the protocol, survives ECH",
    "B": "vendor-owned name (SNI/Host/DNS) - identifies the application, lost to ECH",
    "C": "IP prefix - identifies the address owner, not the application",
    "D": "port or heuristic",
}


def load(db: Path):
    b = db.read_bytes()
    hs = struct.calcsize(HDR_FMT)
    (magic, ver, napp, ndom, pool_sz, aoff, doff, poff,
     built, ncidr, coff, npay, payoff) = struct.unpack(HDR_FMT, b[:hs])
    pool = b[poff:poff + pool_sz]

    def s(off: int) -> str:
        return pool[off:pool.index(b"\0", off)].decode("utf-8", "replace")

    apps = {}
    for i in range(napp):
        aid, noff, _cat, lic, _p = struct.unpack("<IIHBB", b[aoff + i * 12:aoff + i * 12 + 12])
        apps[aid] = (s(noff), lic)
    return b, apps, s, dict(ndom=ndom, doff=doff, ncidr=ncidr, coff=coff,
                            npay=npay, payoff=payoff, ver=ver)


def rows(db: Path, max_lic: int, sources: dict[str, list[str]]):
    b, apps, s, H = load(db)

    for i in range(H["ndom"]):
        noff, aid, mt, conf, tier, lic = struct.unpack(
            "<IIBBBB", b[H["doff"] + i * 12:H["doff"] + i * 12 + 12])
        if lic > max_lic or aid not in apps:
            continue
        name, _ = apps[aid]
        yield {
            "app": name, "rule_type": "name",
            "match": "exact" if mt else "suffix",
            "value": s(noff), "detail": "",
            "tier": TIER[tier], "confidence": conf,
            "license": LICN[lic], "sources": ";".join(sources.get(name, [])),
        }

    for i in range(H["ncidr"]):
        raw, aid, plen, af, tier, conf, lic, _ = struct.unpack(
            "<16sIBBBBB3s", b[H["coff"] + i * 28:H["coff"] + i * 28 + 28])
        if lic > max_lic or aid not in apps:
            continue
        name, _ = apps[aid]
        ip = ipaddress.IPv6Address(raw) if af == 6 else ipaddress.IPv4Address(raw[:4])
        yield {
            "app": name, "rule_type": "ip_prefix", "match": f"ipv{af}",
            "value": f"{ip}/{plen}", "detail": "",
            "tier": TIER[tier], "confidence": conf,
            "license": LICN[lic], "sources": ";".join(sources.get(name, [])),
        }

    for i in range(H["npay"]):
        val, msk, aid, tier, conf, lic, _ = struct.unpack(
            "<4s4sIBBBB", b[H["payoff"] + i * 16:H["payoff"] + i * 16 + 16])
        if lic > max_lic or aid not in apps:
            continue
        name, _ = apps[aid]
        ascii_gloss = "".join(chr(c) if 32 <= c < 127 else "." for c in val)
        wildcards = sum(1 for m in msk if m == 0)
        yield {
            "app": name, "rule_type": "payload", "match": "prefix4",
            "value": val.hex(),
            "detail": f'"{ascii_gloss}"' + (f" mask={msk.hex()}" if wildcards else ""),
            "tier": TIER[tier], "confidence": conf,
            "license": LICN[lic], "sources": ";".join(sources.get(name, [])),
        }


FIELDS = ["app", "rule_type", "match", "value", "detail",
          "tier", "confidence", "license", "sources"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="build/ngfw.sigdb")
    ap.add_argument("--out", default="build/signatures")
    ap.add_argument("--max-license", default="gpl", choices=sorted(LIC_MAX))
    args = ap.parse_args()

    inv = ROOT / "build" / "inventory.json"
    sources = {}
    if inv.exists():
        for a in json.loads(inv.read_text())["apps"]:
            sources[a["name"]] = a.get("sources", [])

    all_rows = list(rows(Path(args.db), LIC_MAX[args.max_license], sources))

    csv_path = Path(args.out).with_suffix(".csv")
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(all_rows)

    jsonl_path = Path(args.out).with_suffix(".jsonl")
    with jsonl_path.open("w", encoding="utf-8") as f:
        for r in all_rows:
            f.write(json.dumps(r, separators=(",", ":")) + "\n")

    by_type: dict[str, int] = {}
    by_tier: dict[str, int] = {}
    for r in all_rows:
        by_type[r["rule_type"]] = by_type.get(r["rule_type"], 0) + 1
        by_tier[r["tier"]] = by_tier.get(r["tier"], 0) + 1

    print(f"exported {len(all_rows):,} signatures "
          f"({len({r['app'] for r in all_rows}):,} applications), "
          f"max-license={args.max_license}")
    for k, v in sorted(by_type.items()):
        print(f"  {k:12} {v:>7,}")
    print("  by tier:", ", ".join(f"{k}={v:,}  ({TIER_MEANING[k].split(' - ')[0]})"
                                  for k, v in sorted(by_tier.items())))
    print(f"  -> {csv_path}  ({csv_path.stat().st_size/1e6:.2f} MB)")
    print(f"  -> {jsonl_path} ({jsonl_path.stat().st_size/1e6:.2f} MB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
