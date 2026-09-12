#!/usr/bin/env python3
"""Audit a compiled .sigdb for duplicate-class and over-broad-rule problems.

An app count is only meaningful if the identities behind it are distinct and the
rules behind them are specific. This reports the four ways that quietly breaks:

  1. near-duplicate ids  - one app counted twice under two spellings
  2. shared suffixes     - one domain claimed by several apps
  3. over-broad suffixes - short rules that will match things they should not
  4. curation coverage   - whether drops/aliases are actually being applied

Nothing is auto-merged. Findings become human-reviewed entries in
data/aliases.json (same service, two ids) or data/drops.json (not an
application), each with a reason. Auto-merging on name similarity is how
"Amazon", "Amazon Prime Video" and "Amazon Music" silently become one app.

Usage:  python3 tools/dup_audit.py [--db build/ngfw.sigdb] [--strict]
"""
from __future__ import annotations

import argparse
import itertools
import json
import re
import struct
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HDR_FMT = "<8IQIIII"

# A short suffix is not automatically wrong - aa.com really is American
# Airlines - but it is where false positives concentrate, so it gets reported.
BROAD_LEN = 6


def load(db_path: Path):
    b = db_path.read_bytes()
    hs = struct.calcsize(HDR_FMT)
    (magic, ver, napp, ndom, pool_sz, aoff, doff, poff,
     _built, ncidr, coff, npay, payoff) = struct.unpack(HDR_FMT, b[:hs])
    pool = b[poff:poff + pool_sz]

    def s(off: int) -> str:
        return pool[off:pool.index(b"\0", off)].decode("utf-8", "replace")

    names: dict[int, str] = {}
    lic: dict[int, int] = {}
    for i in range(napp):
        aid, noff, _cat, l, _p = struct.unpack("<IIHBB", b[aoff + i * 12:aoff + i * 12 + 12])
        names[aid] = s(noff)
        lic[aid] = l

    doms: dict[str, set[str]] = defaultdict(set)
    for i in range(ndom):
        noff, aid, _mt, _c, _t, _l = struct.unpack("<IIBBBB", b[doff + i * 12:doff + i * 12 + 12])
        doms[s(noff)].add(names.get(aid, "?"))

    return names, lic, doms, {"apps": napp, "domains": ndom,
                              "cidrs": ncidr, "payloads": npay}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="build/ngfw.sigdb")
    ap.add_argument("--strict", action="store_true",
                    help="exit non-zero if near-duplicate ids remain")
    args = ap.parse_args()

    names, lic, doms, counts = load(Path(args.db))
    print(f"database: {counts['apps']} apps, {counts['domains']:,} domain rules, "
          f"{counts['cidrs']:,} cidr, {counts['payloads']} payload")

    # --- 1. near-duplicate ids -------------------------------------------
    norm = defaultdict(set)
    for n in names.values():
        norm[re.sub(r"[^a-z0-9]", "", n.lower())].add(n)
    near = {k: v for k, v in norm.items() if len(v) > 1}
    print(f"\n1. near-duplicate ids: {len(near)} groups")
    for v in sorted(near.values())[:15]:
        print(f"     {sorted(v)}")
    if len(near) > 15:
        print(f"     ... and {len(near) - 15} more")

    # --- 2. suffixes claimed by more than one app ------------------------
    multi = {d: a for d, a in doms.items() if len(a) > 1}
    print(f"\n2. suffixes claimed by 2+ apps: {len(multi):,} of {len(doms):,}")
    pair = Counter()
    for apps in multi.values():
        for p in itertools.combinations(sorted(apps), 2):
            pair[p] += 1
    for (a, b), c in pair.most_common(10):
        print(f"     {c:>4} shared   {a}  <->  {b}")

    # --- 3. over-broad suffixes ------------------------------------------
    broad = sorted(d for d in doms if len(d) <= BROAD_LEN)
    print(f"\n3. suffixes <= {BROAD_LEN} chars: {len(broad)}")
    for d in broad[:12]:
        print(f"     {d!r:10} -> {sorted(doms[d])}")

    # --- 4. curation coverage --------------------------------------------
    ali_f, drop_f = ROOT / "data/aliases.json", ROOT / "data/drops.json"
    ali = json.loads(ali_f.read_text()) if ali_f.exists() else {}
    drp = json.loads(drop_f.read_text()) if drop_f.exists() else {}
    ali = {k: v for k, v in ali.items() if not k.startswith("_")}
    drp = {k: v for k, v in drp.items() if not k.startswith("_")}
    print(f"\n4. curation: {len(ali)} aliases, {len(drp)} drops")

    leaked = [k for k in drp if k in set(names.values())]
    stale_a = [k for k in ali if k in set(names.values())]
    if leaked:
        print(f"     FAIL dropped ids still present: {leaked}")
    if stale_a:
        print(f"     FAIL aliased ids still present: {stale_a}")
    if not leaked and not stale_a:
        print("     ok   every drop and alias is applied")

    bad = bool(leaked or stale_a) or (args.strict and near)
    print(f"\n{'FAIL' if bad else 'PASS'}: curation consistent"
          f"{'' if not near else f'; {len(near)} near-dup groups await review'}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
