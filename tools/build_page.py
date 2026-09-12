#!/usr/bin/env python3
"""Build the Signature Register page from the compiled corpus.

    python3 tools/build_page.py            # -> build/signature-register.html

Source lives in page/register.template.html. That path matters: the template is
source, not output, and an earlier version of it sat under build/ where
`make clean` deleted it.

Two things this does that are easy to get wrong by hand:

* **Embeds the whole corpus.** Every rule, not a sample, so a reader can open one
  application and see all of its evidence.
* **Emits pure ASCII.** Non-ASCII bytes in the file render as mojibake wherever
  the page is served without a charset header. Markup gets numeric entities,
  script bodies get \\uXXXX escapes.
"""
from __future__ import annotations

import argparse
import collections
import ipaddress
import json
import re
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TEMPLATE = ROOT / "page" / "register.template.html"
HDR_FMT = "<8IQIIII"
LICN = ["permissive", "LGPL-3.0", "GPL-2.0"]


def read_corpus(db_path: Path, inventory: Path) -> dict:
    b = db_path.read_bytes()
    hs = struct.calcsize(HDR_FMT)
    (magic, ver, napp, ndom, pool_sz, aoff, doff, poff,
     _built, ncidr, coff, npay, payoff) = struct.unpack(HDR_FMT, b[:hs])
    pool = b[poff:poff + pool_sz]

    def s(off: int) -> str:
        return pool[off:pool.index(b"\0", off)].decode("utf-8", "replace")

    meta: dict[int, dict] = {}
    for i in range(napp):
        aid, noff, _cat, lic, _p = struct.unpack("<IIHBB", b[aoff + i * 12:aoff + i * 12 + 12])
        meta[aid] = {"n": s(noff), "l": lic, "D": [], "C": [], "P": [], "t": 9, "cf": 0}

    def bump(a, tier, conf):
        a["t"] = min(a["t"], tier)
        a["cf"] = max(a["cf"], conf)

    for i in range(ndom):
        noff, aid, mt, conf, tier, lic = struct.unpack(
            "<IIBBBB", b[doff + i * 12:doff + i * 12 + 12])
        a = meta.get(aid)
        if a:
            a["D"].append([s(noff), mt, conf, lic])
            bump(a, tier, conf)

    for i in range(ncidr):
        raw, aid, plen, af, tier, conf, lic, _ = struct.unpack(
            "<16sIBBBBB3s", b[coff + i * 28:coff + i * 28 + 28])
        a = meta.get(aid)
        if a:
            ip = ipaddress.IPv6Address(raw) if af == 6 else ipaddress.IPv4Address(raw[:4])
            a["C"].append([f"{ip}/{plen}", af, conf, lic])
            bump(a, tier, conf)

    for i in range(npay):
        val, msk, aid, tier, conf, lic, _ = struct.unpack(
            "<4s4sIBBBB", b[payoff + i * 16:payoff + i * 16 + 16])
        a = meta.get(aid)
        if a:
            a["P"].append([val.hex(), msk.hex(), conf, lic])
            bump(a, tier, conf)

    inv = {}
    curation = {}
    if inventory.exists():
        blob = json.loads(inventory.read_text())
        inv = {x["name"]: x.get("sources", []) for x in blob["apps"]}
        curation = blob.get("curation", {})

    apps = []
    for a in meta.values():
        a["D"].sort(key=lambda r: (len(r[0]), r[0]))
        a["C"].sort(key=lambda r: r[0])
        apps.append({"n": a["n"], "l": a["l"], "s": inv.get(a["n"], []),
                     "t": a["t"] if a["t"] < 9 else None, "cf": a["cf"],
                     "D": a["D"], "C": a["C"], "P": a["P"]})

    return {
        "apps": apps, "curation": curation, "lic": LICN,
        "totals": {
            "apps": len(apps), "domains": ndom, "cidrs": ncidr, "payloads": npay,
            "bySource": dict(collections.Counter(x for a in apps for x in a["s"])),
            "byLicense": dict(collections.Counter(a["l"] for a in apps)),
            "multiSource": sum(1 for a in apps if len(a["s"]) > 1),
            "noRules": sum(1 for a in apps if not (a["D"] or a["C"] or a["P"])),
        },
    }


def to_ascii(template: str) -> str:
    """Escape every non-ASCII character, respecting script vs markup context."""
    def esc_script(m):
        body = "".join(c if ord(c) < 128 else "\\u%04x" % ord(c) for c in m.group(2))
        return m.group(1) + body + m.group(3)

    # JSON script blocks are filled in later; leave them alone here.
    template = re.sub(r"(<script(?![^>]*application/json)[^>]*>)(.*?)(</script>)",
                      esc_script, template, flags=re.S)
    parts = []
    for part in re.split(r"(<script.*?</script>)", template, flags=re.S):
        if part.startswith("<script"):
            parts.append(part)
        else:
            parts.append("".join(c if ord(c) < 128 else "&#x%x;" % ord(c) for c in part))
    return "".join(parts)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="build/ngfw.sigdb")
    ap.add_argument("--inventory", default="build/inventory.json")
    ap.add_argument("--out", default="build/signature-register.html")
    args = ap.parse_args()

    if not TEMPLATE.exists():
        print(f"error: template missing at {TEMPLATE}", file=sys.stderr)
        return 1

    corpus = read_corpus(Path(args.db), Path(args.inventory))
    data = json.dumps(corpus, separators=(",", ":"))
    # A literal </script> inside the JSON would close the element early.
    data = data.replace("</", "<\\/")

    page = to_ascii(TEMPLATE.read_text(encoding="utf-8")).replace("__DATA__", data)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(page, encoding="utf-8")

    raw = out.read_bytes()
    bad = sum(1 for b in raw if b > 127)
    t = corpus["totals"]
    rules = t["domains"] + t["cidrs"] + t["payloads"]
    print(f"built {out}  {len(raw):,} bytes ({len(raw)/1e6:.2f} MB of 16 MB cap)")
    print(f"  {t['apps']:,} applications, {rules:,} rules embedded "
          f"({t['payloads']} payload / {t['domains']:,} name / {t['cidrs']:,} prefix)")
    if bad:
        print(f"  ERROR: {bad} non-ASCII bytes survived", file=sys.stderr)
        return 1
    print("  pure ASCII: yes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
