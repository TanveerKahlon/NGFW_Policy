#!/usr/bin/env python3
"""Measure the real application count per source, and their union.

Claimed counts are marketing. This walks the vendored trees, extracts actual
application identities, normalizes them, and reports the overlap matrix — the
only defensible basis for a "we detect N applications" claim.

Usage:  python3 tools/measure_corpus.py [--json out.json]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TP = ROOT / "third_party"

# Acronyms and vendor shorthands that must collapse before comparison, or the
# same app is counted twice under two spellings.
ACRONYMS = {
    "ms": "microsoft", "msn": "microsoft", "aws": "amazon", "gcp": "google",
    "gdrive": "googledrive", "yt": "youtube", "fb": "facebook", "ig": "instagram",
    "ms365": "microsoft365", "o365": "microsoft365", "office365": "microsoft365",
}
# Tokens that carry no identity and only cause false differences.
STOPWORDS = {"protocol", "proto", "app", "application", "service", "services",
             "client", "server", "com", "net", "org", "inc", "the"}


def normalize(name: str) -> str:
    """Reduce a display name to a comparable identity key."""
    s = name.strip().lower()
    s = re.sub(r"^ndpi_protocol_", "", s)
    s = re.sub(r"[^a-z0-9]+", " ", s)
    parts = [p for p in s.split() if p and p not in STOPWORDS]
    parts = [ACRONYMS.get(p, p) for p in parts]
    return "".join(parts)


# --------------------------------------------------------------- extractors

def extract_ndpi() -> tuple[set[str], dict]:
    """nDPI protocol IDs, split into protocol-like vs application-like."""
    f = TP / "ndpi/src/include/ndpi_protocol_ids.h"
    if not f.exists():
        return set(), {"error": "not vendored"}

    ids = re.findall(r"NDPI_PROTOCOL_([A-Z0-9_]+)\s*=\s*(\d+)", f.read_text(errors="ignore"))
    names = {n for n, _ in ids
             if not n.startswith(("FREE_", "UNKNOWN", "MAX_SUPPORTED", "NUM_"))}

    # Transport/infrastructure protocols are not "applications" for counting.
    PROTOCOLISH = {
        "TLS", "HTTP", "DNS", "QUIC", "TCP", "UDP", "ICMP", "ICMPV6", "IP_", "SSH",
        "FTP_CONTROL", "FTP_DATA", "SMTP", "IMAP", "POP3", "NTP", "DHCP", "DHCPV6",
        "SNMP", "BGP", "OSPF", "VRRP", "IGMP", "SCTP", "GRE", "IPSEC", "L2TP",
        "PPTP", "RTP", "RTCP", "RTSP", "SIP", "STUN", "MDNS", "LLMNR", "NETBIOS",
        "SMBV1", "SMBV23", "NFS", "LDAP", "KERBEROS", "RADIUS", "SYSLOG", "TFTP",
        "TELNET", "MODBUS", "DNP3", "S7COMM", "MQTT", "COAP", "AMQP", "TOR",
    }
    apps = {n for n in names if n not in PROTOCOLISH}
    return {normalize(n) for n in apps}, {
        "protocol_ids_total": len(ids),
        "named": len(names),
        "protocol_like": len(names & PROTOCOLISH),
        "app_like": len(apps),
        "dissector_files": len(list((TP / "ndpi/src/lib/protocols").glob("*.c")))
                           if (TP / "ndpi/src/lib/protocols").exists() else 0,
    }


def extract_openappid() -> tuple[set[str], dict]:
    """ODP detectable apps.

    Counting `detection_name` alone UNDERSTATES this corpus badly: most apps have
    no dedicated Lua file, they appear as appId rows inside shared
    ssl_host_group / url pattern tables. An app with a host pattern is genuinely
    detectable whether or not it has its own detector file, so both are counted.
    """
    base = TP / "openappid-odp"
    if not base.exists():
        return set(), {"error": "not vendored"}

    # appId -> display name
    names: dict[int, str] = {}
    mf = base / "appMapping.data"
    if mf.exists():
        for line in mf.read_text(errors="ignore").splitlines():
            cols = line.split("\t")
            if len(cols) >= 2 and cols[0].strip().isdigit():
                names[int(cols[0])] = cols[1].strip()

    ssl_re = re.compile(r"\{\s*\d+\s*,\s*(\d+)\s*,\s*['\"][^'\"]+['\"]\s*\}")
    url_re = re.compile(
        r'\{\s*\d+\s*,\s*\d+\s*,\s*\d+\s*,\s*\d+\s*,\s*\d+\s*,'
        r'\s*"[^"]+"\s*,\s*"[^"]*"\s*,\s*"[^"]*"\s*,\s*"[^"]*"\s*,\s*(\d+)\s*\}')

    detectors = set()
    pattern_backed = set()
    for lua in (base / "lua").glob("*.lua"):
        text = lua.read_text(errors="ignore")
        m = re.search(r"^detection_name:\s*(.+)$", text, re.M)
        if m:
            detectors.add(m.group(1).strip())
        for rx in (ssl_re, url_re):
            for hit in rx.finditer(text):
                nm = names.get(int(hit.group(1)))
                if nm:
                    pattern_backed.add(nm)

    lua_named = len(detectors)          # capture BEFORE the union
    detectors |= pattern_backed

    mapping = base / "appMapping.data"
    rows = flagged = 0
    registry = set()
    if mapping.exists():
        for line in mapping.read_text(errors="ignore").splitlines():
            cols = line.split("\t")
            if len(cols) < 6:
                continue
            rows += 1
            registry.add(cols[1].strip())
            if any(c.strip() not in ("0", "") for c in cols[2:5]):
                flagged += 1

    return {normalize(d) for d in detectors}, {
        "lua_files": len(list((base / "lua").glob("*.lua"))),
        "named_lua_detectors": lua_named,
        "host_pattern_backed": len(pattern_backed),
        "detectable_total": len(detectors),
        "appmapping_rows": rows,
        "appmapping_flagged": flagged,
        "registry_names": len(registry),
        "claimed": 2600,
    }


def extract_netify() -> tuple[set[str], dict]:
    """Netify's Apache-2.0 app list — the only cleanly shippable corpus."""
    cands = [TP / "netify-agent/deploy/netify-apps.conf",
             TP / "netify-agent/netify-apps.conf"]
    f = next((c for c in cands if c.exists()), None)
    if f is None:
        found = list((TP / "netify-agent").rglob("netify-apps.conf")) if (TP / "netify-agent").exists() else []
        f = found[0] if found else None
    if f is None:
        return set(), {"error": "netify-apps.conf not found"}

    apps, counts = set(), defaultdict(int)
    for line in f.read_text(errors="ignore").splitlines():
        if line.startswith("#") or not line.strip():
            continue
        kind = line.split(":", 1)[0]
        counts[kind] += 1
        if kind == "app":
            parts = line.split(":", 2)
            if len(parts) == 3:
                apps.add(parts[2].replace("netify.", "").strip())

    return {normalize(a) for a in apps}, {
        "apps": len(apps),
        "rules_domain": counts.get("dom", 0),
        "rules_cidr": counts.get("net", 0),
        "rules_expr": counts.get("nsd", 0),
        "rules_total": sum(v for k, v in counts.items() if k != "app"),
        "license": "Apache-2.0",
    }


def extract_mmt_dpi() -> tuple[set[str], dict]:
    f = TP / "mmt-dpi/src/mmt_tcpip/include/mmt_tcpip_protocols.h"
    if not f.exists():
        return set(), {"error": "not vendored"}
    protos = re.findall(r"#define\s+PROTO_([A-Z0-9_]+)\s+\d+", f.read_text(errors="ignore"))
    return {normalize(p) for p in protos}, {"protocol_defines": len(protos)}


def extract_libprotoident() -> tuple[set[str], dict]:
    """One lpi_<proto>.cc module per protocol, split across lib/tcp and lib/udp."""
    base = TP / "libprotoident/lib"
    if not base.exists():
        return set(), {"error": "not vendored"}

    per_dir = {}
    names: set[str] = set()
    for sub in ("tcp", "udp"):
        files = list((base / sub).glob("lpi_*.cc"))
        per_dir[f"modules_{sub}"] = len(files)
        names |= {f.stem[len("lpi_"):] for f in files}

    # tcp/ and udp/ both carry e.g. lpi_dns.cc — one protocol, two transports.
    return {normalize(n) for n in names}, {
        **per_dir,
        "modules_total": sum(per_dir.values()),
        "distinct_after_transport_merge": len(names),
    }


def extract_odp_taxonomy() -> tuple[set[str], dict]:
    """ODP's appMapping.data as a NAME TAXONOMY, not detectors.

    These 3.3k names have IDs allocated but mostly no detector behind them.
    They are worthless as signatures and valuable as a *derivation target list*:
    known application identities we can build our own signatures for.
    Counted separately from detector-backed apps — never added to that total.
    """
    f = TP / "openappid-odp/appMapping.data"
    if not f.exists():
        return set(), {"error": "not vendored"}

    names, flagged = set(), set()
    for line in f.read_text(errors="ignore").splitlines():
        cols = line.split("\t")
        if len(cols) < 6:
            continue
        nm = cols[1].strip()
        names.add(nm)
        if any(c.strip() not in ("0", "") for c in cols[2:5]):
            flagged.add(nm)

    return {normalize(n) for n in flagged}, {
        "registry_names": len(names),
        "flagged_names": len(flagged),
        "note": "taxonomy only - no detector; derivation targets",
    }


def count_rules() -> dict:
    """Signature-rule volume, which is a different question from app count."""
    out = {}
    inc = TP / "ndpi/src/lib/inc_generated"
    if inc.exists():
        n = 0
        for f in inc.glob("*.c.inc"):
            n += sum(1 for ln in f.read_text(errors="ignore").splitlines()
                     if ln.lstrip().startswith("{"))
        out["ndpi_inc_generated_entries"] = n
    cm = TP / "ndpi/src/lib/ndpi_content_match.c.inc"
    if cm.exists():
        out["ndpi_content_match_entries"] = sum(
            1 for ln in cm.read_text(errors="ignore").splitlines()
            if ln.lstrip().startswith('{ "'))
    nf = list((TP / "netify-agent").rglob("netify-apps.conf")) if (TP / "netify-agent").exists() else []
    if nf:
        out["netify_rules"] = sum(
            1 for ln in nf[0].read_text(errors="ignore").splitlines()
            if ln[:4] in ("dom:", "net:", "nsd:"))
    out["total"] = sum(v for v in out.values())
    return out


# Detector-backed sources: an identity here has real matching logic behind it.
SOURCES = {
    "ndpi": (extract_ndpi, "LGPL-3.0"),
    "openappid": (extract_openappid, "GPL-2.0"),
    "netify": (extract_netify, "Apache-2.0"),
    "mmt-dpi": (extract_mmt_dpi, "Apache-2.0"),
    "libprotoident": (extract_libprotoident, "LGPL-3.0"),
}

# Name-only taxonomies: identities with no signature. Reported, never summed in.
TAXONOMIES = {
    "openappid-registry": (extract_odp_taxonomy, "GPL-2.0"),
}

PERMISSIVE = {"Apache-2.0", "MIT", "BSD-3-Clause", "BSD-2-Clause", "Unlicense"}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", help="write the full report here")
    args = ap.parse_args()

    sets: dict[str, set[str]] = {}
    stats: dict[str, dict] = {}
    licenses: dict[str, str] = {}

    print("=" * 74)
    print("MEASURED APPLICATION COUNTS  (claimed numbers are not used anywhere)")
    print("=" * 74)

    for name, (fn, lic) in SOURCES.items():
        s, meta = fn()
        sets[name], stats[name], licenses[name] = s, meta, lic
        if "error" in meta:
            print(f"\n{name:16} SKIPPED — {meta['error']}")
            continue
        print(f"\n{name:16} {lic:12} distinct app identities: {len(s)}")
        for k, v in meta.items():
            print(f"{'':16}   {k:24} {v}")

    live = {k: v for k, v in sets.items() if v}
    union = set().union(*live.values()) if live else set()
    perm_union = set().union(*[v for k, v in live.items() if licenses[k] in PERMISSIVE]) or set()

    print("\n" + "=" * 74)
    print("OVERLAP MATRIX (shared identities)")
    print("=" * 74)
    names = sorted(live)
    print(f"{'':16}" + "".join(f"{n[:12]:>14}" for n in names))
    for a in names:
        row = "".join(f"{len(live[a] & live[b]):>14}" for b in names)
        print(f"{a:16}{row}")

    print("\n" + "=" * 74)
    print("UNIQUE CONTRIBUTION (identities found in no other source)")
    print("=" * 74)
    for a in names:
        others = set().union(*[live[b] for b in names if b != a]) if len(names) > 1 else set()
        uniq = live[a] - others
        print(f"  {a:16} {len(uniq):>5} unique   of {len(live[a]):>5}")

    # Taxonomies: names without signatures. Reported apart, never summed in.
    tax_sets: dict[str, set[str]] = {}
    for name, (fn, lic) in TAXONOMIES.items():
        s, meta = fn()
        if "error" in meta:
            continue
        tax_sets[name] = s
        licenses[name] = lic
        stats[name] = meta

    tax_union = set().union(*tax_sets.values()) if tax_sets else set()
    tax_new = tax_union - union

    rules = count_rules()

    print("\n" + "=" * 74)
    print("RULE VOLUME (a different question from app count)")
    print("=" * 74)
    for k, v in rules.items():
        print(f"  {k:34} {v:>8,}")

    print("\n" + "=" * 74)
    print("THE NUMBER")
    print("=" * 74)
    print("  TIER 1 — detector-backed (real matching logic exists)")
    print(f"    union, all sources          : {len(union):>5}")
    print(f"    union, permissive-only      : {len(perm_union):>5}   <- SHIPPABLE")
    print("\n  TIER 2 — name taxonomy (identity known, NO signature)")
    print(f"    ODP registry, flagged       : {len(tax_union):>5}")
    print(f"    of which new vs Tier 1      : {len(tax_new):>5}   <- derivation targets")
    print("\n  CEILING IF EVERY TAXONOMY NAME WERE GIVEN A SIGNATURE")
    print(f"    all sources                 : {len(union | tax_union):>5}")
    print(f"    target                      :  3000")
    print(f"    remaining gap               : {max(0, 3000 - len(union | tax_union)):>5}")
    print("\n  Honest reading: we have signatures for", len(union), "apps today")
    print(f"  ({len(perm_union)} shippable). The ODP taxonomy names {len(tax_new)} more")
    print("  identities we could derive signatures for ourselves via CT logs")
    print("  and public feeds — which is also the only license-clean route.")

    if args.json:
        Path(args.json).write_text(json.dumps({
            "stats": stats,
            "licenses": licenses,
            "counts": {k: len(v) for k, v in sets.items()},
            "union_all": len(union),
            "union_permissive": len(perm_union),
            "target": 3000,
        }, indent=2))
        print(f"\nreport -> {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
