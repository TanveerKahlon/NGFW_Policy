#!/usr/bin/env python3
"""sigc — compile vendored corpora into a .sigdb binary.

Source of truth stays in the vendored trees; this produces the mmap-able blob
the engine loads. Every rule carries its source's license tier, so a build can
be filtered to what it may actually ship:

    python3 tools/sigc.py --out build/ngfw.sigdb
    python3 tools/sigc.py --out build/permissive.sigdb --max-license permissive
"""
from __future__ import annotations

import argparse
import ipaddress
import re
import struct
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TP = ROOT / "third_party"

MAGIC = 0x4457474E
VERSION = 3

LIC_PERMISSIVE, LIC_LGPL, LIC_GPL = 0, 1, 2
LIC_NAMES = {"permissive": LIC_PERMISSIVE, "lgpl": LIC_LGPL, "gpl": LIC_GPL}

TIER_A, TIER_B, TIER_C, TIER_D = 0, 1, 2, 3
DOM_SUFFIX, DOM_EXACT = 0, 1

HDR_FMT = "<8IQIIII"        # 56 bytes, matches ngfw_sigdb_header_t (v3)
APP_FMT = "<IIHBB"           # 12 bytes
DOM_FMT = "<IIBBBB"          # 12 bytes
CIDR_FMT = "<16sIBBBBB3s"    # 28 bytes
PAY_FMT  = "<4s4sIBBBB"      # 16 bytes


def _slug(name: str) -> str:
    """The single identity normalizer every source must pass through.

    Sources disagree on separators - nDPI emits AMAZON_VIDEO, Netify
    amazon_video, OpenAppID "Amazon Video" - and left alone that produced 54
    near-duplicate groups where one real app was counted two or three times.
    Collapsing every non-alphanumeric run to a single hyphen merges them.
    """
    out = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return out or "unknown"


def _load_curation() -> tuple[dict[str, str], dict[str, dict]]:
    """Human-reviewed identity decisions. Never inferred, never auto-extended."""
    import json
    ali, drp = {}, {}
    f = ROOT / "data" / "aliases.json"
    if f.exists():
        ali = {k: v for k, v in json.loads(f.read_text()).items()
               if not k.startswith("_")}
    f = ROOT / "data" / "drops.json"
    if f.exists():
        drp = {k: v for k, v in json.loads(f.read_text()).items()
               if not k.startswith("_")}
    return ali, drp


# Byte prefixes belonging to a framing the engine dissects natively. A corpus
# rule that pins one is a truncation artifact, not a signature: MMT-DPI's
# gnutella detector really compares thirteen bytes of one specific ClientHello,
# and the first four of those are just "a TLS record" - shared with every HTTPS
# flow on the internet. Truncated to the matcher's four-byte width it stops
# meaning "gnutella" and starts meaning "TLS".
#
# Per-source uniqueness cannot catch this: within MMT-DPI gnutella really is the
# only claimant. The guard lives in Builder.payload() rather than in a loader so
# no extractor can route around it, and grows an entry whenever the engine gains
# a dissector that owns a framing outright.
_RESERVED_FRAMINGS = (
    # TLS/SSL record header: content types change_cipher_spec/alert/handshake/
    # application_data, followed by the major version. src/engine/tls.c parses
    # these itself and is authoritative there.
    ((0x14, 0x15, 0x16, 0x17), (0x03,)),
)


def _pins_reserved_framing(value: bytes, mask: bytes) -> bool:
    """True if the pattern explicitly pins the header of a reserved framing.

    Only pinned bytes count. `16 03 01 00` and `16 03 ?? ??` both pin a TLS
    record header and are refused; `?? ?? 01 00` merely happens to be
    compatible with one, and is left to the confidence scaling instead.
    """
    for framing in _RESERVED_FRAMINGS:
        if all(mask[i] and value[i] in allowed for i, allowed in enumerate(framing)):
            return True
    return False


class Builder:
    """Accumulates apps and domain rules, then serializes them."""

    def __init__(self) -> None:
        self.apps: dict[str, int] = {}          # slug -> app_id
        self.app_meta: dict[int, tuple[str, int, int]] = {}   # id -> (name, cat, lic)
        self.domains: list[tuple[str, int, int, int, int, int]] = []
        self.cidrs: list[tuple[bytes, int, int, int, int, int, int]] = []
        self.payloads: list[tuple[bytes, bytes, int, int, int, int]] = []
        self._next_id = 1
        self._seen: set[tuple[str, int, int]] = set()
        self._seen_cidr: set[tuple[bytes, int, int, int]] = set()
        self._seen_pay: set[tuple[bytes, bytes, int]] = set()
        self.aliases, self.drops = _load_curation()
        self.app_sources: dict[int, set[str]] = {}
        self._current_source = "?"
        self.dropped_hits = 0
        self.aliased_hits = 0
        self.reserved_dropped = 0

    DROPPED = 0     # sentinel app id: caller must discard the rule

    def app(self, slug: str, license_tier: int, category: int = 0) -> int:
        """Resolve a source slug to a canonical app id.

        Returns DROPPED (0) for identities curation says are not applications;
        callers must not attach rules to it.
        """
        if slug in self.drops:
            self.dropped_hits += 1
            return self.DROPPED
        if slug in self.aliases:
            self.aliased_hits += 1
            slug = self.aliases[slug]

        # Identity is keyed on the separator-free form, so "epic-games" and
        # "epicgames" resolve to one app. This is exact equality modulo
        # punctuation, NOT fuzzy matching - nothing is merged on name
        # similarity, which is how "Amazon", "Amazon Music" and "Amazon Prime
        # Video" would wrongly collapse into one.
        key = re.sub(r"[^a-z0-9]", "", slug)

        if key in self.apps:
            aid = self.apps[key]
            self.app_sources.setdefault(aid, set()).add(self._current_source)
            name, cat, lic = self.app_meta[aid]
            # Prefer the hyphenated spelling for display; it reads better and is
            # stable regardless of which source happened to arrive first.
            if "-" in slug and "-" not in name:
                name = slug
            self.app_meta[aid] = (name, cat, min(license_tier, lic))
            return aid

        aid = self._next_id
        self._next_id += 1
        self.apps[key] = aid
        self.app_meta[aid] = (slug, category, license_tier)
        self.app_sources.setdefault(aid, set()).add(self._current_source)
        return aid

    def domain(self, name: str, app_id: int, *, exact: bool = False,
               tier: int = TIER_B, confidence: int = 80,
               license_tier: int = LIC_PERMISSIVE) -> bool:
        name = name.strip().lower()
        # A leading dot is the conventional "and all subdomains" marker in these
        # lists (".googlezip.net"). It is not part of the name, and leaving it
        # in produces an empty first label that no correct parser will match.
        if name.startswith("."):
            name = name.lstrip(".")
            exact = False
        name = name.rstrip(".")
        if not name or " " in name or "." not in name:
            return False
        # Reject anything still carrying an empty label; it can never match.
        if ".." in name:
            return False
        # A rule is identified by (name, kind, app) — the same domain claimed by
        # two sources for the same app is one rule, not two.
        key = (name, DOM_EXACT if exact else DOM_SUFFIX, app_id)
        if key in self._seen:
            return False
        self._seen.add(key)
        self.domains.append((name, app_id, DOM_EXACT if exact else DOM_SUFFIX,
                             confidence, tier, license_tier))
        return True

    def cidr(self, cidr: str, app_id: int, *, tier: int = TIER_C,
             confidence: int = 40, license_tier: int = LIC_PERMISSIVE) -> bool:
        """Add an IP prefix rule.

        Default confidence is deliberately low: an IP prefix says who owns the
        address, not which application is talking. Behind a CDN it is close to
        meaningless on its own, so it corroborates or narrows rather than
        deciding. Promoting these to high confidence is how engines produce
        confident false positives.
        """
        if app_id == self.DROPPED:
            return False
        if app_id == self.DROPPED:
            return False
        try:
            net = ipaddress.ip_network(cidr.strip(), strict=False)
        except ValueError:
            return False

        raw = net.network_address.packed
        af = 4 if net.version == 4 else 6
        raw = raw + b"\0" * (16 - len(raw))
        key = (raw, net.prefixlen, af, app_id)
        if key in self._seen_cidr:
            return False
        self._seen_cidr.add(key)
        self.cidrs.append((raw, app_id, net.prefixlen, af, tier, confidence,
                           license_tier))
        return True

    def payload(self, value: bytes, mask: bytes, app_id: int, *,
                tier: int = TIER_A, confidence: int = 60,
                license_tier: int = LIC_LGPL) -> bool:
        """Add a 4-byte payload-prefix rule (tier A: survives ECH)."""
        if app_id == self.DROPPED:
            return False
        if len(value) != 4 or len(mask) != 4:
            return False
        if not any(mask):                 # all-wildcard matches everything
            return False
        if _pins_reserved_framing(value, mask):
            self.reserved_dropped += 1
            return False
        value = bytes(v & m for v, m in zip(value, mask))
        key = (value, mask, app_id)
        if key in self._seen_pay:
            return False
        self._seen_pay.add(key)
        self.payloads.append((value, mask, app_id, tier, confidence, license_tier))
        return True

    def serialize(self, max_license: int) -> bytes:
        apps = [(aid, n, c, l) for aid, (n, c, l) in self.app_meta.items()
                if l <= max_license]
        doms = [d for d in self.domains if d[5] <= max_license]
        cids = [c for c in self.cidrs if c[6] <= max_license]
        pays = [q for q in self.payloads if q[5] <= max_license]
        keep = {a[0] for a in apps}
        doms = [d for d in doms if d[1] in keep]
        cids = [c for c in cids if c[1] in keep]
        pays = [q for q in pays if q[2] in keep]

        pool = bytearray(b"\0")           # offset 0 is the empty string
        offsets: dict[str, int] = {}

        def intern(s: str) -> int:
            if s not in offsets:
                offsets[s] = len(pool)
                pool.extend(s.encode("utf-8", "replace") + b"\0")
            return offsets[s]

        app_blob = b"".join(
            struct.pack(APP_FMT, aid, intern(name), cat, lic, 0)
            for aid, name, cat, lic in sorted(apps)
        )
        dom_blob = b"".join(
            struct.pack(DOM_FMT, intern(name), aid, mt, conf, tier, lic)
            for name, aid, mt, conf, tier, lic in doms
        )

        cidr_blob = b"".join(
            struct.pack(CIDR_FMT, raw, aid, plen, af, tier, conf, lic, b"\0" * 3)
            for raw, aid, plen, af, tier, conf, lic in cids
        )

        pay_blob = b"".join(
            struct.pack(PAY_FMT, val, msk, aid, tier, conf, lic, 0)
            for val, msk, aid, tier, conf, lic in pays
        )

        hdr_size = struct.calcsize(HDR_FMT)
        app_off = hdr_size
        dom_off = app_off + len(app_blob)
        cidr_off = dom_off + len(dom_blob)
        pay_off = cidr_off + len(cidr_blob)
        pool_off = pay_off + len(pay_blob)

        hdr = struct.pack(HDR_FMT, MAGIC, VERSION, len(apps), len(doms),
                          len(pool), app_off, dom_off, pool_off,
                          int(time.time()), len(cids), cidr_off,
                          len(pays), pay_off)
        return hdr + app_blob + dom_blob + cidr_blob + pay_blob + bytes(pool)


# ------------------------------------------------------------------ sources

def load_netify(b: Builder) -> dict:
    """Netify's Apache-2.0 list: app: definitions plus dom:/net: rules."""
    found = list((TP / "netify-agent").rglob("netify-apps.conf"))
    if not found:
        return {"error": "netify-apps.conf not found"}

    by_native: dict[str, int] = {}
    apps = doms = nets = skipped = 0

    for line in found[0].read_text(errors="ignore").splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split(":", 2)
        if len(parts) < 3:
            continue
        kind, native, rest = parts[0], parts[1], parts[2]

        if kind == "app":
            slug = _slug(rest.replace("netify.", "").strip())
            if slug != "unknown":
                by_native[native] = b.app(slug, LIC_PERMISSIVE)
                apps += 1
        elif kind == "dom":
            aid = by_native.get(native)
            if aid is None:
                skipped += 1
                continue
            # Vendor-owned hostname => tier B.
            if b.domain(rest, aid, tier=TIER_B, confidence=85,
                        license_tier=LIC_PERMISSIVE):
                doms += 1
        elif kind == "net":
            aid = by_native.get(native)
            if aid is None:
                skipped += 1
                continue
            if b.cidr(rest, aid, tier=TIER_C, confidence=45,
                      license_tier=LIC_PERMISSIVE):
                nets += 1

    return {"apps": apps, "domains": doms, "cidrs": nets,
            "orphan_rules": skipped, "license": "Apache-2.0"}


# host_match[]: { "hostname", "AppName", NDPI_PROTOCOL_X, NDPI_PROTOCOL_CATEGORY_Y, ... }
_HOST_MATCH = re.compile(
    r'\{\s*"([^"]+)"\s*,\s*"([^"]+)"\s*,\s*NDPI_PROTOCOL_([A-Z0-9_]+)')


def load_ndpi_hosts(b: Builder) -> dict:
    """nDPI's hostname->protocol table (LGPL), so the license filter has teeth.

    nDPI names each app twice: a display name ("AmazonVideo") and a protocol
    constant (NDPI_PROTOCOL_AMAZON_VIDEO). We key on the constant, which is the
    stable identity, and keep the display name only for readability.
    """
    f = TP / "ndpi/src/lib/ndpi_content_match.c.inc"
    if not f.exists():
        return {"error": "not vendored"}

    text = f.read_text(errors="ignore")
    apps = doms = ip_rows = 0

    for m in _HOST_MATCH.finditer(text):
        host, _display, proto = m.group(1), m.group(2), m.group(3)

        # The same file carries IP-prefix tables; those are tier C, not domains.
        try:
            ipaddress.ip_address(host)
            ip_rows += 1
            continue
        except ValueError:
            pass
        if "." not in host:
            continue

        slug = _slug(proto)
        if slug not in b.apps:
            apps += 1
        aid = b.app(slug, LIC_LGPL)
        if b.domain(host, aid, tier=TIER_B, confidence=75,
                    license_tier=LIC_LGPL):
            doms += 1

    return {"new_apps": apps, "domains": doms, "ip_rows_skipped": ip_rows,
            "license": "LGPL-3.0"}


# ------------------------------------------------------------------- openappid
# ODP ships GPL-2.0 detector content. The Lua files are mostly procedural, but
# two table shapes carry directly usable host signatures, and appMapping.data
# resolves the numeric appId to a name.

# gSSLHostPatternList: { type, appId, 'domain' }
_ODP_SSL = re.compile(r"\{\s*\d+\s*,\s*(\d+)\s*,\s*['\"]([^'\"]+)['\"]\s*\}")

# gUrlPatternList: { _, _, _, serviceId, clientId, "host", "path", "scheme", "", appId }
# The APP is the LAST field; field 4 is a service/protocol id. Reading the wrong
# one silently mislabels thousands of rules (frostwire.com would become "SMTPS").
_ODP_URL = re.compile(
    r'\{\s*\d+\s*,\s*\d+\s*,\s*\d+\s*,\s*\d+\s*,\s*\d+\s*,'
    r'\s*"([^"]+)"\s*,\s*"[^"]*"\s*,\s*"[^"]*"\s*,\s*"[^"]*"\s*,\s*(\d+)\s*\}')


def _odp_app_names() -> dict[int, str]:
    f = TP / "openappid-odp/appMapping.data"
    if not f.exists():
        return {}
    out: dict[int, str] = {}
    for line in f.read_text(errors="ignore").splitlines():
        cols = line.split("\t")
        if len(cols) >= 2 and cols[0].strip().isdigit():
            out[int(cols[0])] = cols[1].strip()
    return out




def load_openappid(b: Builder) -> dict:
    """OpenAppID SSL-host and URL host patterns -> tier B domain rules."""
    base = TP / "openappid-odp/lua"
    if not base.exists():
        return {"error": "not vendored"}

    names = _odp_app_names()
    if not names:
        return {"error": "appMapping.data missing"}

    apps: set[str] = set()
    ssl_rules = url_rules = unresolved = 0

    for lua in base.glob("*.lua"):
        text = lua.read_text(errors="ignore")

        for m in _ODP_SSL.finditer(text):
            app_id, host = int(m.group(1)), m.group(2)
            nm = names.get(app_id)
            if not nm:
                unresolved += 1
                continue
            slug = _slug(nm)
            apps.add(slug)
            aid = b.app(slug, LIC_GPL)
            if b.domain(host, aid, tier=TIER_B, confidence=80,
                        license_tier=LIC_GPL):
                ssl_rules += 1

        for m in _ODP_URL.finditer(text):
            host, app_id = m.group(1), int(m.group(2))
            nm = names.get(app_id)
            if not nm:
                unresolved += 1
                continue
            slug = _slug(nm)
            apps.add(slug)
            aid = b.app(slug, LIC_GPL)
            if b.domain(host, aid, tier=TIER_B, confidence=80,
                        license_tier=LIC_GPL):
                url_rules += 1

    return {"apps": len(apps), "ssl_host_rules": ssl_rules,
            "url_host_rules": url_rules, "unresolved_appids": unresolved,
            "license": "GPL-2.0"}


# --------------------------------------------------------------------- mmt-dpi
# Apache-2.0, so everything here lands in the SHIPPABLE build.
#
# The host table lives in mmt_tcpip_classif_utils.c as
#   {".163.com", PROTO_163, 0}
# Note the LEADING DOT: a grep anchored on [a-z0-9] after the quote finds almost
# nothing and makes this corpus look empty. It is not.
_MMT_DOMAIN = re.compile(r'\{\s*"\.([a-z0-9][^"]*)"\s*,\s*PROTO_([A-Z0-9_]+)\s*,')


def load_mmt_dpi(b: Builder) -> dict:
    """MMT-DPI host table -> tier B domain rules, permissively licensed."""
    base = TP / "mmt-dpi/src"
    if not base.exists():
        return {"error": "not vendored"}

    apps: set[str] = set()
    rules = 0
    for src in base.rglob("*.c"):
        text = src.read_text(errors="ignore")
        if "PROTO_" not in text:
            continue
        for m in _MMT_DOMAIN.finditer(text):
            host, proto = m.group(1), m.group(2)
            slug = _slug(proto)
            apps.add(slug)
            aid = b.app(slug, LIC_PERMISSIVE)
            # Leading dot in the source means "and all subdomains" -> suffix.
            if b.domain(host, aid, tier=TIER_B, confidence=70,
                        license_tier=LIC_PERMISSIVE):
                rules += 1

    return {"apps": len(apps), "domain_rules": rules, "license": "Apache-2.0"}


# -------------------------------------------------------------- libprotoident
# LGPL-3.0. One lpi_<proto>.cc module per protocol; matching is expressed as
# comparisons against the first four payload bytes in each direction:
#
#   MATCHSTR(payload, "HTTP")              -> 4 literal bytes
#   MATCH(payload, 'B', 'Z', 'h', '9')     -> 4 byte quad
#   MATCH(payload, 0x16, 0x03, ANY, ANY)   -> quad with wildcards
#
# These are tier A: they read the protocol on the wire, so they keep working
# when ECH blinds every SNI-based signature.

_LPI_MATCHSTR = re.compile(r'MATCHSTR\(\s*payload\s*,\s*"((?:[^"\\]|\\.)*)"\s*\)')
_LPI_MATCH = re.compile(
    r"MATCH\(\s*payload\s*,\s*([^,()]+),\s*([^,()]+),\s*([^,()]+),\s*([^,()]+)\)")


def _c_string_bytes(lit: str) -> bytes:
    """Decode a C string literal body to raw bytes (handles \\xNN, \\n, ...)."""
    try:
        return lit.encode("latin-1", "ignore").decode("unicode_escape").encode("latin-1")
    except Exception:
        return b""


def _lpi_byte(tok: str) -> tuple[int, int]:
    """Return (value, mask) for one MATCH argument."""
    t = tok.strip()
    if t == "ANY":
        return 0, 0x00
    m = re.fullmatch(r"0[xX]([0-9a-fA-F]{1,2})", t)
    if m:
        return int(m.group(1), 16), 0xFF
    m = re.fullmatch(r"'(\\?.)'", t)
    if m:
        c = m.group(1)
        if c.startswith("\\"):
            dec = _c_string_bytes(c)
            return (dec[0], 0xFF) if dec else (0, 0)
        return ord(c), 0xFF
    return -1, -1                      # an expression we cannot evaluate


def load_libprotoident(b: Builder) -> dict:
    """libprotoident 4-byte payload prefixes -> tier A PROTOCOL rules.

    Extraction is filtered, because the naive version is unsound. A MATCH() call
    is one condition inside a bidirectional conjunction with length constraints:

        if (match_taobao_req(payload[0]) && match_taobao_resp(payload[1]))

    Lifted out alone a condition loses that context, and taobao's
    `16 03 01 00` branch then fires on every TLS ClientHello in existence.

    Filters:
      1. claimed by exactly ONE protocol corpus-wide - this alone removes
         `16 03 01 00`, which taobao and vmware both use
      2. at least two distinct byte values - drops 00000000 and friends
      3. wildcarded patterns need >= 2 pinned bytes, and carry confidence scaled
         to how much is actually pinned: two known bytes is a 1-in-65k match and
         may corroborate, never decide.
    """
    base = TP / "libprotoident/lib"
    if not base.exists():
        return {"error": "not vendored"}

    # (value, mask) -> claiming protocols
    claims: dict[tuple[bytes, bytes], set[str]] = {}
    FULL = b"\xff\xff\xff\xff"

    for sub in ("tcp", "udp"):
        for src in (base / sub).glob("lpi_*.cc"):
            app = _slug(src.stem[len("lpi_"):])
            text = src.read_text(errors="ignore")

            for m in _LPI_MATCHSTR.finditer(text):
                raw = _c_string_bytes(m.group(1))
                if len(raw) >= 4:
                    claims.setdefault((raw[:4], FULL), set()).add(app)

            for m in _LPI_MATCH.finditer(text):
                vals, masks, ok = [], [], True
                for g in m.groups():
                    v, mk = _lpi_byte(g)
                    if v < 0:
                        ok = False
                        break
                    vals.append(v if mk else 0)
                    masks.append(mk)
                if ok:
                    claims.setdefault((bytes(vals), bytes(masks)), set()).add(app)

    # Fewer pinned bytes means a looser pattern, so less confidence in it.
    CONF = {4: 65, 3: 55, 2: 40}
    apps: set[str] = set()
    exact = wild = ambiguous = degenerate = too_loose = 0

    for (value, mask), owners in claims.items():
        if len(owners) != 1:
            ambiguous += 1
            continue
        pinned = sum(1 for m in mask if m)
        if pinned < 2:
            too_loose += 1
            continue
        known = bytes(v for v, m in zip(value, mask) if m)
        if len(set(known)) < 2:
            degenerate += 1
            continue

        slug = next(iter(owners))
        apps.add(slug)
        aid = b.app(slug, LIC_LGPL)
        if b.payload(value, mask, aid, tier=TIER_A,
                     confidence=CONF[pinned], license_tier=LIC_LGPL):
            if pinned == 4:
                exact += 1
            else:
                wild += 1

    return {"apps": len(apps), "exact_rules": exact, "masked_rules": wild,
            "dropped_ambiguous": ambiguous, "dropped_degenerate": degenerate,
            "dropped_under_2_pinned": too_loose, "license": "LGPL-3.0"}



# ------------------------------------------------------- tier A: payload bytes
# Tier A reads the protocol off the wire instead of trusting a name, so it is the
# only evidence that survives Encrypted Client Hello. It is also structurally
# scarce: a distinctive byte prefix only exists for protocols that put one there,
# and anything riding HTTPS does not.
#
# Every C DPI engine expresses these as a compare of the first payload bytes
# against a literal, one file per protocol:
#     memcmp(payload, "SSH-", 4)        (mmt-dpi)
#     memcmp(packet->payload, "RTPS", 4) / ndpi_match_strprefix(p, len, "OggS")
#
# Same soundness filters as libprotoident: a prefix claimed by two protocols is
# not a signature, and one with fewer than two distinct byte values is noise.

_BYTECMP = re.compile(
    r'(?:mmt_)?memcmp\(\s*(?:\(\s*const\s+char\s*\*\s*\)\s*)?(?:&\s*)?'
    r'(?:packet->)?payload\s*(?:\[\s*0\s*\])?\s*,\s*"((?:[^"\\]|\\.)*)"\s*,\s*(\d+)\s*\)')
_STRPREFIX = re.compile(r'ndpi_match_strprefix\([^,]+,[^,]+,\s*"((?:[^"\\]|\\.)*)"\s*\)')


def _harvest_prefixes(root: Path, namer, extra_re=None) -> dict[bytes, set[str]]:
    """Collect 4-byte payload prefixes from C sources, keyed by claiming protocol."""
    claims: dict[bytes, set[str]] = {}
    if not root.exists():
        return claims
    for f in root.rglob("*.c"):
        proto = namer(f)
        if not proto:
            continue
        text = f.read_text(errors="ignore")
        pats = [m.group(1) for m in _BYTECMP.finditer(text)]
        if extra_re:
            pats += [m.group(1) for m in extra_re.finditer(text)]
        for lit in pats:
            raw = _c_string_bytes(lit)
            if len(raw) >= 4:
                claims.setdefault(raw[:4], set()).add(_slug(proto))
    return claims


def _emit_prefixes(b: Builder, claims, license_tier: int, confidence: int) -> dict:
    apps: set[str] = set()
    emitted = ambiguous = degenerate = 0
    for pattern, owners in claims.items():
        if len(owners) != 1:
            ambiguous += 1
            continue
        if len(set(pattern)) < 2:
            degenerate += 1
            continue
        slug = next(iter(owners))
        apps.add(slug)
        aid = b.app(slug, license_tier)
        if b.payload(pattern, b"\xff\xff\xff\xff", aid, tier=TIER_A,
                     confidence=confidence, license_tier=license_tier):
            emitted += 1
    return {"apps": len(apps), "payload_rules": emitted,
            "dropped_ambiguous": ambiguous, "dropped_degenerate": degenerate}


def load_mmt_payload(b: Builder) -> dict:
    """MMT-DPI payload prefixes -> tier A, Apache-2.0, so these SHIP."""
    root = TP / "mmt-dpi/src/mmt_tcpip/lib/protocols"
    claims = _harvest_prefixes(
        root, lambda f: f.stem[len("proto_"):] if f.stem.startswith("proto_") else None)
    if not claims:
        return {"error": "not vendored"}
    out = _emit_prefixes(b, claims, LIC_PERMISSIVE, 65)
    out["license"] = "Apache-2.0"
    return out


def load_ndpi_payload(b: Builder) -> dict:
    """nDPI dissector payload prefixes -> tier A."""
    root = TP / "ndpi/src/lib/protocols"
    claims = _harvest_prefixes(root, lambda f: f.stem, _STRPREFIX)
    if not claims:
        return {"error": "not vendored"}
    out = _emit_prefixes(b, claims, LIC_LGPL, 65)
    out["license"] = "LGPL-3.0"
    return out


# ------------------------------------------------------------- derivation feeds
# Fetched from the primary upstreams by scripts/fetch_feeds.sh. These are public
# operator-published facts about their own address space, so the resulting rules
# are ours: no upstream corpus license attaches, and they are fresher than any
# vendored snapshot.

FEEDS = ROOT / "data" / "feeds"


def _json(name: str):
    import json
    f = FEEDS / name
    if not f.exists():
        return None
    try:
        return json.loads(f.read_text())
    except Exception:
        return None


def load_cloud_feeds(b: Builder) -> dict:
    """Cloud/CDN/service IP ranges -> tier C attribution."""
    added: dict[str, int] = {}

    def add(slug: str, cidr: str, conf: int = 40) -> None:
        aid = b.app(slug, LIC_PERMISSIVE)
        if b.cidr(cidr, aid, tier=TIER_C, confidence=conf,
                  license_tier=LIC_PERMISSIVE):
            added[slug] = added.get(slug, 0) + 1

    # AWS names the service per prefix, which is the useful granularity:
    # S3, CLOUDFRONT and EC2 are different applications to a firewall.
    aws = _json("aws-ip-ranges.json")
    if aws:
        for key, pfx in (("prefixes", "ip_prefix"), ("ipv6_prefixes", "ipv6_prefix")):
            for e in aws.get(key, []):
                svc = (e.get("service") or "AMAZON").lower()
                slug = "aws" if svc == "amazon" else f"aws-{svc.replace('_', '-')}"
                add(slug, e[pfx])

    gcp = _json("gcp-cloud.json")
    if gcp:
        for e in gcp.get("prefixes", []):
            c = e.get("ipv4Prefix") or e.get("ipv6Prefix")
            if c:
                add("google-cloud", c)

    orc = _json("oracle-ip-ranges.json")
    if orc:
        for reg in orc.get("regions", []):
            for e in reg.get("cidrs", []):
                if e.get("cidr"):
                    add("oracle-cloud", e["cidr"])

    gh = _json("github-meta.json")
    if gh:
        for key, val in gh.items():
            if not isinstance(val, list):
                continue
            slug = "github" if key in ("web", "api", "git") else f"github-{key}"
            for c in val:
                if isinstance(c, str) and "/" in c:
                    add(slug, c)

    fast = _json("fastly-ip-list.json")
    if fast:
        for c in fast.get("addresses", []) + fast.get("ipv6_addresses", []):
            add("fastly", c)

    for fn, slug in (("cloudflare-v4.txt", "cloudflare"),
                     ("cloudflare-v6.txt", "cloudflare")):
        f = FEEDS / fn
        if f.exists():
            for line in f.read_text().split():
                if "/" in line:
                    add(slug, line)

    do = FEEDS / "digitalocean.csv"
    if do.exists():
        for line in do.read_text(errors="ignore").splitlines():
            c = line.split(",")[0].strip()
            if "/" in c:
                add("digitalocean", c)

    # Tor exits are single addresses, and unlike a CDN range the attribution is
    # exact: traffic to a listed exit really is Tor. Confidence is high.
    tor = FEEDS / "tor-exit-list.txt"
    if tor.exists():
        for line in tor.read_text(errors="ignore").splitlines():
            ip = line.strip()
            if ip and not ip.startswith("#"):
                add("tor", ip + ("/32" if ":" not in ip else "/128"), conf=75)

    if not added:
        return {"error": "no feeds found - run scripts/fetch_feeds.sh"}
    total = sum(added.values())
    return {"apps": len(added), "cidrs": total, "license": "public-data"}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--max-license", default="gpl", choices=sorted(LIC_NAMES))
    ap.add_argument("--emit-json", help="also write a full app inventory here")
    args = ap.parse_args()

    b = Builder()
    print("compiling signature database")
    for name, fn in (("netify", load_netify),
                     ("ndpi-hosts", load_ndpi_hosts),
                     ("openappid", load_openappid),
                     ("mmt-dpi", load_mmt_dpi),
                     ("libprotoident", load_libprotoident),
                     ("mmt-payload", load_mmt_payload),
                     ("ndpi-payload", load_ndpi_payload),
                     ("cloud-feeds", load_cloud_feeds)):
        b._current_source = name
        info = fn(b)
        if "error" in info:
            print(f"  {name:14} SKIPPED — {info['error']}")
        else:
            print(f"  {name:14} " + "  ".join(f"{k}={v}" for k, v in info.items()))

    if b.dropped_hits or b.aliased_hits:
        print(f"  {'curation':14} dropped_rules={b.dropped_hits}  "
              f"aliased_ids={b.aliased_hits}  "
              f"(data/drops.json, data/aliases.json)")
    if b.reserved_dropped:
        print(f"  {'framing':14} payload_rules_refused={b.reserved_dropped}  "
              f"(pinned a framing the engine dissects natively)")

    blob = b.serialize(LIC_NAMES[args.max_license])
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(blob)

    if args.emit_json:
        import json
        maxl = LIC_NAMES[args.max_license]
        doms_by_app: dict[int, list[str]] = {}
        for name_, aid, mt, conf, tier, lic in b.domains:
            if lic <= maxl:
                doms_by_app.setdefault(aid, []).append(name_)
        cidr_n: dict[int, int] = {}
        for _r, aid, _p, _af, _t, _c, lic in b.cidrs:
            if lic <= maxl:
                cidr_n[aid] = cidr_n.get(aid, 0) + 1
        pay_by_app: dict[int, list[str]] = {}
        for val, msk, aid, _t, _c, lic in b.payloads:
            if lic <= maxl:
                pay_by_app.setdefault(aid, []).append(val.hex())

        inv = []
        for aid, (nm, cat, lic) in sorted(b.app_meta.items()):
            if lic > maxl:
                continue
            dl = sorted(doms_by_app.get(aid, []), key=len)
            inv.append({
                "id": aid, "name": nm, "license": lic,
                "sources": sorted(b.app_sources.get(aid, [])),
                "domains": len(dl), "cidrs": cidr_n.get(aid, 0),
                "payloads": len(pay_by_app.get(aid, [])),
                "sample_domains": dl[:10],
                "sample_payloads": pay_by_app.get(aid, [])[:4],
            })
        Path(args.emit_json).write_text(json.dumps({
            "apps": inv,
            "curation": {"aliases": b.aliases, "drops": b.drops,
                         "dropped_rules": b.dropped_hits,
                         "aliased_ids": b.aliased_hits},
        }))
        print(f"  inventory -> {args.emit_json}")

    hdr = struct.unpack(HDR_FMT, blob[:struct.calcsize(HDR_FMT)])
    print(f"\n  -> {out}  ({len(blob):,} bytes)")
    print(f"     apps={hdr[2]}  domain_rules={hdr[3]}  cidr_rules={hdr[9]}"
          f"  payload_rules={hdr[11]}  string_pool={hdr[4]:,}B"
          f"  max_license={args.max_license}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
