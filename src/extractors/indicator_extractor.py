"""Extracts security indicators (CVEs, IPs, CIDRs, domains, hashes) from page text.

This is the NGFW-facing extractor: its output is what feeds rule/blocklist
generation downstream. It refangs defanged indicators first, because advisories
and threat reports almost always publish them neutered (1.2.3[.]4, hxxp://...).
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any

from src.extractors.base import BaseExtractor

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
# A CVSS vector string ("CVSS:4.0/AV:N/AC:L/...") leads with the *spec version*,
# not a severity. Strip vectors before scanning or every v4.0 advisory scores 4.0.
CVSS_VECTOR_RE = re.compile(
    r"CVSS:\d(?:\.\d)?/[A-Z]{1,2}:[A-Z](?:/[A-Z]{1,2}:[A-Z])*", re.IGNORECASE
)
# No leading \b: vendors emit "LOWCVSS-B: 4.8" once severity labels are joined.
CVSS_ANCHOR_RE = re.compile(r"CVSS", re.IGNORECASE)
CVSS_WINDOW = 160
# Real phrasings seen in the wild, all within a window after the CVSS mention:
#   "CVSS-B: 4.8"  |  "| CVSS |...| v3 8.4 |"  |  "CVSS v3.1 base score of 9.8"
# Requiring one decimal place keeps table counts and version numbers out.
CVSS_SCORE_RE = re.compile(
    r"(?:v?[234](?:\.\d)?\s+)?(?:base\s+)?(?:score\s*)?(?:of\s+|[:=]\s*)?(\d{1,2}\.\d)\b"
)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")
IPV6_RE = re.compile(r"\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}(?:/\d{1,3})?\b")
MD5_RE = re.compile(r"\b[0-9a-f]{32}\b", re.IGNORECASE)
SHA1_RE = re.compile(r"\b[0-9a-f]{40}\b", re.IGNORECASE)
SHA256_RE = re.compile(r"\b[0-9a-f]{64}\b", re.IGNORECASE)
URL_RE = re.compile(r"\bhttps?://[^\s<>\"')\]]+", re.IGNORECASE)
DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|net|org|io|ru|cn|info|biz|top|xyz|co|uk|de|nl|su|onion|pw|cc|me|tk)\b",
    re.IGNORECASE,
)

# Refanging table: defanged form -> real form.
_REFANG = [
    ("[.]", "."), ("(.)", "."), ("{.}", "."), (" dot ", "."),
    ("[:]", ":"), ("[://]", "://"),
    ("hxxps", "https"), ("hxxp", "http"),
    ("[at]", "@"), ("(at)", "@"),
]

# Hosts that appear in every advisory and are never the indicator.
DOMAIN_NOISE = {
    "example.com", "www.w3.org", "schema.org", "github.com", "www.github.com",
    "twitter.com", "x.com", "linkedin.com", "www.linkedin.com", "youtube.com",
    "nvd.nist.gov", "cve.mitre.org", "cwe.mitre.org", "first.org",
}


def refang(text: str) -> str:
    """Turn defanged indicators back into parseable ones."""
    out = text
    for bad, good in _REFANG:
        out = out.replace(bad, good).replace(bad.upper(), good)
    return out


def _valid_ipv4(token: str) -> str | None:
    """Validate an IPv4 address or CIDR, rejecting version-number lookalikes."""
    try:
        if "/" in token:
            return str(ipaddress.ip_network(token, strict=False))
        return str(ipaddress.ip_address(token))
    except ValueError:
        return None


class IndicatorExtractor(BaseExtractor):
    """Scans text for IOCs and vulnerability identifiers.

    Pass `text=` to scan already-extracted body text; otherwise the raw HTML is
    scanned, which is noisier but catches indicators inside tables and <code>.
    """

    name = "indicators"

    @staticmethod
    def _cvss_scores(text: str) -> list[float]:
        """Find severity scores near a CVSS mention, ignoring vector strings."""
        cleaned = CVSS_VECTOR_RE.sub(" ", text)
        scores: list[float] = []
        for anchor in CVSS_ANCHOR_RE.finditer(cleaned):
            window = cleaned[anchor.end() : anchor.end() + CVSS_WINDOW]
            match = CVSS_SCORE_RE.search(window)
            if not match:
                continue
            value = float(match.group(1))
            if 0.0 <= value <= 10.0:
                scores.append(value)
        return scores

    def extract(self, html: str, url: str = "", **kwargs: Any) -> dict[str, Any]:
        source_text = kwargs.get("text") or html
        text = refang(source_text)

        cves = sorted({m.group(0).upper() for m in CVE_RE.finditer(text)})

        ipv4: set[str] = set()
        cidrs: set[str] = set()
        for match in IPV4_RE.finditer(text):
            normalized = _valid_ipv4(match.group(0))
            if not normalized:
                continue
            (cidrs if "/" in normalized else ipv4).add(normalized)

        ipv6: set[str] = set()
        for match in IPV6_RE.finditer(text):
            try:
                token = match.group(0)
                ipv6.add(str(ipaddress.ip_network(token, strict=False)
                             if "/" in token else ipaddress.ip_address(token)))
            except ValueError:
                continue

        sha256 = {m.group(0).lower() for m in SHA256_RE.finditer(text)}
        sha1 = {m.group(0).lower() for m in SHA1_RE.finditer(text)}
        md5 = {m.group(0).lower() for m in MD5_RE.finditer(text)}
        # A sha256 contains substrings that match md5/sha1 patterns only at
        # word boundaries, so no overlap in practice — but strip defensively.
        sha1 -= sha256
        md5 -= sha256 | sha1

        domains = {
            d.lower() for d in (m.group(0) for m in DOMAIN_RE.finditer(text))
            if d.lower() not in DOMAIN_NOISE
        }

        cvss_scores = self._cvss_scores(text)

        return {
            "cves": cves,
            "cvss_max": max(cvss_scores) if cvss_scores else None,
            "ipv4": sorted(ipv4),
            "ipv6": sorted(ipv6),
            "cidrs": sorted(cidrs),
            "domains": sorted(domains),
            "urls": sorted({m.group(0).rstrip(".,;") for m in URL_RE.finditer(text)}),
            "md5": sorted(md5),
            "sha1": sorted(sha1),
            "sha256": sorted(sha256),
        }
