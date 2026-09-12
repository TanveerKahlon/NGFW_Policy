"""URL canonicalization and validation."""
from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

TRACKING_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "gclid", "fbclid", "mc_cid", "mc_eid", "ref", "ref_src",
}

ALLOWED_SCHEMES = {"http", "https"}


def canonicalize(url: str) -> str:
    """Normalize a URL for stable dedup keys.

    Lowercases scheme/host, drops the fragment and tracking params,
    strips a default port and a trailing slash on non-root paths.
    """
    parsed = urlparse(url.strip())
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()

    if parsed.port and not (
        (scheme == "http" and parsed.port == 80) or (scheme == "https" and parsed.port == 443)
    ):
        host = f"{host}:{parsed.port}"

    path = parsed.path or "/"
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")

    query = urlencode(
        [(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True)
         if k.lower() not in TRACKING_PARAMS]
    )

    return urlunparse((scheme, host, path, "", query, ""))


def is_fetchable(url: str) -> bool:
    """Reject non-HTTP(S) schemes and obviously malformed URLs."""
    try:
        parsed = urlparse(url.strip())
    except ValueError:
        return False
    return parsed.scheme.lower() in ALLOWED_SCHEMES and bool(parsed.hostname)
