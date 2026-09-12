"""Per-domain token-bucket rate limiting."""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse


@dataclass
class DomainBucket:
    """Token bucket for a single domain."""

    rps: float
    burst: int = 1
    tokens: float = field(default=1.0)
    updated_at: float = field(default_factory=time.monotonic)
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self.updated_at
        self.tokens = min(float(self.burst), self.tokens + elapsed * self.rps)
        self.updated_at = now

    async def acquire(self) -> float:
        """Block until a token is available. Returns seconds waited."""
        async with self.lock:
            self._refill()
            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return 0.0
            deficit = 1.0 - self.tokens
            wait = deficit / self.rps if self.rps > 0 else 0.0
            await asyncio.sleep(wait)
            self._refill()
            self.tokens = max(0.0, self.tokens - 1.0)
            return wait


class RateLimiter:
    """Dispenses per-domain buckets, so one slow host never throttles another."""

    def __init__(self, default_rps: float = 0.5, burst: int = 1):
        self.default_rps = default_rps
        self.burst = burst
        self._buckets: dict[str, DomainBucket] = {}
        self._overrides: dict[str, float] = {}

    def set_domain_rps(self, domain: str, rps: float) -> None:
        self._overrides[domain.lower()] = rps
        self._buckets.pop(domain.lower(), None)

    @staticmethod
    def domain_of(url: str) -> str:
        return (urlparse(url).hostname or "").lower()

    def bucket_for(self, url: str) -> DomainBucket:
        domain = self.domain_of(url)
        if domain not in self._buckets:
            rps = self._overrides.get(domain, self.default_rps)
            self._buckets[domain] = DomainBucket(
                rps=rps, burst=self.burst, tokens=float(self.burst)
            )
        return self._buckets[domain]

    async def acquire(self, url: str) -> float:
        return await self.bucket_for(url).acquire()
