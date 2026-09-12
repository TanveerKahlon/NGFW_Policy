"""robots.txt fetching, caching and rule evaluation."""
from __future__ import annotations

import asyncio
import time
from urllib.parse import urljoin, urlparse
from urllib.robotparser import RobotFileParser

import httpx

from src.utils.logging import get_logger

logger = get_logger(__name__)

DEFAULT_TTL_SECONDS = 3600


class RobotsTxtChecker:
    """Caches one parser per origin, with a TTL.

    Fails open: if robots.txt cannot be fetched (network error, 5xx), the URL is
    allowed. A 4xx is treated by the standard as "no restrictions".
    """

    def __init__(
        self, user_agent: str = "*", ttl: int = DEFAULT_TTL_SECONDS, timeout: float = 10.0
    ):
        self.user_agent = user_agent
        self.ttl = ttl
        self.timeout = timeout
        self._cache: dict[str, tuple[RobotFileParser, float]] = {}
        # One lock per origin: concurrent URLs from the same host would
        # otherwise each miss the cache and refetch robots.txt.
        self._locks: dict[str, asyncio.Lock] = {}

    @staticmethod
    def _origin(url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    async def _load(self, origin: str) -> RobotFileParser:
        parser = RobotFileParser()
        robots_url = urljoin(origin + "/", "robots.txt")
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                resp = await client.get(robots_url, headers={"User-Agent": self.user_agent})
            if resp.status_code >= 500:
                parser.allow_all = True
            elif resp.status_code >= 400:
                parser.allow_all = True
            else:
                parser.parse(resp.text.splitlines())
        except Exception as e:
            logger.debug("robots_fetch_failed", origin=origin, error=str(e))
            parser.allow_all = True
        return parser

    def _fresh(self, origin: str) -> RobotFileParser | None:
        cached = self._cache.get(origin)
        if cached and (time.monotonic() - cached[1]) < self.ttl:
            return cached[0]
        return None

    async def _get_parser(self, origin: str) -> RobotFileParser:
        parser = self._fresh(origin)
        if parser is not None:
            return parser

        lock = self._locks.setdefault(origin, asyncio.Lock())
        async with lock:
            # Re-check: another task may have populated the cache while we waited.
            parser = self._fresh(origin)
            if parser is not None:
                return parser
            parser = await self._load(origin)
            self._cache[origin] = (parser, time.monotonic())
            return parser

    async def can_fetch(self, url: str) -> bool:
        parser = await self._get_parser(self._origin(url))
        return parser.can_fetch(self.user_agent, url)

    async def crawl_delay(self, url: str) -> float | None:
        """Return the host's declared Crawl-delay, if any."""
        parser = await self._get_parser(self._origin(url))
        try:
            delay = parser.crawl_delay(self.user_agent)
        except Exception:
            return None
        return float(delay) if delay is not None else None
