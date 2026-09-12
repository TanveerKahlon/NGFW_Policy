"""RSS/Atom source: the feed supplies URLs, HTTP supplies the pages."""
from __future__ import annotations

import asyncio
from typing import Any

import feedparser

from src.core.config import SourceConfig
from src.sources.base import FetchResult
from src.sources.http_source import HttpSource
from src.utils.logging import get_logger

logger = get_logger(__name__)


class RssSource(HttpSource):
    """Discovers article URLs from one or more feeds, then fetches each page.

    Feed entry metadata (title, published date, summary) is preserved and
    merged into the FetchResult so extraction can fall back to it.
    """

    kind = "rss"

    def __init__(self, config: SourceConfig, timeout: float = 30.0, user_agent: str = ""):
        super().__init__(config, timeout=timeout, user_agent=user_agent)
        self._entry_meta: dict[str, dict[str, Any]] = {}

    async def discover(self) -> list[str]:
        urls: list[str] = []
        for feed_url in self.config.all_urls:
            entries = await self._parse_feed(feed_url)
            for entry in entries:
                link = entry.get("link")
                if not link or link in self._entry_meta:
                    continue
                self._entry_meta[link] = entry
                urls.append(link)
                if len(urls) >= self.config.max_items:
                    return urls
        return urls

    async def _parse_feed(self, feed_url: str) -> list[dict[str, Any]]:
        raw = await super().fetch(feed_url)
        if not raw.ok:
            logger.warning("feed_fetch_failed", url=feed_url, error=raw.error)
            return []

        # feedparser is synchronous and CPU-bound; keep it off the event loop.
        parsed = await asyncio.to_thread(feedparser.parse, raw.html)
        if parsed.bozo and not parsed.entries:
            logger.warning("feed_parse_failed", url=feed_url,
                           error=str(parsed.get("bozo_exception")))
            return []

        return [
            {
                "link": e.get("link", ""),
                "title": e.get("title", ""),
                "published": e.get("published", "") or e.get("updated", ""),
                "summary": e.get("summary", ""),
            }
            for e in parsed.entries
        ]

    async def fetch(self, url: str, **kwargs: Any) -> FetchResult:
        result = await super().fetch(url, **kwargs)
        entry = self._entry_meta.get(url)
        if entry:
            result.metadata["feed_entry"] = entry
        return result
