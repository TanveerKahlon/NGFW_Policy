"""Crawl orchestration: discover -> gate -> fetch -> extract -> emit."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

from src.core.config import CrawlConfig, Settings, SourceConfig
from src.extractors.base import ExtractionStatus
from src.extractors.indicator_extractor import IndicatorExtractor
from src.extractors.registry import build_extractor
from src.outputs.base import BaseOutput
from src.sources.base import BaseSource, FetchStatus
from src.sources.factory import build_source
from src.utils.logging import get_logger
from src.utils.rate_limiter import RateLimiter
from src.utils.robotstxt import RobotsTxtChecker
from src.utils.url import canonicalize, is_fetchable

logger = get_logger(__name__)


@dataclass
class CrawlStats:
    """Per-run counters, printed as the CLI summary."""

    discovered: int = 0
    fetched: int = 0
    failed: int = 0
    skipped_robots: int = 0
    skipped_duplicate: int = 0
    extracted_success: int = 0
    extracted_partial: int = 0
    extracted_fail: int = 0
    per_source: dict[str, int] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "discovered": self.discovered,
            "fetched": self.fetched,
            "failed": self.failed,
            "skipped_robots": self.skipped_robots,
            "skipped_duplicate": self.skipped_duplicate,
            "extracted_success": self.extracted_success,
            "extracted_partial": self.extracted_partial,
            "extracted_fail": self.extracted_fail,
            "per_source": dict(self.per_source),
        }


class Pipeline:
    """Runs configured sources concurrently, respecting robots and rate limits.

    Concurrency is bounded globally by `settings.max_concurrency`; politeness is
    enforced per-domain by the rate limiter, so a burst of URLs from one host
    serializes without stalling other hosts.
    """

    def __init__(
        self,
        config: CrawlConfig,
        settings: Settings,
        outputs: list[BaseOutput] | None = None,
    ):
        self.config = config
        self.settings = settings
        self.outputs = outputs or []
        self.stats = CrawlStats()

        self.rate_limiter = RateLimiter(default_rps=settings.default_rps)
        self.robots = RobotsTxtChecker(user_agent=settings.user_agent)
        self.indicators = IndicatorExtractor()

        self._seen: set[str] = set()
        self._semaphore = asyncio.Semaphore(settings.max_concurrency)
        self._write_lock = asyncio.Lock()

    async def run(self, only: list[str] | None = None) -> CrawlStats:
        sources = self.config.enabled_sources()
        if only:
            wanted = set(only)
            sources = [s for s in sources if s.name in wanted]
            missing = wanted - {s.name for s in sources}
            if missing:
                logger.warning("unknown_sources", names=sorted(missing))

        if not sources:
            logger.warning("no_sources_selected")
            return self.stats

        await asyncio.gather(*(self._run_source(sc) for sc in sources))
        return self.stats

    async def _run_source(self, source_config: SourceConfig) -> None:
        if source_config.rps is not None:
            for url in source_config.all_urls:
                domain = RateLimiter.domain_of(url)
                if domain:
                    self.rate_limiter.set_domain_rps(domain, source_config.rps)

        source = build_source(
            source_config,
            timeout=self.settings.timeout,
            user_agent=self.settings.user_agent,
        )
        log = logger.bind(source=source_config.name, kind=source_config.kind.value)

        try:
            urls = await source.discover()
            log.info("discovered", count=len(urls))
            self.stats.discovered += len(urls)

            urls = urls[: source_config.max_items]
            await asyncio.gather(*(self._process(source, source_config, u) for u in urls))
        except Exception as e:
            log.error("source_failed", error=str(e))
        finally:
            await source.close()

    async def _process(self, source: BaseSource, source_config: SourceConfig, url: str) -> None:
        log = logger.bind(source=source_config.name, url=url)

        if not is_fetchable(url):
            log.debug("skipped_unfetchable")
            return

        canonical = canonicalize(url)
        async with self._write_lock:
            if canonical in self._seen:
                self.stats.skipped_duplicate += 1
                return
            self._seen.add(canonical)

        if self.settings.respect_robots and not await self.robots.can_fetch(url):
            log.info("skipped_robots_disallow")
            self.stats.skipped_robots += 1
            return

        async with self._semaphore:
            await self.rate_limiter.acquire(url)
            result = await source.fetch(url)

        if result.status is FetchStatus.SKIPPED:
            return
        if not result.ok:
            self.stats.failed += 1
            log.warning("fetch_failed", status=result.status.value, error=result.error)
            return

        self.stats.fetched += 1
        self.stats.per_source[source_config.name] = (
            self.stats.per_source.get(source_config.name, 0) + 1
        )

        record = self._build_record(result, source_config)
        await self._emit(record)

    def _build_record(self, result, source_config: SourceConfig) -> dict[str, Any]:
        extractor = build_extractor(source_config.extraction)
        extraction = extractor.extract_and_evaluate(
            result.html, source_config.extraction, url=result.url_final or result.url_original
        )

        if extraction.status is ExtractionStatus.SUCCESS:
            self.stats.extracted_success += 1
        elif extraction.status is ExtractionStatus.PARTIAL:
            self.stats.extracted_partial += 1
        else:
            self.stats.extracted_fail += 1

        data = dict(extraction.data)

        # Feed metadata is a better fallback than an empty field.
        feed_entry = result.metadata.get("feed_entry") or {}
        for key, meta_key in (("title", "title"), ("published", "published")):
            if not data.get(key) and feed_entry.get(meta_key):
                data[key] = feed_entry[meta_key]

        indicators = self.indicators.extract(
            result.html, url=result.url_final, text=data.get("text", "")
        )

        return {
            "job_id": result.job_id,
            "source_name": result.source_name,
            "url_original": result.url_original,
            "url_final": result.url_final,
            "url_canonical": result.url_canonical,
            "status_code": result.status_code,
            "fetched_at": result.fetched_at,
            "status": extraction.status.value,
            "quality_score": round(extraction.quality_score, 3),
            "missing_fields": extraction.missing_fields,
            "extractor": extraction.extractor_name,
            "indicators": indicators,
            **data,
        }

    async def _emit(self, record: dict[str, Any]) -> None:
        if not self.outputs:
            return
        async with self._write_lock:
            for output in self.outputs:
                try:
                    await output.write(record)
                except Exception as e:
                    logger.error("output_write_failed", output=output.name, error=str(e))
