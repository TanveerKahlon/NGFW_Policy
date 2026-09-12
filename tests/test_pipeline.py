import pytest

from src.core.config import CrawlConfig, ExtractionConfig, Settings, SourceConfig
from src.core.pipeline import Pipeline
from src.sources.base import BaseSource, FetchResult, FetchStatus

HTML = """
<html><body><article>
<h1>Advisory for CVE-2024-3400</h1>
<p>Exploited in the wild. C2 observed at 45.77.12.9 and evil[.]top.</p>
<p>Palo Alto Networks published hotfixes across every supported branch today.</p>
</article></body></html>
"""


class FakeSource(BaseSource):
    """Serves canned HTML so the pipeline can be tested without network."""

    kind = "fake"

    def __init__(self, config, timeout=30.0, user_agent=""):
        super().__init__(config)
        self.fetched: list[str] = []

    async def discover(self):
        return self.config.all_urls

    async def fetch(self, url, **kwargs):
        self.fetched.append(url)
        if "fail" in url:
            return FetchResult(
                source_name=self.name, url_original=url,
                status=FetchStatus.FAILED, error="boom",
            )
        return FetchResult(
            source_name=self.name, url_original=url, url_final=url,
            url_canonical=url, status_code=200, html=HTML,
        )


class CollectingOutput:
    name = "collect"

    def __init__(self):
        self.records = []

    async def write(self, record):
        self.records.append(record)


@pytest.fixture
def settings():
    return Settings(respect_robots=False, default_rps=1000.0, max_concurrency=4)


@pytest.fixture
def patched_factory(monkeypatch):
    monkeypatch.setattr(
        "src.core.pipeline.build_source",
        lambda config, timeout=30.0, user_agent="": FakeSource(config),
    )


def make_config(urls, **kwargs):
    return CrawlConfig(sources=[SourceConfig(
        name="test-src",
        urls=urls,
        extraction=ExtractionConfig(
            required_fields=["title", "text"], min_quality_score=0.5
        ),
        **kwargs,
    )])


async def test_end_to_end_produces_enriched_record(settings, patched_factory):
    output = CollectingOutput()
    pipeline = Pipeline(make_config(["https://example.com/a"]), settings, [output])
    stats = await pipeline.run()

    assert stats.fetched == 1
    assert stats.extracted_success == 1
    assert len(output.records) == 1

    record = output.records[0]
    assert "CVE-2024-3400" in record["title"]
    assert record["indicators"]["cves"] == ["CVE-2024-3400"]
    assert "45.77.12.9" in record["indicators"]["ipv4"]
    assert "evil.top" in record["indicators"]["domains"]
    assert record["quality_score"] > 0.5


async def test_duplicate_urls_fetched_once(settings, patched_factory):
    output = CollectingOutput()
    urls = ["https://example.com/a", "https://example.com/a?utm_source=x", "https://example.com/a#f"]
    pipeline = Pipeline(make_config(urls), settings, [output])
    stats = await pipeline.run()

    assert stats.fetched == 1
    assert stats.skipped_duplicate == 2


async def test_failed_fetch_counted_and_not_emitted(settings, patched_factory):
    output = CollectingOutput()
    pipeline = Pipeline(
        make_config(["https://example.com/fail", "https://example.com/ok"]), settings, [output]
    )
    stats = await pipeline.run()

    assert stats.failed == 1
    assert stats.fetched == 1
    assert len(output.records) == 1


async def test_unfetchable_urls_are_dropped(settings, patched_factory):
    output = CollectingOutput()
    config = make_config(["javascript:alert(1)", "https://example.com/a"])
    pipeline = Pipeline(config, settings, [output])
    stats = await pipeline.run()
    assert stats.fetched == 1


async def test_max_items_caps_urls(settings, patched_factory):
    output = CollectingOutput()
    urls = [f"https://example.com/{i}" for i in range(10)]
    pipeline = Pipeline(make_config(urls, max_items=3), settings, [output])
    stats = await pipeline.run()
    assert stats.fetched == 3


async def test_only_filter_selects_sources(settings, patched_factory):
    config = CrawlConfig(sources=[
        SourceConfig(name="a", urls=["https://a.com/1"]),
        SourceConfig(name="b", urls=["https://b.com/1"]),
    ])
    output = CollectingOutput()
    stats = await Pipeline(config, settings, [output]).run(only=["b"])

    assert stats.fetched == 1
    assert output.records[0]["source_name"] == "b"


async def test_robots_disallow_skips_fetch(settings, patched_factory, monkeypatch):
    settings.respect_robots = True
    output = CollectingOutput()
    pipeline = Pipeline(make_config(["https://example.com/a"]), settings, [output])

    async def deny(url):
        return False

    monkeypatch.setattr(pipeline.robots, "can_fetch", deny)
    stats = await pipeline.run()

    assert stats.skipped_robots == 1
    assert stats.fetched == 0


async def test_output_failure_does_not_abort_crawl(settings, patched_factory):
    class BrokenOutput:
        name = "broken"

        async def write(self, record):
            raise RuntimeError("disk full")

    pipeline = Pipeline(make_config(["https://example.com/a"]), settings, [BrokenOutput()])
    stats = await pipeline.run()
    assert stats.fetched == 1
