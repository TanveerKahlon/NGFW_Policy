from src.core.config import ExtractionConfig
from src.extractors.article_extractor import ArticleExtractor
from src.extractors.jsonld_extractor import JsonLdExtractor
from src.extractors.registry import build_extractor
from src.extractors.selector_extractor import SelectorExtractor

ARTICLE_HTML = """
<html><head><title>Ignored</title></head><body>
<nav>menu junk</nav>
<article>
  <h1>Critical PAN-OS Vulnerability</h1>
  <p>A command injection flaw tracked as CVE-2024-3400 affects PAN-OS firewalls.</p>
  <p>Palo Alto Networks has released hotfixes for all affected branches.</p>
</article>
<footer>copyright junk</footer>
</body></html>
"""


def test_article_extractor_gets_title_and_body():
    data = ArticleExtractor().extract(ARTICLE_HTML, url="https://example.com/a")
    assert "PAN-OS" in data["title"]
    assert "CVE-2024-3400" in data["text"]
    assert "menu junk" not in data["text"]


def test_article_extractor_survives_empty_html():
    data = ArticleExtractor().extract("", url="https://example.com/a")
    assert data["text"] == ""


def test_jsonld_extractor_reads_graph():
    html = """
    <script type="application/ld+json">
    {"@context":"https://schema.org","@graph":[
      {"@type":"Article","headline":"Advisory 42","datePublished":"2026-01-05",
       "author":{"@type":"Person","name":"PSIRT"}}]}
    </script>"""
    data = JsonLdExtractor().extract(html, url="https://example.com/a")
    assert data["title"] == "Advisory 42"
    assert data["published"] == "2026-01-05"
    assert data["author"] == "PSIRT"


def test_jsonld_skips_malformed_block():
    html = '<script type="application/ld+json">{not json]</script>'
    assert JsonLdExtractor().extract(html, url="u") == {"url": "u"}


def test_selector_extractor_text_and_attribute():
    html = '<div><h1 class="t">Title</h1><time datetime="2026-02-01">Feb</time></div>'
    extractor = SelectorExtractor({"title": "h1.t", "published": "time@datetime"})
    data = extractor.extract(html, url="u")
    assert data["title"] == "Title"
    assert data["published"] == "2026-02-01"


def test_selector_extractor_multiple_matches_return_list():
    html = "<ul><li>a</li><li>b</li></ul>"
    data = SelectorExtractor({"items": "li"}).extract(html, url="u")
    assert data["items"] == ["a", "b"]


def test_registry_builds_by_strategy():
    assert isinstance(build_extractor(ExtractionConfig(strategy="article")), ArticleExtractor)
    assert isinstance(build_extractor(ExtractionConfig(strategy="jsonld")), JsonLdExtractor)

    selector = build_extractor(ExtractionConfig(strategy="selectors", selectors={"a": "h1"}))
    assert isinstance(selector, SelectorExtractor)
    assert selector.selectors == {"a": "h1"}


def test_registry_rejects_unknown_strategy():
    import pytest

    with pytest.raises(ValueError, match="Unknown extraction strategy"):
        build_extractor(ExtractionConfig(strategy="nope"))


def test_extract_and_evaluate_catches_extractor_errors():
    class Boom(SelectorExtractor):
        def extract(self, html, url="", **kwargs):
            raise RuntimeError("kaboom")

    result = Boom().extract_and_evaluate("<html></html>", ExtractionConfig(), url="u")
    assert result.errors == ["kaboom"]
