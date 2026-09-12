"""Main-content extraction via trafilatura, with a selectolax fallback."""
from __future__ import annotations

from typing import Any

from src.extractors.base import BaseExtractor


class ArticleExtractor(BaseExtractor):
    """Pulls title, body text, author and publication date out of a page.

    trafilatura does the boilerplate removal. If it declines to return a body
    (very short pages, unusual markup), we fall back to stripped <p> text so the
    pipeline still gets something scoreable rather than an empty dict.
    """

    name = "article"

    def extract(self, html: str, url: str = "", **kwargs: Any) -> dict[str, Any]:
        data: dict[str, Any] = {"url": url}

        try:
            import trafilatura
            from trafilatura.metadata import extract_metadata
        except ImportError:
            return {**data, **self._fallback(html)}

        text = trafilatura.extract(
            html,
            url=url or None,
            include_comments=False,
            include_tables=True,
            favor_precision=True,
        )

        meta = None
        try:
            meta = extract_metadata(html, default_url=url or None)
        except Exception:
            meta = None

        if meta is not None:
            data.update({
                "title": meta.title or "",
                "author": meta.author or "",
                "published": meta.date or "",
                "sitename": meta.sitename or "",
                "description": meta.description or "",
            })

        data["text"] = text or ""

        if not data.get("text") or not data.get("title"):
            for key, value in self._fallback(html).items():
                if not data.get(key):
                    data[key] = value

        return data

    @staticmethod
    def _fallback(html: str) -> dict[str, Any]:
        """Cheap structural extraction when trafilatura returns nothing."""
        try:
            from selectolax.parser import HTMLParser
        except ImportError:
            return {}

        tree = HTMLParser(html)
        for tag in ("script", "style", "nav", "footer", "header", "aside"):
            for node in tree.css(tag):
                node.decompose()

        title_node = tree.css_first("h1") or tree.css_first("title")
        paragraphs = [p.text(strip=True) for p in tree.css("p")]

        return {
            "title": title_node.text(strip=True) if title_node else "",
            "text": "\n\n".join(t for t in paragraphs if t),
        }
