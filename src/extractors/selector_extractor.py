"""CSS-selector extraction, driven entirely by config."""
from __future__ import annotations

from typing import Any

from src.extractors.base import BaseExtractor


class SelectorExtractor(BaseExtractor):
    """Applies the `selectors` map from a source's extraction config.

    A selector may end in `@attr` to read an attribute instead of text, e.g.
        published: "time.date@datetime"
    Selectors matching multiple nodes return a list.
    """

    name = "selectors"

    def __init__(self, selectors: dict[str, str] | None = None):
        self.selectors = selectors or {}

    def extract(self, html: str, url: str = "", **kwargs: Any) -> dict[str, Any]:
        selectors = kwargs.get("selectors") or self.selectors
        if not selectors:
            return {}

        try:
            from selectolax.parser import HTMLParser
        except ImportError:
            return {}

        tree = HTMLParser(html)
        data: dict[str, Any] = {"url": url}

        for field_name, selector in selectors.items():
            css, _, attr = selector.partition("@")
            nodes = tree.css(css.strip())
            if not nodes:
                continue

            values = [
                (n.attributes.get(attr) or "") if attr else n.text(strip=True)
                for n in nodes
            ]
            values = [v.strip() for v in values if v and v.strip()]
            if not values:
                continue
            data[field_name] = values[0] if len(values) == 1 else values

        return data
