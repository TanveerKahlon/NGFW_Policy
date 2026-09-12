"""Structured-data extraction from JSON-LD blocks."""
from __future__ import annotations

import json
from typing import Any

from src.extractors.base import BaseExtractor

# Maps schema.org keys onto our flat field names.
_FIELD_MAP = {
    "headline": "title",
    "name": "title",
    "datePublished": "published",
    "dateModified": "modified",
    "description": "description",
    "articleBody": "text",
}


class JsonLdExtractor(BaseExtractor):
    """Reads <script type="application/ld+json"> payloads.

    Handles the three shapes that appear in the wild: a bare object, a list of
    objects, and an @graph wrapper. Malformed blocks are skipped rather than
    failing the whole extraction.
    """

    name = "jsonld"

    def extract(self, html: str, url: str = "", **kwargs: Any) -> dict[str, Any]:
        try:
            from selectolax.parser import HTMLParser
        except ImportError:
            return {}

        tree = HTMLParser(html)
        data: dict[str, Any] = {"url": url}

        for node in tree.css('script[type="application/ld+json"]'):
            raw = node.text(strip=True)
            if not raw:
                continue
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                continue

            for obj in self._iter_objects(payload):
                for schema_key, field_name in _FIELD_MAP.items():
                    value = obj.get(schema_key)
                    if value and not data.get(field_name):
                        data[field_name] = self._flatten(value)

                author = obj.get("author")
                if author and not data.get("author"):
                    data["author"] = self._flatten(author)

        return data

    @staticmethod
    def _iter_objects(payload: Any):
        """Yield every dict in an object / list / @graph payload."""
        stack = [payload]
        while stack:
            item = stack.pop()
            if isinstance(item, list):
                stack.extend(item)
            elif isinstance(item, dict):
                yield item
                if "@graph" in item:
                    stack.append(item["@graph"])

    @staticmethod
    def _flatten(value: Any) -> str:
        """Reduce a schema.org value to a plain string."""
        if isinstance(value, str):
            return value.strip()
        if isinstance(value, dict):
            return str(value.get("name") or value.get("@id") or "").strip()
        if isinstance(value, list):
            parts = [JsonLdExtractor._flatten(v) for v in value]
            return ", ".join(p for p in parts if p)
        return str(value)
