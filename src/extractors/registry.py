"""Builds the extractor chain for a source."""
from __future__ import annotations

from src.core.config import ExtractionConfig
from src.extractors.article_extractor import ArticleExtractor
from src.extractors.base import BaseExtractor
from src.extractors.jsonld_extractor import JsonLdExtractor
from src.extractors.selector_extractor import SelectorExtractor

_BY_NAME: dict[str, type[BaseExtractor]] = {
    "article": ArticleExtractor,
    "jsonld": JsonLdExtractor,
    "selectors": SelectorExtractor,
}


def build_extractor(config: ExtractionConfig) -> BaseExtractor:
    """Instantiate the extractor named by the config's strategy."""
    cls = _BY_NAME.get(config.strategy)
    if cls is None:
        raise ValueError(
            f"Unknown extraction strategy: {config.strategy!r} "
            f"(known: {', '.join(sorted(_BY_NAME))})"
        )
    if cls is SelectorExtractor:
        return SelectorExtractor(config.selectors)
    return cls()
