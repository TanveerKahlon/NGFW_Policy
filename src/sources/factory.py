"""Maps a SourceConfig.kind to its concrete source class."""
from __future__ import annotations

from src.core.config import SourceConfig, SourceKind
from src.sources.base import BaseSource
from src.sources.browser_source import BrowserSource
from src.sources.http_source import HttpSource
from src.sources.rss_source import RssSource

_REGISTRY: dict[SourceKind, type[BaseSource]] = {
    SourceKind.HTTP: HttpSource,
    SourceKind.RSS: RssSource,
    SourceKind.BROWSER: BrowserSource,
}


def build_source(config: SourceConfig, timeout: float = 30.0, user_agent: str = "") -> BaseSource:
    cls = _REGISTRY.get(config.kind)
    if cls is None:
        raise ValueError(f"Unknown source kind: {config.kind}")
    return cls(config, timeout=timeout, user_agent=user_agent)
