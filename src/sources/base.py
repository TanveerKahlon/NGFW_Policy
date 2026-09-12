"""Base source ABC and the FetchResult it returns."""
from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from src.core.config import SourceConfig


class FetchStatus(StrEnum):
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"      # robots-disallowed, or 304 Not Modified
    RATE_LIMITED = "rate_limited"


@dataclass
class FetchResult:
    """One fetched document, before extraction."""

    job_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source_name: str = ""
    url_original: str = ""
    url_final: str = ""
    url_canonical: str = ""
    status: FetchStatus = FetchStatus.SUCCESS
    status_code: int = 0
    html: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    fetched_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.status is FetchStatus.SUCCESS and bool(self.html)


class BaseSource(ABC):
    """Abstract base for everything that can produce documents."""

    kind: str = "base"

    def __init__(self, config: SourceConfig):
        self.config = config
        self.name = config.name

    @property
    def user_agent(self) -> str:
        return self.config.headers.get("User-Agent", "*")

    @abstractmethod
    async def fetch(self, url: str, **kwargs) -> FetchResult:
        """Fetch a single URL."""
        ...

    async def discover(self) -> list[str]:
        """Return the URLs this source wants crawled.

        Override for sources with their own discovery (RSS, sitemaps).
        """
        return self.config.all_urls

    async def close(self) -> None:
        """Release held resources (HTTP clients, browsers)."""
