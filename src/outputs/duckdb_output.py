"""DuckDB sink with idempotent upserts keyed on the canonical URL."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src.outputs.base import BaseOutput
from src.utils.logging import get_logger

logger = get_logger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS documents (
    url_canonical  VARCHAR PRIMARY KEY,
    source_name    VARCHAR,
    url_final      VARCHAR,
    title          VARCHAR,
    author         VARCHAR,
    published      VARCHAR,
    text           VARCHAR,
    cves           VARCHAR[],
    cvss_max       DOUBLE,
    ipv4           VARCHAR[],
    cidrs          VARCHAR[],
    domains        VARCHAR[],
    sha256         VARCHAR[],
    quality_score  DOUBLE,
    status         VARCHAR,
    indicators     JSON,
    fetched_at     VARCHAR
);
"""

_COLUMNS = [
    "url_canonical", "source_name", "url_final", "title", "author", "published",
    "text", "cves", "cvss_max", "ipv4", "cidrs", "domains", "sha256",
    "quality_score", "status", "indicators", "fetched_at",
]


class DuckDbOutput(BaseOutput):
    """Re-crawling a URL updates its row instead of duplicating it."""

    name = "duckdb"

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._conn = None
        self.count = 0

    async def open(self) -> None:
        import duckdb

        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = duckdb.connect(str(self.path))
        self._conn.execute(SCHEMA)

    async def write(self, record: dict[str, Any]) -> None:
        if self._conn is None:
            await self.open()
        assert self._conn is not None

        indicators = record.get("indicators") or {}
        row = {
            "url_canonical": record.get("url_canonical", ""),
            "source_name": record.get("source_name", ""),
            "url_final": record.get("url_final", ""),
            "title": record.get("title", ""),
            "author": record.get("author", ""),
            "published": record.get("published", ""),
            "text": record.get("text", ""),
            "cves": indicators.get("cves") or [],
            "cvss_max": indicators.get("cvss_max"),
            "ipv4": indicators.get("ipv4") or [],
            "cidrs": indicators.get("cidrs") or [],
            "domains": indicators.get("domains") or [],
            "sha256": indicators.get("sha256") or [],
            "quality_score": record.get("quality_score", 0.0),
            "status": record.get("status", ""),
            "indicators": json.dumps(indicators, default=str),
            "fetched_at": record.get("fetched_at", ""),
        }

        placeholders = ", ".join("?" for _ in _COLUMNS)
        updates = ", ".join(f"{c} = excluded.{c}" for c in _COLUMNS if c != "url_canonical")
        self._conn.execute(
            f"INSERT INTO documents ({', '.join(_COLUMNS)}) VALUES ({placeholders}) "
            f"ON CONFLICT (url_canonical) DO UPDATE SET {updates}",
            [row[c] for c in _COLUMNS],
        )
        self.count += 1

    async def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None
            logger.info("duckdb_written", path=str(self.path), records=self.count)
