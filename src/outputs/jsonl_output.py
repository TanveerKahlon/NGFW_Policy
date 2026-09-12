"""Append-only JSONL sink."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, TextIO

from src.outputs.base import BaseOutput
from src.utils.logging import get_logger

logger = get_logger(__name__)


class JsonlOutput(BaseOutput):
    """One JSON object per line. Handy for grep/jq and for replaying a run."""

    name = "jsonl"

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._fh: TextIO | None = None
        self.count = 0

    async def open(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = self.path.open("a", encoding="utf-8")

    async def write(self, record: dict[str, Any]) -> None:
        if self._fh is None:
            await self.open()
        assert self._fh is not None
        self._fh.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
        self.count += 1

    async def close(self) -> None:
        if self._fh is not None:
            self._fh.flush()
            self._fh.close()
            self._fh = None
            logger.info("jsonl_written", path=str(self.path), records=self.count)
