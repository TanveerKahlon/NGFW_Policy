"""Base output sink."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class BaseOutput(ABC):
    """A destination for crawled records.

    Sinks are used as async context managers so they can open files or DB
    handles once per run and flush deterministically on exit.
    """

    name: str = "base"

    async def __aenter__(self) -> BaseOutput:
        await self.open()
        return self

    async def __aexit__(self, *exc_info) -> None:
        await self.close()

    async def open(self) -> None:
        """Prepare the sink. Override if resources need acquiring."""

    @abstractmethod
    async def write(self, record: dict[str, Any]) -> None:
        """Persist a single record."""
        ...

    async def write_many(self, records: list[dict[str, Any]]) -> None:
        for record in records:
            await self.write(record)

    async def close(self) -> None:
        """Flush and release resources."""
