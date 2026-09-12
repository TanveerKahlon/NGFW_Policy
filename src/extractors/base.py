"""Base extractor ABC, quality scoring, and the extraction contract."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from src.core.config import ExtractionConfig


class ExtractionStatus(StrEnum):
    SUCCESS = "SUCCESS"
    PARTIAL = "PARTIAL"
    FAIL = "FAIL"


@dataclass
class ExtractionResult:
    """Outcome of one extraction attempt.

    Contract:
    - SUCCESS: every required field present AND quality_score >= min_quality_score
    - PARTIAL: some required fields present, but not all (or score below threshold)
    - FAIL:    no required field present, or the extractor raised
    """

    status: ExtractionStatus = ExtractionStatus.FAIL
    data: dict[str, Any] = field(default_factory=dict)
    missing_fields: list[str] = field(default_factory=list)
    quality_score: float = 0.0
    extractor_name: str = ""
    errors: list[str] = field(default_factory=list)


def is_present(value: Any) -> bool:
    """Empty string, empty collection, and None all count as absent; 0 and False do not."""
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, dict, tuple, set)):
        return len(value) > 0
    return True


def compute_quality_score(
    data: dict[str, Any],
    required_fields: list[str],
    optional_fields: list[str] | None = None,
) -> tuple[float, list[str]]:
    """Weighted completeness score: required fields count double.

    Returns (score in 0..1, list of missing required fields).
    """
    optional = optional_fields if optional_fields is not None else [
        k for k in data if k not in required_fields
    ]

    total_weight = len(required_fields) * 2.0 + len(optional) * 1.0
    if total_weight == 0:
        return 1.0, []

    earned = 0.0
    missing: list[str] = []

    for f in required_fields:
        if is_present(data.get(f)):
            earned += 2.0
        else:
            missing.append(f)

    for f in optional:
        if is_present(data.get(f)):
            earned += 1.0

    return earned / total_weight, missing


def evaluate_extraction(
    data: dict[str, Any],
    config: ExtractionConfig,
    extractor_name: str,
) -> ExtractionResult:
    """Score extracted data against the configured contract."""
    score, missing = compute_quality_score(
        data, config.required_fields, config.optional_fields or None
    )

    if not config.required_fields or (not missing and score >= config.min_quality_score):
        status = ExtractionStatus.SUCCESS
    elif not data or missing == config.required_fields:
        status = ExtractionStatus.FAIL
    else:
        status = ExtractionStatus.PARTIAL

    return ExtractionResult(
        status=status,
        data=data,
        missing_fields=missing,
        quality_score=score,
        extractor_name=extractor_name,
    )


class BaseExtractor(ABC):
    """Abstract base for all extractors."""

    name: str = "base"

    @abstractmethod
    def extract(self, html: str, url: str = "", **kwargs) -> dict[str, Any]:
        """Return a flat dict of field_name -> value."""
        ...

    def extract_and_evaluate(
        self,
        html: str,
        config: ExtractionConfig,
        url: str = "",
        **kwargs,
    ) -> ExtractionResult:
        try:
            data = self.extract(html, url=url, **kwargs)
        except Exception as e:
            return ExtractionResult(
                status=ExtractionStatus.FAIL,
                extractor_name=self.name,
                errors=[str(e)],
            )
        return evaluate_extraction(data, config, self.name)
