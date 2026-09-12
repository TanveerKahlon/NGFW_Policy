from src.core.config import ExtractionConfig
from src.extractors.base import (
    ExtractionStatus,
    compute_quality_score,
    evaluate_extraction,
    is_present,
)


def test_is_present_semantics():
    assert is_present("x") and is_present([1]) and is_present(0) and is_present(False)
    assert not is_present("") and not is_present("   ")
    assert not is_present([]) and not is_present(None)


def test_required_fields_weigh_double():
    score, missing = compute_quality_score(
        {"title": "t", "text": ""}, ["title", "text"], []
    )
    assert missing == ["text"]
    assert score == 0.5


def test_all_present_scores_one():
    score, missing = compute_quality_score({"title": "t", "text": "b"}, ["title", "text"], [])
    assert score == 1.0 and missing == []


def test_status_success_partial_fail():
    config = ExtractionConfig(required_fields=["title", "text"], min_quality_score=0.5)

    ok = evaluate_extraction({"title": "t", "text": "b"}, config, "x")
    assert ok.status is ExtractionStatus.SUCCESS

    partial = evaluate_extraction({"title": "t", "text": ""}, config, "x")
    assert partial.status is ExtractionStatus.PARTIAL
    assert partial.missing_fields == ["text"]

    bad = evaluate_extraction({}, config, "x")
    assert bad.status is ExtractionStatus.FAIL


def test_no_required_fields_always_succeeds():
    result = evaluate_extraction({"a": 1}, ExtractionConfig(), "x")
    assert result.status is ExtractionStatus.SUCCESS
