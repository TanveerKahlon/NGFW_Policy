import pytest
import yaml
from pydantic import ValidationError

from src.core.config import Settings, SourceKind, clear_config_cache, load_config

SAMPLE = {
    "sources": [
        {
            "name": "a",
            "kind": "rss",
            "url": "https://a.com/feed",
            "urls": ["https://a.com/other"],
            "extraction": {"strategy": "article", "required_fields": ["title"]},
        },
        {"name": "b", "enabled": False, "url": "https://b.com"},
    ]
}


@pytest.fixture
def config_file(tmp_path):
    clear_config_cache()
    path = tmp_path / "sources.yaml"
    path.write_text(yaml.safe_dump(SAMPLE))
    return path


def test_load_parses_kinds_and_extraction(config_file):
    config = load_config(config_file)
    source = config.get("a")
    assert source.kind is SourceKind.RSS
    assert source.extraction.required_fields == ["title"]


def test_enabled_sources_filters(config_file):
    assert [s.name for s in load_config(config_file).enabled_sources()] == ["a"]


def test_all_urls_merges_url_and_urls(config_file):
    assert load_config(config_file).get("a").all_urls == [
        "https://a.com/feed",
        "https://a.com/other",
    ]


def test_defaults_applied(config_file):
    source = load_config(config_file).get("b")
    assert source.kind is SourceKind.HTTP
    assert source.rps is None
    assert source.extraction.strategy == "article"


def test_cache_returns_same_object_until_mtime_changes(config_file):
    first = load_config(config_file)
    assert load_config(config_file) is first


def test_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_config(tmp_path / "nope.yaml")


def test_invalid_kind_rejected(tmp_path):
    clear_config_cache()
    path = tmp_path / "bad.yaml"
    path.write_text(yaml.safe_dump({"sources": [{"name": "x", "kind": "carrier-pigeon"}]}))
    with pytest.raises(ValidationError):
        load_config(path)


def test_settings_env_override(monkeypatch):
    monkeypatch.setenv("NGFW_DEFAULT_RPS", "3.5")
    monkeypatch.setenv("NGFW_RESPECT_ROBOTS", "false")
    settings = Settings()
    assert settings.default_rps == 3.5
    assert settings.respect_robots is False
