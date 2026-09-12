"""Settings and YAML source-config loading."""
from __future__ import annotations

import os
from enum import StrEnum
from pathlib import Path

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config" / "sources.yaml"


class Settings(BaseSettings):
    """Process-wide settings, overridable from .env or the environment."""

    model_config = SettingsConfigDict(env_prefix="NGFW_", env_file=".env", extra="ignore")

    user_agent: str = "ngfw-crawler/0.1 (+security-research)"
    respect_robots: bool = True
    default_rps: float = 0.5
    max_concurrency: int = 4
    timeout: float = 30.0
    data_dir: Path = PROJECT_ROOT / "data"


class SourceKind(StrEnum):
    HTTP = "http"
    RSS = "rss"
    BROWSER = "browser"


class ExtractionConfig(BaseModel):
    """The contract an extraction must satisfy to count as SUCCESS."""

    strategy: str = "article"
    required_fields: list[str] = Field(default_factory=list)
    optional_fields: list[str] = Field(default_factory=list)
    min_quality_score: float = 0.5
    selectors: dict[str, str] = Field(default_factory=dict)


class SourceConfig(BaseModel):
    name: str
    kind: SourceKind = SourceKind.HTTP
    enabled: bool = True
    url: str = ""
    urls: list[str] = Field(default_factory=list)
    rps: float | None = None
    max_items: int = 50
    impersonate: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    extraction: ExtractionConfig = Field(default_factory=ExtractionConfig)

    @property
    def all_urls(self) -> list[str]:
        out = list(self.urls)
        if self.url and self.url not in out:
            out.insert(0, self.url)
        return out


class CrawlConfig(BaseModel):
    sources: list[SourceConfig] = Field(default_factory=list)

    def enabled_sources(self) -> list[SourceConfig]:
        return [s for s in self.sources if s.enabled]

    def get(self, name: str) -> SourceConfig | None:
        return next((s for s in self.sources if s.name == name), None)


_cache: dict[str, tuple[CrawlConfig, float]] = {}


def load_config(path: str | Path | None = None) -> CrawlConfig:
    """Load and validate sources.yaml, cached on file mtime."""
    config_path = Path(path or DEFAULT_CONFIG_PATH).resolve()
    if not config_path.exists():
        raise FileNotFoundError(f"Config not found: {config_path}")

    key = str(config_path)
    mtime = os.path.getmtime(config_path)
    cached = _cache.get(key)
    if cached and cached[1] == mtime:
        return cached[0]

    with open(config_path) as f:
        raw = yaml.safe_load(f) or {}

    config = CrawlConfig.model_validate(raw)
    _cache[key] = (config, mtime)
    return config


def clear_config_cache() -> None:
    _cache.clear()
