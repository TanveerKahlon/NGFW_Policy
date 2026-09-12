"""ngfw command-line interface."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from src.core.config import Settings, load_config
from src.core.pipeline import Pipeline
from src.outputs.duckdb_output import DuckDbOutput
from src.outputs.jsonl_output import JsonlOutput
from src.utils.logging import setup_logging

console = Console()


@click.group()
@click.option("--log-level", default=None, help="DEBUG, INFO, WARNING, ERROR.")
def cli(log_level: str | None) -> None:
    """Security advisory and threat-intel crawler."""
    setup_logging(log_level)


@cli.command("list")
@click.option("--config", "config_path", default=None, help="Path to sources.yaml.")
def list_sources(config_path: str | None) -> None:
    """Show configured sources."""
    config = load_config(config_path)

    table = Table(title="Configured sources")
    table.add_column("Name", style="cyan")
    table.add_column("Kind")
    table.add_column("Enabled")
    table.add_column("Strategy")
    table.add_column("URLs", justify="right")

    for source in config.sources:
        table.add_row(
            source.name,
            source.kind.value,
            "[green]yes[/]" if source.enabled else "[dim]no[/]",
            source.extraction.strategy,
            str(len(source.all_urls)),
        )
    console.print(table)


@cli.command()
@click.option("--config", "config_path", default=None, help="Path to sources.yaml.")
@click.option("--source", "only", multiple=True, help="Crawl only these sources (repeatable).")
@click.option("--limit", type=int, default=None, help="Cap URLs per source.")
@click.option("--jsonl", "jsonl_path", default=None, help="Write JSONL here.")
@click.option("--duckdb", "duckdb_path", default=None, help="Write DuckDB here.")
@click.option("--no-robots", is_flag=True,
              help="Skip robots.txt checks (use only on hosts you own).")
@click.option("--rps", type=float, default=None, help="Override default per-domain requests/sec.")
@click.option("--concurrency", type=int, default=None, help="Override max concurrent fetches.")
def crawl(
    config_path: str | None,
    only: tuple[str, ...],
    limit: int | None,
    jsonl_path: str | None,
    duckdb_path: str | None,
    no_robots: bool,
    rps: float | None,
    concurrency: int | None,
) -> None:
    """Run a crawl."""
    settings = Settings()
    if no_robots:
        settings.respect_robots = False
    if rps is not None:
        settings.default_rps = rps
    if concurrency is not None:
        settings.max_concurrency = concurrency

    config = load_config(config_path)
    if limit is not None:
        for source in config.sources:
            source.max_items = limit

    data_dir = Path(settings.data_dir)
    outputs = []
    if jsonl_path or not duckdb_path:
        outputs.append(JsonlOutput(jsonl_path or data_dir / "documents.jsonl"))
    if duckdb_path:
        outputs.append(DuckDbOutput(duckdb_path))

    stats = asyncio.run(_run(config, settings, outputs, list(only)))

    table = Table(title="Crawl summary")
    table.add_column("Metric", style="cyan")
    table.add_column("Count", justify="right")
    for key, value in stats.as_dict().items():
        if key == "per_source":
            continue
        table.add_row(key, str(value))
    console.print(table)

    if stats.per_source:
        per_source = Table(title="Documents per source")
        per_source.add_column("Source", style="cyan")
        per_source.add_column("Count", justify="right")
        for name, count in sorted(stats.per_source.items()):
            per_source.add_row(name, str(count))
        console.print(per_source)


async def _run(config, settings, outputs, only):
    for output in outputs:
        await output.open()
    try:
        pipeline = Pipeline(config, settings, outputs)
        return await pipeline.run(only=only or None)
    finally:
        for output in outputs:
            await output.close()


@cli.command()
@click.argument("url")
@click.option("--strategy", default="article", help="article, jsonld, or selectors.")
@click.option("--browser", is_flag=True, help="Render with headless Chromium first.")
@click.option("--json", "as_json", is_flag=True, help="Print the full record as JSON.")
def fetch(url: str, strategy: str, browser: bool, as_json: bool) -> None:
    """Fetch and extract a single URL, without touching the configured sources."""
    from src.core.config import ExtractionConfig, SourceConfig, SourceKind

    settings = Settings()
    source_config = SourceConfig(
        name="adhoc",
        kind=SourceKind.BROWSER if browser else SourceKind.HTTP,
        url=url,
        extraction=ExtractionConfig(strategy=strategy),
    )

    record = asyncio.run(_fetch_one(source_config, settings))
    if record is None:
        console.print("[red]Fetch failed.[/]")
        raise SystemExit(1)

    if as_json:
        console.print_json(json.dumps(record, default=str))
        return

    console.print(f"[bold cyan]{record.get('title') or '(no title)'}[/]")
    console.print(f"[dim]{record.get('url_final')}[/]")
    console.print(f"quality={record.get('quality_score')} status={record.get('status')}\n")

    indicators = record.get("indicators", {})
    hits = {k: v for k, v in indicators.items() if v}
    if hits:
        table = Table(title="Indicators")
        table.add_column("Type", style="cyan")
        table.add_column("Values")
        for key, value in hits.items():
            rendered = ", ".join(map(str, value)) if isinstance(value, list) else str(value)
            table.add_row(key, rendered[:400])
        console.print(table)

    text = record.get("text") or ""
    if text:
        console.print(f"\n{text[:1500]}{'...' if len(text) > 1500 else ''}")


async def _fetch_one(source_config, settings):
    from src.core.config import CrawlConfig

    pipeline = Pipeline(CrawlConfig(sources=[source_config]), settings, outputs=[])
    captured: list[dict] = []

    async def capture(record):
        captured.append(record)

    pipeline._emit = capture
    await pipeline.run()
    return captured[0] if captured else None


if __name__ == "__main__":
    cli()
