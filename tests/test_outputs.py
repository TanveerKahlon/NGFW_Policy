import json

from src.outputs.duckdb_output import DuckDbOutput
from src.outputs.jsonl_output import JsonlOutput

RECORD = {
    "url_canonical": "https://example.com/a",
    "source_name": "t",
    "title": "Advisory",
    "text": "body",
    "quality_score": 0.9,
    "status": "SUCCESS",
    "fetched_at": "2026-09-10T00:00:00Z",
    "indicators": {"cves": ["CVE-2024-3400"], "cvss_max": 10.0, "ipv4": ["1.1.1.1"]},
}


async def test_jsonl_writes_one_object_per_line(tmp_path):
    path = tmp_path / "out.jsonl"
    async with JsonlOutput(path) as sink:
        await sink.write(RECORD)
        await sink.write({**RECORD, "url_canonical": "https://example.com/b"})

    lines = path.read_text().strip().split("\n")
    assert len(lines) == 2
    assert json.loads(lines[0])["title"] == "Advisory"


async def test_jsonl_appends_across_runs(tmp_path):
    path = tmp_path / "out.jsonl"
    for _ in range(2):
        async with JsonlOutput(path) as sink:
            await sink.write(RECORD)
    assert len(path.read_text().strip().split("\n")) == 2


async def test_duckdb_upsert_is_idempotent(tmp_path):
    import duckdb

    path = tmp_path / "out.duckdb"
    async with DuckDbOutput(path) as sink:
        await sink.write(RECORD)
        await sink.write({**RECORD, "title": "Advisory v2"})

    conn = duckdb.connect(str(path))
    rows = conn.execute("SELECT url_canonical, title, cves, cvss_max FROM documents").fetchall()
    conn.close()

    assert len(rows) == 1
    assert rows[0][1] == "Advisory v2"
    assert rows[0][2] == ["CVE-2024-3400"]
    assert rows[0][3] == 10.0


async def test_duckdb_handles_missing_indicators(tmp_path):
    import duckdb

    path = tmp_path / "out.duckdb"
    async with DuckDbOutput(path) as sink:
        await sink.write({"url_canonical": "https://example.com/x"})

    conn = duckdb.connect(str(path))
    row = conn.execute("SELECT cves, cvss_max FROM documents").fetchone()
    conn.close()
    assert row[0] == []
    assert row[1] is None
