# ngfw

Security advisory and threat-intel crawler. Pulls vendor PSIRT feeds, CERT
advisories and threat reports, extracts the article body, and mines it for
indicators (CVEs, CVSS scores, IPs, CIDRs, domains, file hashes) that can feed
firewall rule and blocklist generation.

Architecture mirrors `~/Projects/scrapper`: **sources → extractors → outputs**,
wired together by a config-driven pipeline.

## Setup

```bash
uv venv --python 3.13
uv pip install -e '.[dev]'
cp .env.example .env          # optional; sane defaults are built in
```

Headless-browser rendering is opt-in (the Chromium build is already cached
under `~/Library/Caches/ms-playwright`):

```bash
uv pip install -e '.[browser]'
```

## Usage

```bash
ngfw list                                   # show configured sources
ngfw crawl                                  # crawl every enabled source
ngfw crawl --source paloalto-psirt --limit 5
ngfw crawl --duckdb data/advisories.duckdb  # query it later with SQL
ngfw fetch https://example.com/advisory     # one URL, no config needed
ngfw fetch <url> --browser --json           # render JS first, dump the record
```

Useful flags: `--rps` (per-domain rate), `--concurrency`, `--limit`,
`--no-robots` (only for hosts you control).

## How a crawl runs

1. **Discover** — each source yields URLs. `rss` parses feeds; `http`/`browser`
   use the configured URLs directly.
2. **Gate** — URLs are canonicalized (fragment and `utm_*` stripped) and deduped,
   checked against `robots.txt`, then rate-limited per domain.
3. **Fetch** — `httpx` by default. On a 403/429/503, a source with
   `impersonate:` set retries through `curl_cffi` with a real browser's TLS
   fingerprint. `browser` sources render in headless Chromium instead.
4. **Extract** — the configured strategy runs, then the result is scored against
   the source's contract (`required_fields`, `min_quality_score`) and labelled
   SUCCESS / PARTIAL / FAIL.
5. **Enrich** — every document is scanned for indicators, refanging defanged
   forms (`1.2.3[.]4`, `hxxp://`) first.
6. **Emit** — written to JSONL and/or DuckDB. DuckDB upserts on the canonical
   URL, so re-crawling updates rows instead of duplicating them.

## Adding a source

Append to `config/sources.yaml`:

```yaml
  - name: vendor-psirt
    kind: rss                # http | rss | browser
    enabled: true
    url: https://vendor.example/advisories.xml
    rps: 0.5                 # per-domain requests/sec
    max_items: 25
    impersonate: chrome124   # optional: only used after a 403/429/503
    extraction:
      strategy: article      # article | jsonld | selectors
      required_fields: [title, text]
      optional_fields: [published, author]
      min_quality_score: 0.5
```

For `strategy: selectors`, supply a `selectors` map. A selector may read an
attribute with `@`:

```yaml
      selectors:
        title: "h1.advisory-title"
        published: "time.published@datetime"
```

## Layout

```
src/core/       settings, YAML config loading, the pipeline orchestrator
src/sources/    http (+ curl_cffi fallback), rss, browser (playwright)
src/extractors/ article (trafilatura), jsonld, selectors, indicators
src/outputs/    jsonl, duckdb
src/utils/      rate limiter, robots.txt, URL canonicalizer, logging
```

## Querying results

```sql
-- advisories with a high CVSS, newest first
SELECT title, cvss_max, cves, url_final
FROM documents
WHERE cvss_max >= 8.0
ORDER BY fetched_at DESC;

-- every unique IPv4 indicator seen
SELECT DISTINCT unnest(ipv4) AS ip FROM documents;
```

## Development

```bash
pytest -q          # 70 tests
ruff check .
```

## Politeness

`robots.txt` is honoured by default (fetched once per origin, cached with a TTL,
failing open on network errors) and requests are rate-limited per domain at
0.5 rps. Raise `--rps` only for hosts whose terms you have checked. The
`impersonate` fallback exists so vendor advisory pages behind generic bot walls
stay reachable — it is not a bypass for sites that have asked you not to crawl.
