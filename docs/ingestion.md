# Ingestion

Adapter-based pipeline: **fetch → parse → normalize → dedupe** (`src/threat_research_mcp/ingestion`).

## Supported source types

| `type` | Purpose | Required fields | Notes |
|--------|---------|-----------------|--------|
| `local_file` | Text, HTML, or STIX JSON on disk | `path` (file or directory) | Directory uses `pattern` (glob, default `*`). `.json` is parsed as STIX when possible; otherwise stored as raw JSON. |
| `rss` / `rss_atom` | RSS 2.0 or Atom feed | `url` | HTTP GET; Basic auth or API key via `SourceConfig`. |
| `html_report` / `html` | Single HTML page | `url` **or** `path` (not both) | Strips scripts/styles; extracts `<title>` and body text. |
| `stix_bundle` / `stix` | STIX 2.x bundle file | `path` | One file; extracts report/indicator/malware/etc. into separate normalized docs. |
| `taxii` / `taxii2` | TAXII 2.1 collection objects | `api_root` | Optional `collection_id`; if omitted and multiple collections exist, configure `collection_id` explicitly. Supports pagination via `next`. Uses `Accept: application/taxii+json;version=2.1`. |

Shared optional fields on every source: `username`, `password`, `api_key`, `api_key_header`, `api_key_prefix`, `timeout_seconds`, `source_trust`.

## Python API

```python
from threat_research_mcp.ingestion import IngestionManager, sources_from_dict

sources = sources_from_dict({
    "sources": [
        {"name": "notes", "type": "local_file", "path": "./reports", "pattern": "*.md"},
    ]
})
docs = IngestionManager(sources).run(skip_duplicates=True)
for d in docs:
    print(d.title, d.fingerprint[:16], d.normalized_text[:120])
```

YAML config:

```python
from threat_research_mcp.ingestion import IngestionManager, load_sources_yaml

sources = load_sources_yaml("configs/sources.example.yaml")
docs = IngestionManager(sources).run()
```

JSON config: same shape as the `sources` list or `{"sources": [...]}` — use `load_sources_json`.

## Fingerprints

`NormalizedDocument.fingerprint` is SHA-256 of `source_name`, `title`, and normalized body (prefix). The `Deduper` inside `IngestionManager` skips already-seen fingerprints within the manager instance.

## MCP tools

- **`ingest_sources(config_path)`** — runs `IngestionManager` on a `.yaml` / `.yml` / `.json` file and returns `{ "count", "documents" }` as JSON strings (each document matches `NormalizedDocument`).
- **`intel_to_analysis_product(text?, sources_config_path?, workflow?)`** — merges analyst text with ingested bodies, runs the orchestrator, returns **`AnalysisProduct`** JSON only; extends `provenance` with one row per ingested document.

## Errors

Failures (HTTP, parse, missing fields) raise `IngestionError` with a short message suitable for logging or MCP tool responses.
