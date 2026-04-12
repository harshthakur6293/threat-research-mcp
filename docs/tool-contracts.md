# Tool Contracts

Tools are exposed via MCP and should keep stable, clear I/O contracts.

## Granular tools

- `extract_iocs`
- `summarize`
- `attack_map`
- `hunt`
- `sigma`
- `coverage`

Prefer structured JSON-like outputs where possible.

## Canonical bundle

- **`analysis_product`** — Input: `text`, optional `workflow` (default `threat_research`). Output: JSON matching **`AnalysisProduct`** (`docs/canonical-schemas.md`, `schema_version` **1.0**). Same workflow as the CLI; returns only the canonical object (not the legacy `research` / `detection` dicts).

- **`ingest_sources`** — Input: `config_path` to `.yaml` / `.yml` / `.json` sources list. Output: `{ "count", "documents" }` JSON.

- **`intel_to_analysis_product`** — Inputs: optional `text`, optional `sources_config_path`, optional `workflow`. Merges bodies from ingestion with analyst text, runs workflow, returns **`AnalysisProduct`** JSON; `provenance` includes ingested documents when `sources_config_path` is set.

The full workflow JSON from the CLI also embeds **`analysis_product`** alongside legacy keys for backward compatibility. With **`--sources PATH`**, the CLI merges the same way and prints the full JSON payload (including merged `analysis_product.provenance`).

- **`validate_sigma`** — Input: Sigma YAML string. Output: JSON `{ "valid": bool, "errors": string[] }` (required fields: `title`, `logsource`, `detection` with `condition` and `selection` or `selection_*`).
