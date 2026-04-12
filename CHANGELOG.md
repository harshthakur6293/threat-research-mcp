# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

- **SQLite**: `normalized_documents` and `analysis_products` tables (append-only) when `THREAT_RESEARCH_MCP_DB` is set; MCP search tools `search_ingested_intel`, `search_analysis_product_history`, `get_stored_analysis_product`; ingestion provenance merged before workflow persistence when sources are used.
- Planned: optional export/sync to Neo4j / Synapse (see `integrations/*` placeholders).

**Release tagging:** after updating this file and `pyproject.toml`, create a tag, e.g. `git tag -a v0.2.0 -m "Release 0.2.0"` and push tags when publishing to GitHub.

## [0.2.0] — 2026-04-11

### Added

- **Ingestion pipeline**: `local_file`, RSS/Atom, HTML, STIX bundles, TAXII 2.1; `IngestionManager`, YAML/JSON configs (`configs/sources.example.yaml`).
- **MCP tools**: `ingest_sources`, `intel_to_analysis_product`, `analysis_product` (canonical `AnalysisProduct` JSON), `validate_sigma`.
- **CLI**: `--sources` to merge YAML/JSON sources with `--text` before workflow.
- **Canonical schemas**: `AnalysisProduct`, IOC discriminated union, hunt/delivery and detection bundles (`docs/canonical-schemas.md`).
- **Cross-SIEM drafts**: KQL + SPL drafts and MITRE-style `data_source_recommendations` from an offline technique table; `run_detection(text, research)`.
- **Extensions catalog** for optional peer MCPs (`src/threat_research_mcp/extensions/`, `configs/external_mcps.example.yaml`).
- **Docs**: architecture, organization adoption, ingestion, tool contracts, detection engineering updates.

### Changed

- `generate_sigma` uses safer quoting and `falsepositives` stub line.
- Workflow JSON responses include `analysis_product` for downstream consumers.

## [0.1.0]

- Initial project scaffold: core tools, agents, orchestrator, CI, security, and build workflows.
