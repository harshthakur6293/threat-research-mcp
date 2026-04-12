# Roadmap

This document outlines planned features and maps scaffolded code directories to future release versions.

## v0.2.0 (Current Release)

**Status:** Production-ready

**Features:**
- 4-agent orchestration (research, hunting, detection, review)
- Intel ingestion from RSS, HTML, STIX, TAXII, local files
- 15 MCP tools for IOC extraction, analysis, validation, history search
- `AnalysisProduct` JSON schema for structured incident handoffs
- Optional SQLite persistence (workflow runs, ingested documents, analysis products)
- Cross-SIEM detection drafts (Sigma, KQL, SPL) with ATT&CK technique mapping
- Defensive policy enforcement

**Code modules:**
- `agents/` - Agent implementations
- `orchestrator/` - Workflow routing, state, policy
- `ingestion/` - Source adapters and normalization
- `tools/` - MCP tool implementations
- `schemas/` - Pydantic models
- `storage/sqlite.py` - Persistence layer
- `detection/` - Cross-SIEM draft generation
- `utils/` - Helper functions
- `extensions/` - External MCP catalog

## v0.3 (Next Release)

**Focus:** Depth integrations and search

**Planned features:**
- Direct CTI platform integrations (MISP, OpenCTI, Synapse)
- Semantic search over normalized intel corpus
- Structured observability (logging, metrics, tracing)
- Advanced storage repositories with rich query interfaces
- Static knowledge resources (MITRE reference, Sigma style guides, analyst playbooks)

**Scaffolded code (to be implemented):**
- `integrations/misp/` - MISP client and mapper
- `integrations/opencti/` - OpenCTI client and mapper
- `integrations/synapse/` - Synapse client, mapper, Storm queries, ingestion bridge
- `retrieval/` - Semantic search, ranking, hybrid retrieval
- `observability/` - Logging, metrics, tracing helpers
- `storage/repositories/` - Specialized repositories (documents, sources, detections)
- `resources/` - Static knowledge bases (MITRE, Sigma, playbooks)

**Target timeline:** Q3 2026

## v0.4 (Future)

**Focus:** Graph intelligence and multi-tenancy

**Planned features:**
- Graph-based CTI relationship reasoning
- Entity resolution and threat actor attribution
- Campaign clustering and timeline reconstruction
- Multi-tenant workspace isolation
- Session memory and conversation continuity
- Neo4j integration for graph storage

**Scaffolded code (to be implemented):**
- `graph/entities.py` - CTI entity models
- `graph/ontology.py` - Relationship ontology
- `graph/relationships.py` - Graph reasoning
- `integrations/neo4j/` - Neo4j client, queries, schema
- `tenancy/` - Workspace isolation helpers
- `memory/` - Context retention and session memory
- `storage/repositories/sessions.py` - Session tracking
- `storage/repositories/artifacts.py` - Artifact management

**Target timeline:** Q1 2027

## v0.5+ (Exploratory)

**Focus:** Extensibility and advanced workflows

**Potential features:**
- LLM provider abstraction for pluggable backends
- Extensible policy engine with rule-based framework
- Hunt campaign management and hypothesis tracking
- Coverage analysis with ATT&CK Navigator integration
- Advanced detection engineering workflows

**Scaffolded code (to be implemented):**
- `providers/` - LLM provider abstraction
- `policy/` - Advanced policy engine (beyond basic defensive checks)
- `hunt/` - Hunt campaign management (beyond basic generation)
- `coverage/` - Detection coverage analysis (beyond primitives)
- `storage/repositories/hunts.py` - Hunt tracking
- `storage/repositories/coverage.py` - Coverage tracking

**Target timeline:** TBD based on community feedback

## Contributing to Roadmap Items

Interested in implementing a roadmap feature? Here's how to get started:

1. **Check the scaffolded code** - Most future features have placeholder modules that show the intended structure
2. **Review the specs** - See [`security-agent-mcp-cursor-handoff.md`](../security-agent-mcp-cursor-handoff.md) for architectural vision
3. **Open an issue** - Discuss your implementation approach before starting work
4. **Start small** - Consider implementing a subset of the planned feature first
5. **Add tests** - All new features require test coverage

## Feedback

Have ideas for the roadmap? Open an issue with the `roadmap` label to discuss:
- Feature priorities
- New capabilities not listed here
- Changes to the planned architecture
- Integration requests for additional CTI platforms

## Version Philosophy

- **v0.2:** Core workflow proven and stable
- **v0.3:** Depth integrations for production use
- **v0.4:** Intelligence features (graph, memory, multi-tenancy)
- **v0.5+:** Extensibility and advanced workflows

Each version builds on the previous foundation while maintaining backward compatibility for core workflows and schemas.
