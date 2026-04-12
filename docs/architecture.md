# Architecture

## Product intent (GitHub / multi-tenant mindset)

**threat-research-mcp** is meant to ship as an **open-source defensive platform**: take intel in, run **structured workflows** from research through hunt hypotheses into detection drafts, with **policy, review, and optional persistence**—usable by individuals, labs, and organizations without locking them into one vendor stack.

The codebase is layered so that:

- **Defaults work locally** (stdlib + SQLite paths, no paid APIs required for the core loop).
- **Depth is composable**: organizations can add **other MCP servers** (or HTTP services) where this project intentionally stays thinner (full ATT&CK DB, huge detection corpora, hunt frameworks, IOC reputation APIs).

## Layered design

1. **MCP tools layer** (`tools/`) — stable tool contracts (`extract_iocs`, `summarize`, …).
2. **Agent layer** (`agents/`) — research, hunting, detection, reviewer roles over tools.
3. **Orchestrator** (`orchestrator/`) — routing, policy, workflow state, formatting.
4. **Ingestion** (`ingestion/`) — adapters (local, RSS, HTML, STIX bundle, TAXII 2.1), normalize, dedupe.
5. **Memory + storage** (`memory/`, `storage/`) — session/project persistence (evolving).
6. **Integrations** (`integrations/*`) — optional CTI/graph backends (placeholders today).
7. **Extensions catalog** (`extensions/`) — **documentation-first** registry of optional OSS MCPs that pair with this repo; future home for optional in-process MCP clients.

Orchestration stays separate from tool contracts so adopters can swap providers or add bridges without rewriting the whole server.

## Implementation Status (v0.2.0)

### Production-Ready (Current Release)

These modules are fully implemented and tested:

- **Agents** (`agents/`) — Research, hunting, detection, review orchestration (4 agents)
- **Ingestion** (`ingestion/`) — RSS, HTML, STIX, TAXII, local file adapters with normalization and deduplication
- **Tools** (`tools/`) — 15 MCP tools for IOC extraction, analysis, validation, and history search
- **Orchestrator** (`orchestrator/`) — Workflow routing, state management, policy checks, analysis product builder
- **Schemas** (`schemas/`) — Pydantic models for IOCs, ATT&CK, hunts, detections, AnalysisProduct
- **Storage** (`storage/sqlite.py`) — Optional SQLite persistence for workflow runs, ingested documents, and analysis products
- **Detection** (`detection/`) — Cross-SIEM draft generation (Sigma, KQL, SPL) with technique data source mapping
- **Utils** (`utils/`) — Text processing, YAML parsing, hashing, validation helpers
- **Extensions** (`extensions/`) — External MCP catalog for documenting peer servers

### Scaffolded for Future Versions

These directories contain placeholder code or minimal scaffolds intended for future development:

- **Integrations** (`integrations/`) — MISP, OpenCTI, Synapse, Neo4j bridges (v0.3+)
  - Currently: placeholder clients and mappers
  - Future: direct API integration for CTI platform synchronization
- **Graph Models** (`graph/`) — CTI relationship reasoning and entity resolution (v0.4+)
  - Currently: placeholder entities, ontology, relationships modules
  - Future: graph-based threat actor attribution and campaign clustering
- **Retrieval** (`retrieval/`) — Semantic search and hybrid ranking for intel corpus (v0.3+)
  - Currently: scaffold with `get_*_status()` stubs
  - Future: vector search over normalized documents for context-aware hunt suggestions
- **Observability** (`observability/`) — Structured logging, metrics, tracing (v0.3+)
  - Currently: empty module
  - Future: OpenTelemetry integration for production deployments
- **Multi-tenancy** (`tenancy/`) — Workspace isolation for shared deployments (v0.4+)
  - Currently: placeholder isolation helpers
  - Future: per-workspace ingestion, storage, and policy boundaries
- **Providers** (`providers/`) — LLM provider abstraction (v0.5+)
  - Currently: empty module
  - Future: pluggable LLM backends for agent reasoning
- **Advanced Storage** (`storage/repositories/`) — Specialized repositories (v0.3+)
  - Currently: scaffold modules for hunts, coverage, sessions, artifacts
  - Future: rich query interfaces and relationship tracking
- **Memory** (`memory/`) — Context retention helpers (v0.4+)
  - Currently: empty module
  - Future: session memory and conversation continuity
- **Resources** (`resources/`) — Static knowledge bases (v0.3+)
  - Currently: placeholder files for MITRE reference, Sigma style guides, analyst playbooks
  - Future: embedded reference data for offline operation
- **Policy** (`policy/`) — Advanced policy engine (v0.3+)
  - Currently: basic defensive policy in `orchestrator/policy.py`
  - Future: extensible rule-based policy framework
- **Coverage** (`coverage/`) — Detection coverage analysis (v0.3+)
  - Currently: basic primitives in tools
  - Future: ATT&CK Navigator integration and gap analysis workflows
- **Hunt** (`hunt/`) — Hunt framework helpers (v0.3+)
  - Currently: basic hunt generation in `agents/hunting_agent.py`
  - Future: hunt campaign management and hypothesis tracking

**For v0.2 adopters:** Focus on the "Production-Ready" modules listed above. Scaffolded directories are architectural placeholders and are not required for current functionality. See `.github/ROADMAP.md` for planned implementation timeline.

## Lifecycle: intel → hunt → detections

```text
Sources (files, RSS, HTML, TAXII/STIX, …)
        → IngestionManager (normalize + fingerprint)
        → WorkflowState + agents
        → outputs: IOCs, summaries, ATT&CK hints, hunt artifacts, Sigma drafts, coverage hints, review
```

Organizations may stop after **research**, or run full **threat_research** / **hunt_generation** / **detection_generation** workflows depending on `router` + config.

## Optional external MCP composition (recommended model)

**Host-level composition (default for consumers)**  
Register **threat-research-mcp** together with specialist MCPs in the same client (e.g. Cursor). The assistant sequences calls: e.g. `extract_iocs` / workflows here, then **mitre-attack-mcp** for technique detail, **security-detections-mcp** for rule coverage, **fastmcp-threatintel** for enrichment.

- **Pros:** no subprocess coupling, each server upgrades independently, clearest security boundary.
- **Cons:** orchestration is *assistant-driven* unless you document playbooks.

**Embedded bridges (future, explicit scope)**  
This process could implement an MCP **client** to call other servers or HTTP proxies. That belongs behind **explicit config**, timeouts, and org security review—not implicit magic.

Catalog and URLs for the OSS community servers we align with live in:

- `src/threat_research_mcp/extensions/external_mcp_catalog.py`
- `configs/external_mcps.example.yaml` (runbook / template)

## What this repo deliberately does *not* bundle

To stay maintainable and license-friendly as a GitHub project:

- Full MITRE STIX mirror as a database (use **mitre-attack-mcp** or local STIX + ingestion).
- Multi-thousand-rule SIEM corpora (use **security-detections-mcp** or your own path indexes).
- Paid TI API keys (use **fastmcp-threatintel** or org secrets + a thin adapter later).

Those are **peers**, not requirements, unless you choose to integrate them at the host or via future bridges.

## Extension points (for contributors)

| Area | How to extend |
|------|----------------|
| Ingestion | New `IntelAdapter` + `register_adapter()` in `ingestion/registry.py`. |
| Tools | New MCP tool in `server.py` + implementation under `tools/`. |
| Workflows | New routed name in `orchestrator/router.py` + agent wiring. |
| External MCPs | Today: document + host config. Tomorrow: optional bridge module under `extensions/` or `integrations/` with tests. |

## Safety

Defensive-only posture is enforced in orchestrator policy and documented in `docs/safety-model.md`. External MCPs carry their own terms; operators must authorize their use in their environment.
