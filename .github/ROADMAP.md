# Roadmap

This document outlines planned features and maps scaffolded code directories to future release versions.

## v0.4.0 (Current Release)

**Status:** Production-ready

**Features:**
- 4-agent orchestration (research, hunting, detection, review)
- Intel ingestion from RSS, HTML, STIX, TAXII, local files
- 19 MCP tools for IOC extraction, analysis, validation, history search
- `AnalysisProduct` JSON schema for structured incident handoffs
- Optional SQLite persistence (workflow runs, ingested documents, analysis products)
- Cross-SIEM detection drafts (Sigma, KQL, SPL) with ATT&CK technique mapping
- Defensive policy enforcement
- **Threat Actor Testing Framework** - 6 realistic APT/UNC profiles with 100+ techniques
- **Log Source Recommendations** - Specific log sources for 20+ techniques across cloud/endpoint/network
- **Optional MCP Integrations** - Chain with 4 specialist MCPs (fastmcp-threatintel, Security-Detections-MCP, threat-hunting-mcp, splunk-mcp)
- **100 Passing Tests** - Comprehensive test coverage including 29 threat actor scenario tests

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

## v0.5.0 (Next Release - Graph Intelligence)

**Focus:** Graph-based threat intelligence and relationship reasoning

**Planned features:**
- **Graph Data Model** - NetworkX-based graph for CTI entities and relationships
- **Threat Actor Attribution** - Probabilistic attribution using IOC/technique overlap
- **Attack Chain Prediction** - Predict next techniques based on historical sequences
- **Campaign Tracking** - Link IOCs to campaigns via graph traversal
- **Detection Gap Analysis** - Identify techniques lacking detection coverage
- **Graph Visualization** - Mermaid and interactive D3.js visualizations
- **Optional Neo4j Connector** - Enterprise-scale graph database support

**New MCP Tools:**
- `attribute_threat_actor` - Probabilistic threat actor attribution
- `predict_next_techniques` - Attack chain prediction
- `find_related_campaigns` - Campaign discovery via graph traversal
- `find_detection_gaps` - Coverage gap analysis
- `visualize_threat_landscape` - Generate Mermaid graph visualizations

**Implementation:**
- `graph/manager.py` - Core graph engine (NetworkX)
- `graph/entities.py` - Entity models (ThreatActor, Campaign, IOC, Technique)
- `graph/builder.py` - Auto-populate graph from analysis products
- `graph/visualization.py` - Mermaid and D3.js export
- `integrations/neo4j/` - Optional Neo4j connector for enterprise
- `tools/graph_tools.py` - 5 new graph-powered MCP tools
- `scripts/build_threat_graph.py` - Initialize graph from threat actor profiles

**Documentation:**
- `docs/GRAPH-FEATURE-PLAN.md` - Complete implementation plan
- `docs/GRAPH-QUICK-VISUAL.md` - Visual quick reference with examples

**Target timeline:** Q2 2026

**Success Metrics:**
- 500+ nodes, 2000+ edges in initial graph
- >80% attribution accuracy on known APT scenarios
- >70% prediction accuracy for next-technique
- <100ms for 2-hop graph queries

## v0.6.0 (Future - Advanced Intelligence)

**Focus:** Machine learning and temporal analysis

**Planned features:**
- **Campaign Clustering** - ML-based campaign identification from IOC/technique patterns
- **Temporal Analysis** - Technique evolution and trend analysis over time
- **Similarity Scoring** - Actor-to-actor and campaign-to-campaign similarity
- **Automated Graph Updates** - Real-time graph updates from new intelligence
- **Entity Resolution** - Deduplicate and merge related entities
- **Multi-tenant Workspace Isolation** - Enterprise workspace separation
- **Session Memory** - Conversation continuity and context retention

**Scaffolded code (to be implemented):**
- `graph/ml.py` - ML-based clustering and similarity
- `graph/temporal.py` - Time-series analysis
- `graph/entity_resolution.py` - Entity deduplication
- `tenancy/` - Workspace isolation helpers
- `memory/` - Context retention and session memory
- `storage/repositories/sessions.py` - Session tracking
- `storage/repositories/artifacts.py` - Artifact management

**Target timeline:** Q3 2026

## v0.7.0+ (Exploratory - Integrations & Extensibility)

**Focus:** CTI platform integrations and extensibility

**Potential features:**
- **Direct CTI Platform Integrations** - MISP, OpenCTI, Synapse connectors
- **Semantic Search** - Search over normalized intel corpus
- **LLM Provider Abstraction** - Pluggable LLM backends
- **Extensible Policy Engine** - Rule-based framework
- **Hunt Campaign Management** - Hypothesis tracking
- **Coverage Analysis** - ATT&CK Navigator integration
- **Advanced Detection Engineering** - Multi-stage detection workflows

**Scaffolded code (to be implemented):**
- `integrations/misp/` - MISP client and mapper
- `integrations/opencti/` - OpenCTI client and mapper
- `integrations/synapse/` - Synapse client, mapper, Storm queries
- `retrieval/` - Semantic search, ranking, hybrid retrieval
- `providers/` - LLM provider abstraction
- `policy/` - Advanced policy engine
- `hunt/` - Hunt campaign management
- `coverage/` - Detection coverage analysis
- `observability/` - Logging, metrics, tracing helpers

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

- **v0.4:** Core workflow + threat actor testing (CURRENT)
- **v0.5:** Graph-based intelligence and relationship reasoning (NEXT)
- **v0.6:** Advanced intelligence (ML, temporal analysis)
- **v0.7+:** CTI platform integrations and extensibility

Each version builds on the previous foundation while maintaining backward compatibility for core workflows and schemas.

## Quick Links

- **Current Release:** [v0.4.0 Features](#v040-current-release)
- **Next Release:** [v0.5.0 Graph Intelligence Plan](../docs/GRAPH-FEATURE-PLAN.md)
- **Visual Guide:** [Graph Features Quick Reference](../docs/GRAPH-QUICK-VISUAL.md)
