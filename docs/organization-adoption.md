# Organization adoption

## Who this is for

Security teams, CTI, detection engineering, IR, and threat hunting functions that want a **defensive, MCP-native** way to go from **intel → hunt ideas → detection drafts**, with optional ingestion from files, feeds, HTML, and TAXII/STIX—without committing to a single commercial platform.

**Hands-on guide (another org, OTX/Anomali/VT patterns, Cursor install):** [`using-as-a-security-engineer.md`](using-as-a-security-engineer.md).

## Fast path (internal trial)

1. Clone the repo and install: `pip install -e .[dev]`
2. Run CLI workflows on your own sample text and compare outputs to your standards
3. Enable the MCP server in your client (`python -m threat_research_mcp.server`)
4. Add **optional** specialist MCPs in the same client when you need depth (see below)

## Composition with other open-source MCP servers (recommended)

**threat-research-mcp** is designed as the **workflow + ingestion + orchestration** core. Many organizations will also enable peer MCPs:

| Need | Typical peer MCP |
|------|-------------------|
| Full ATT&CK DB, Navigator layers, group gaps | [mitre-attack-mcp](https://github.com/MHaggis/mitre-attack-mcp) |
| Large detection corpora & coverage depth | [Security-Detections-MCP](https://github.com/MHaggis/Security-Detections-MCP) |
| TTP-first hunt frameworks & hunt ops | [threat-hunting-mcp-server](https://github.com/THORCollective/threat-hunting-mcp-server) |
| IOC enrichment (VT, OTX, …) | [fastmcp-threatintel](https://github.com/4R9UN/fastmcp-threatintel) |

**Operational model:** configure all desired servers in your MCP host. Use playbooks (“first extract IOCs here, then enrich there”) in prompts or internal docs. See `configs/external_mcps.example.yaml` for a template runbook.

**Future model:** optional in-process “bridge” modules could call other MCPs or HTTP APIs—only when explicitly configured and reviewed for your threat model.

## Deployment tiers (conceptual)

1. **Starter** — local CLI + MCP stdio, SQLite optional, no external MCPs.
2. **Team** — shared MCP host config, ingestion sources YAML, audit of which tools are enabled.
3. **Program** — optional bridges to CTI/graph systems (`integrations/*`), retention and governance per `docs/governance.md`.

## Governance

Treat all model-assisted outputs as **draft analyst work**. Human review for production detection rules and hunt actions. See `docs/safety-model.md` and `SECURITY.md`.
