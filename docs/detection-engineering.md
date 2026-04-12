# Detection Engineering

The detection subsystem turns behavior descriptions into detection artifacts.

## v1 focus
- Sigma draft generation (safe quoting; optional **`validate_sigma`** MCP tool / `tools.validate_sigma`)
- **KQL** and **SPL** draft queries from the same behavior + parsed MITRE technique IDs (`detection/cross_siem_drafts.py`)
- **MITRE data source hints** for common techniques (`detection/technique_data_sources.py`) → `DetectionRuleArtifact.data_source_recommendations`
- Detection idea generation
- Reviewer validation notes

Templates are stored under src/threat_research_mcp/detection/rule_templates.
