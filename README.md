<div align="center">

# 🔍 Threat Research MCP

**Raw threat intel in → analyst-ready detection package out.**

An offline-first MCP server that chains IOC extraction, ATT&CK mapping, hunt queries, and Sigma rules into a single callable workflow — works with Claude Desktop, Cline, Cursor, Copilot, and any MCP-compatible client.

---

[![CI](https://github.com/harshthakur6293/threat-research-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/harshthakur6293/threat-research-mcp/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-3776ab?logo=python&logoColor=white)](https://www.python.org/downloads/)
[![Tests](https://img.shields.io/badge/tests-118%20passing-22c55e?logo=pytest&logoColor=white)](tests/)
[![Coverage](https://img.shields.io/badge/coverage-65%25-22c55e)](tests/)
[![License: MIT](https://img.shields.io/badge/license-MIT-f59e0b)](LICENSE)
[![MCP](https://img.shields.io/badge/MCP-stdio%20transport-8b5cf6)](https://modelcontextprotocol.io)
[![Tools](https://img.shields.io/badge/tools-46%20registered-0ea5e9)](src/threat_research_mcp/server.py)

[Quick Start](#quick-start) · [Pipeline](#the-pipeline) · [Demo](#demo) · [Tool Catalog](#tool-catalog) · [MCP Config](#mcp-client-configuration)

</div>

---

## The Pipeline

One call — `run_pipeline_tool` — chains all stages:

```
raw intel text  (paste report, IR note, blog post, anything)
       │
       ▼
   extract_iocs ──────────────────── IPv4s, domains, hashes, emails
       │                             confidence-scored, context-labelled
       │
       ▼
     map_ttp ────────────────────── ATT&CK technique IDs + evidence
       │                            confidence score per technique
       │                            suppressed list for analyst review
       │
       ├──▶ hunt_for_techniques ─── SPL / KQL / Elastic hunt queries
       │
       ├──▶ sigma_bundle ────────── curated Sigma rules (or community
       │                            search links for gaps — no fake rules)
       │
       ├──▶ navigator_layer ─────── ATT&CK Navigator JSON
       │                            drag into attack.mitre.org
       │
       └──▶ generate_threat_report ─ self-contained HTML report
                                     D3.js graph · heatmap · hunt cards
```

Each stage is also callable individually. The pipeline is the fast path.

---

## Demo

The `demo/` folder contains a pre-generated Sapphire Sleet (DPRK/BlueNoroff macOS) detection package — no API keys needed to browse it:

<p align="center">
  <img src="demo/demo.svg" alt="Threat Research MCP terminal demo" width="100%">
</p>

```
demo/sapphire_sleet_input.txt          ← raw threat intel text
demo/sapphire_sleet_pipeline.json      ← full pipeline output
demo/sapphire_sleet_report.html        ← open in browser (no server needed)
demo/sapphire_sleet_navigator_layer.json
demo/sapphire_sleet_sigma_bundle.yml
demo/sapphire_sleet_iocs.csv
```

The HTML report (`sapphire_sleet_report.html`) includes:

| Section | What you see |
|---|---|
| Summary strip | IOC count · technique count · hunt count · Sigma count |
| IOC table | Value · type · confidence · MALICIOUS / UNKNOWN / VICTIM label |
| ATT&CK heatmap | Tactic columns, technique tiles, confidence colour |
| D3 force graph | IOC → technique → tactic, click to drill down |
| Hunt cards | Per-technique hypothesis · SPL / KQL / Elastic tab switcher |
| Sigma cards | Curated YAML (expandable) · community rule links for gaps |

---

## Quick Start

### Install (local dev)

```bash
git clone https://github.com/harshthakur6293/threat-research-mcp
cd threat-research-mcp
python -m pip install -e ".[dev]"
python -m threat_research_mcp        # starts the MCP server on stdio
```

> **PyPI / uvx / npm not yet published.** The roadmap entry is `pip install threat-research-mcp` / `uvx threat-research-mcp`. For now, use the local install above.

### First run in Claude Desktop

```json
{
  "mcpServers": {
    "threat-research-mcp": {
      "command": "python",
      "args": ["-m", "threat_research_mcp"],
      "cwd": "/path/to/threat-research-mcp"
    }
  }
}
```

Then paste a threat report and ask:

```
Analyze this report and produce a detection package.
```

---

## MCP Client Configuration

The server uses **stdio transport** — no HTTP, no port, no auth. Works with any MCP-compatible client.

<details>
<summary><b>Claude Desktop</b> — <code>~/Library/Application Support/Claude/claude_desktop_config.json</code></summary>

```json
{
  "mcpServers": {
    "threat-research-mcp": {
      "command": "python",
      "args": ["-m", "threat_research_mcp"],
      "cwd": "/path/to/threat-research-mcp"
    }
  }
}
```
</details>

<details>
<summary><b>VS Code / Cline / Roo Code</b> — <code>.vscode/settings.json</code></summary>

```json
{
  "cline.mcpServers": {
    "threat-research-mcp": {
      "command": "python",
      "args": ["-m", "threat_research_mcp"],
      "cwd": "${workspaceFolder}/../threat-research-mcp"
    }
  }
}
```
</details>

<details>
<summary><b>Cursor</b> — <code>~/.cursor/mcp.json</code></summary>

```json
{
  "mcpServers": {
    "threat-research-mcp": {
      "command": "python",
      "args": ["-m", "threat_research_mcp"],
      "cwd": "/path/to/threat-research-mcp"
    }
  }
}
```
</details>

<details>
<summary><b>Any other MCP client</b></summary>

Use the same shape — `command`, `args`, `cwd`. The server communicates via stdio, so it fits any client that supports the MCP stdio transport spec.
</details>

---

## What Each Stage Produces

### IOC Extraction — `extract_iocs`

Context-aware extraction with a confidence score per indicator:

```json
{
  "ips":     [{"value": "185.220.101.47", "confidence": 0.92, "label": "MALICIOUS"}],
  "domains": [{"value": "cdn.apple-cdn.org", "confidence": 0.85, "label": "MALICIOUS"}],
  "hashes":  [{"value": "a3f8c2d1...", "confidence": 0.78, "label": "HASH"}],
  "emails":  [{"value": "hr@careers-talent.io", "confidence": 0.71, "label": "MALICIOUS"}],
  "filtered_fps": [{"value": "192.168.1.1", "reason": "RFC1918"}]
}
```

Filters automatically: RFC1918 IPs, loopback, version strings, macOS bundle IDs (`com.apple.*`), known-benign CDN/cloud domains.

Context patterns live in `playbook/ioc_context_patterns.yaml` — editable.

---

### ATT&CK Mapping — `map_ttp`

Maps text to techniques using a **284-keyword index** (loaded from `playbook/keywords.yaml`) with an evidence-based confidence model:

```json
{
  "techniques": [
    {
      "id": "T1059.002",
      "name": "AppleScript",
      "tactic": "execution",
      "evidence": ["osascript", "applescript"],
      "confidence": 0.82,
      "confidence_label": "HIGH"
    }
  ],
  "suppressed": [...]
}
```

| Confidence label | Score range | Meaning |
|---|---|---|
| HIGH | ≥ 0.75 | Multiple specific signals, treat as confirmed |
| MEDIUM | 0.55 – 0.75 | Credible, worth hunting |
| LOW | 0.35 – 0.55 | Weak signal, analyst review recommended |
| SUPPRESSED | < 0.35 | Returned in `suppressed[]`, not main list |

Scoring weights live in `playbook/confidence_weights.yaml` — tunable per deployment.

---

### Hunt Hypotheses — `hunt_for_techniques`

Returns one hypothesis per technique × log source combination, each with a ready-to-run query:

```json
{
  "hypothesis": "Attacker invoked osascript to execute in-memory payload",
  "technique_id": "T1059.002",
  "log_source": "edr_macos",
  "spl": "index=edr source=macos process_name=osascript ...",
  "kql": "DeviceProcessEvents | where FileName =~ 'osascript' ...",
  "elastic": "process.name: osascript AND ..."
}
```

---

### Sigma Rules — `sigma_bundle_for_techniques`

Returns **curated rules** for supported techniques. For unsupported techniques, returns a structured `no_curated_rule` response with direct search links to SigmaHQ, Elastic detection-rules, and Splunk Security Content — no plausible-looking garbage rules.

```json
{
  "technique_id": "T1059.001",
  "status": "curated",
  "rule_yaml": "title: PowerShell Download Cradle ..."
}
```

```json
{
  "technique_id": "T1190",
  "status": "no_curated_rule",
  "fallback": {
    "sigmahq_search": "https://github.com/SigmaHQ/sigma/search?q=T1190",
    "elastic_rules":  "https://github.com/elastic/detection-rules/search?q=T1190"
  }
}
```

---

### SIEM-Native Rules — `kql_for_technique` · `spl_for_technique` · `eql_for_technique`

Generates Sentinel Analytics Rules (KQL), Splunk Saved Searches (SPL), and Elastic/Kibana Detection Rules (EQL/ES|QL) for the 20 techniques in the hunt playbook. Returns rule definitions with severity, schedule, entity mappings, and drilldown templates.

---

### ATT&CK Navigator Layer — `navigator_layer`

Produces a drag-and-drop layer JSON for [attack.mitre.org/navigator](https://mitre-attack.github.io/attack-navigator/). Techniques are scored by evidence count — produces an instant heatmap from any pipeline run.

---

### Interactive HTML Report — `generate_threat_report`

One call generates a self-contained browser-ready report from pipeline JSON. No server, no CDN dependencies.

---

## Tool Catalog

46 registered MCP tools total.

### Primary Workflow

| Tool | What it does |
|---|---|
| `run_pipeline_tool` | Full pipeline: text → IOCs → ATT&CK → hunts → Sigma |
| `extract_iocs` | Context-aware IOC extraction with confidence |
| `map_ttp` | ATT&CK technique mapping with evidence + confidence |
| `hunt_from_intel` | Hunt hypotheses from raw text |
| `hunt_for_techniques` | Hunt hypotheses for specific technique IDs |
| `list_log_sources_tool` | List available log source keys for filtering |
| `generate_threat_report` | Self-contained HTML report from pipeline JSON |
| `navigator_layer` | ATT&CK Navigator layer JSON |

### Sigma and Detection Drafts

| Tool | What it does |
|---|---|
| `generate_sigma_rule` | Build Sigma from title + behavior description |
| `sigma_for_technique` | Curated Sigma or `no_curated_rule` for a technique |
| `sigma_bundle_for_techniques` | Batch Sigma for multiple techniques |
| `validate_sigma_rule` | Offline structure validation (no CLI needed) |
| `score_sigma` | Score specificity, coverage, FP risk |
| `score_technique_sigma` | Score a built-in curated rule |
| `kql_for_technique` | Microsoft Sentinel KQL |
| `spl_for_technique` | Splunk SPL |
| `eql_for_technique` | Elastic EQL |
| `yara_for_technique` | YARA file-scanning rules |
| `generate_yara` | Custom YARA from string patterns |
| `ioc_sigma_bundle` | IOC blocklist Sigma bundle with TTL guidance |
| `detection_coverage_gap` | Gap analysis: tracked techniques vs existing detections |
| `atomic_tests_for_technique` | Atomic Red Team test IDs for validation |

### IOC Enrichment (optional, requires API keys)

| Tool | What it does |
|---|---|
| `enrich_ioc_tool` | Single IOC: VT / OTX / AbuseIPDB / URLhaus |
| `enrich_iocs_tool` | Bulk enrich comma-separated IOCs (capped at 20) |

### Intake and Parsing

| Tool | What it does |
|---|---|
| `ingest_feed` | TAXII 2.1, RSS/Atom, HTML, local file ingestion |
| `analyze_intel` | Pipeline on text + ingested feed docs |
| `parse_stix` | Parse STIX 2.x bundle JSON |
| `stix_to_text` | Flatten STIX to pipeline-ready text |
| `timeline` | Sort log lines/event notes chronologically |

### MISP Integration (optional, requires `MISP_URL` + `MISP_KEY`)

| Tool | What it does |
|---|---|
| `misp_pull` | Pull events, returns IOCs + pipeline-ready text |
| `misp_push_sigma` | Push Sigma rule as attribute to a MISP event |
| `misp_create_event` | Create MISP event from pipeline output |

### Campaign Tracking

| Tool | What it does |
|---|---|
| `campaign_update` | Store/update campaign state (JSON, file-based) |
| `campaign_get` | Retrieve campaign state |
| `campaign_list` | List all tracked campaigns |
| `campaign_correlate_ioc` | Find campaigns sharing an IOC |

### Storage and Search

| Tool | What it does |
|---|---|
| `search_intel_history` | Search stored analysis products (SQLite) |
| `get_intel_by_id` | Retrieve stored product by row ID |
| `search_ingested_docs` | Search ingested document store |

### Local ATT&CK Database (optional — requires `python scripts/build_attack_db.py`)

| Tool | What it does |
|---|---|
| `attack_get_technique` | Full technique card: platforms, data sources, detection |
| `attack_get_threat_groups` | Groups known to use a technique |
| `attack_get_techniques_by_group` | Techniques attributed to a group |
| `attack_attribute_to_group` | Rank groups by technique overlap (Jaccard similarity) |
| `attack_get_data_sources` | Map ATT&CK data sources to SIEM log sources |
| `attack_get_mitigations` | ATT&CK recommended mitigations |

Build the database once:

```bash
python scripts/build_attack_db.py
# → playbook/attack.db (~30 MB, ~600 techniques, ~130 groups)
```

---

## Multi-MCP Workflow

This server is designed to be the **workflow layer** — pair it with specialist MCPs for the deepest results:

```mermaid
flowchart LR
    Client(["Agentic Client\nClaude · Cursor · Cline · Copilot"])

    TR["🔍 threat-research-mcp\nintel → hunts → detections → report"]
    MITRE["📚 mitre-attack-mcp\ntechnique · group · mitigation context"]
    DET["🛡️ security-detections-mcp\n8,200+ community rules"]
    SIEM(["SIEM\nSentinel · Splunk · Elastic"])

    Client --> TR
    Client --> MITRE
    Client --> DET
    TR --> SIEM
    MITRE --> TR
    DET --> TR
```

```json
{
  "mcpServers": {
    "threat-research-mcp": {
      "command": "python",
      "args": ["-m", "threat_research_mcp"],
      "cwd": "/path/to/threat-research-mcp"
    },
    "mitre-attack": { "command": "npx", "args": ["-y", "mitre-attack-mcp"] },
    "security-detections": { "command": "npx", "args": ["-y", "security-detections-mcp"] }
  }
}
```

MCP servers don't call each other — your agentic client orchestrates the workflow:

```
1. threat-research-mcp  → run_pipeline_tool(text=<report>)
2. mitre-attack-mcp     → get_technique for each mapped technique
3. security-detections  → list_by_mitre for each technique
4. threat-research-mcp  → sigma_for_technique for gaps only
5. threat-research-mcp  → generate_threat_report
```

---

## Playbook Files

Everything tunable lives in `playbook/` — no code change needed:

| File | Controls |
|---|---|
| `keywords.yaml` | Keyword → ATT&CK technique mapping (284 entries, single source of truth) |
| `confidence_weights.yaml` | Confidence model dimensions, thresholds, specificity tiers |
| `ioc_context_patterns.yaml` | IOC context scoring patterns (malicious / victim / researcher) |
| `atomic_tests.yaml` | Atomic Red Team test ID mapping per technique |
| `siems/` | SIEM field profiles for KQL / SPL / EQL generation |

To add ATT&CK keyword mappings:

```yaml
# playbook/keywords.yaml
entries:
  - keyword: "your-new-keyword"
    tactic: initial-access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
```

Restart the server. No Python changes needed.

---

## Operator Profile

Copy and edit the example:

```bash
cp operator.yaml.example operator.yaml
```

Tells the server what your SOC actually has — primary SIEM, log sources, platform, confidence threshold. Without `operator.yaml`, safe defaults are used and everything works out of the box.

---

## Honest Limitations

| Limitation | Detail |
|---|---|
| **Sigma coverage** | Curated rules exist for ~16 techniques. Others return `no_curated_rule` + community links. No fake rules. |
| **ATT&CK DB** | The 6 `attack_*` lookup tools need `python scripts/build_attack_db.py` run once. They return a structured error until then. |
| **IOC enrichment** | Requires optional API keys (`VIRUSTOTAL_API_KEY`, `OTX_API_KEY`, `ABUSEIPDB_API_KEY`). The core pipeline works with zero keys. |
| **Detection drafts** | Generated KQL/SPL/EQL/YARA are analyst starting points. Review and tune before deploying to production. |
| **PyPI/uvx** | Not published yet. Local install via `pip install -e .` works today. |
| **Campaign tracking** | JSON file-based. Useful for single analyst or shared-git workflows; not a full relational campaign DB. |

---

## Development

```bash
python -m pip install -e ".[dev]"

# Equivalent to CI:
python -m ruff check .
python -m ruff format --check .
python -m pytest -q --cov=src/threat_research_mcp --cov-fail-under=65
python -m bandit -c pyproject.toml -r src
python -m pip_audit --cache-dir .pip-audit-cache
```

Current local status:

```
118 passed, 5 skipped
coverage: 65%
ruff: pass · bandit: pass · pip-audit: pass
```

---

## Repository Layout

```
src/threat_research_mcp/
  server.py               MCP tool registration (46 tools)
  tools/
    run_pipeline.py       end-to-end pipeline orchestrator
    extract_iocs.py       context-aware IOC extraction
    map_attack.py         ATT&CK mapping (loads from keywords.yaml)
    generate_html_report.py  D3.js HTML report generator
    generate_sigma.py     curated Sigma wrapper
    generate_ioc_sigma.py IOC blocklist Sigma bundle
    generate_detections.py   KQL / SPL / EQL / YARA helpers
    navigator_export.py   ATT&CK Navigator layer export
    score_sigma.py        Sigma quality scoring
    attack_lookup.py      optional local ATT&CK SQLite lookup
    campaign_tracker.py   JSON campaign state
    misp_bridge.py        MISP integration

playbook/
  keywords.yaml           ATT&CK keyword index (single source of truth)
  confidence_weights.yaml confidence model + thresholds
  ioc_context_patterns.yaml  IOC context scoring
  atomic_tests.yaml       Atomic Red Team mapping
  siems/                  SIEM field profiles

demo/
  sapphire_sleet_*        pre-generated DPRK macOS detection package

scripts/
  build_attack_db.py      build local ATT&CK SQLite from MITRE STIX
```

---

## Contributing

Contributions are welcome in any of these areas:

- **`playbook/keywords.yaml`** — new ATT&CK keyword mappings
- **`playbook/`** — SIEM profiles, context patterns, atomic test mappings
- **Curated Sigma rules** — new technique coverage in the detection generators
- **Eval cases** — threat reports with expected IOC/technique outputs for regression testing

---

## License

MIT
