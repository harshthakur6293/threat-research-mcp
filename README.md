# Threat Research MCP

[![CI](https://github.com/harshthakur6293/threat-research-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/harshthakur6293/threat-research-mcp/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://img.shields.io/badge/tests-104%20passing-brightgreen.svg)]()
[![Coverage](https://img.shields.io/badge/coverage-68%25-green.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tested with Claude](https://img.shields.io/badge/tested%20with-Claude%20Sonnet%204.6-orange.svg)](https://anthropic.com)
[![Tested with GPT-4o](https://img.shields.io/badge/tested%20with-GPT--4o-blue.svg)](https://openai.com)
[![Tested with Ollama](https://img.shields.io/badge/tested%20with-Ollama%20%28offline%29-lightgrey.svg)](https://ollama.com)

A **Model Context Protocol (MCP) server** for threat intelligence analysis and detection engineering. Built for security analysts, threat hunters, and detection engineers who want to turn raw threat feeds into actionable hunt hypotheses and detection rules — without relying on external SaaS platforms.

---

## What This Does

```
[Raw Threat Intel Feeds]
  TAXII 2.1 · RSS/Atom · HTML reports · Local files · JSON · STIX 2.x bundles · MISP events
        ↓
[Normalize & Extract]
  IOCs: IPs · Domains · Hashes · URLs · Emails
        ↓
[Enrich IOCs]
  VirusTotal · AlienVault OTX · AbuseIPDB · URLhaus (free)
        ↓
[Map ATT&CK Techniques]
  150+ keyword index across all 14 ATT&CK tactics (word-boundary matching, no false positives)
  → pairs with mitre-attack-mcp for deep technique context
        ↓
[Declare Your Environment]
  list_log_sources() → pick your log source keys
  sysmon · windows_events · proxy · dns · email_gateway · edr · macos_unified_log · edr_macos
        ↓
[Generate Hunt Hypotheses]
  Technique + YOUR log sources → specific, actionable hypotheses
  Ready-to-run SPL (Splunk) · KQL (Sentinel) · Elastic queries
        ↓
[Generate Detections — all four formats]
  Sigma rules    → sigma_for_technique / sigma_bundle_for_techniques
  KQL rules      → kql_for_technique  (Microsoft Sentinel)
  SPL rules      → spl_for_technique  (Splunk)
  Elastic rules  → eql_for_technique  (Kibana Detection Engine)
  YARA rules     → yara_for_technique (file/memory scanning)
        ↓
[Score & Validate]
  Sigma quality scorer → specificity · coverage · FP risk (1-5)
  ATT&CK Navigator layer export → drag-and-drop heatmap
  Atomic Red Team mapping → test IDs to validate detections fire
        ↓
[One-Shot Pipeline]
  run_pipeline_tool(text, sources_config, log_sources)
  → all of the above in a single Claude call
```

**Every tool is deterministic and offline-first.** No LLM calls are made inside this MCP — Claude (or your AI assistant) is the orchestrator. This MCP is the toolbox.

---

## Tools

### Feed Ingestion

| Tool | What it does |
|---|---|
| `ingest_feed(config_path)` | Pull from TAXII 2.1, RSS, HTML, or local files using a sources YAML config |
| `analyze_intel(text, sources_config_path)` | Run the full pipeline on text + feed documents combined |

### STIX 2.x Parsing

| Tool | What it does |
|---|---|
| `parse_stix(bundle_json)` | Parse a STIX 2.0/2.1 bundle — extract IOCs, ATT&CK techniques, malware families, threat actors. No external deps. |
| `stix_to_text(bundle_json)` | Flatten a STIX bundle into pipeline-ready text for `run_pipeline_tool` |

### IOC Extraction & Enrichment

| Tool | What it does |
|---|---|
| `extract_iocs(text)` | Extract IPs, domains, URLs, hashes, emails from any text. macOS extension blocklist prevents `.app`/`.plist`/`.kext` false positives. |
| `enrich_ioc_tool(ioc)` | Check a single IOC against VT, OTX, AbuseIPDB, URLhaus |
| `enrich_iocs_tool(iocs_csv)` | Bulk enrich up to 20 IOCs, get aggregate malicious/clean counts |

### TTP Mapping

| Tool | What it does |
|---|---|
| `map_ttp(text)` | Map free-form threat text to ATT&CK technique IDs, names, tactics, and evidence. Word-boundary matching prevents `tor`→"authorization" false positives. |

### ATT&CK Navigator Export

| Tool | What it does |
|---|---|
| `navigator_layer(map_attack_json, layer_name, domain)` | Generate an ATT&CK Navigator 4.5 layer JSON from `map_ttp` output. Drag into [mitre-attack.github.io/attack-navigator](https://mitre-attack.github.io/attack-navigator/) for instant heatmap. |

### Full Pipeline (single call)

| Tool | What it does |
|---|---|
| `run_pipeline_tool(text, sources_config, log_sources, enrich)` | One call: feed ingestion → IOC extraction → enrichment → TTP mapping → hunt hypotheses → Sigma rules. |
| `list_log_sources_tool()` | Catalog of all available log source keys + environment presets. |

### Hunt Hypothesis Generation

| Tool | What it does |
|---|---|
| `hunt_from_intel(text)` | Full pipeline: text → techniques → hypotheses + SIEM queries |
| `hunt_for_techniques(technique_ids, log_sources)` | Given technique IDs, get hypotheses + SPL/KQL/Elastic per log source |

### Detection Generation — Sigma

| Tool | What it does |
|---|---|
| `generate_sigma_rule(title, behavior, logsource)` | Generate a Sigma rule from a title and behavior description |
| `sigma_for_technique(technique_id)` | Generate a production-ready Sigma rule for a specific ATT&CK technique |
| `sigma_bundle_for_techniques(technique_ids)` | Generate Sigma rules for multiple techniques at once |
| `validate_sigma_rule(yaml_text)` | Validate Sigma YAML structure offline (no Sigma CLI required) |

### Sigma Quality Scoring

| Tool | What it does |
|---|---|
| `score_sigma(sigma_yaml)` | Score a Sigma rule on specificity (1-5), coverage (1-5), and FP risk (1-5). Weighted composite score + human-readable rationale. |
| `score_technique_sigma(technique_id)` | Score the built-in Sigma rule for any technique — quick triage for which rules need tuning. |
| `atomic_tests_for_technique(technique_id)` | Atomic Red Team test IDs for a technique. Validate your detections fire before shipping to production. |

### Detection Generation — Native SIEM formats

| Tool | What it does |
|---|---|
| `kql_for_technique(technique_id)` | KQL Analytics Rule for Microsoft Sentinel |
| `spl_for_technique(technique_id)` | SPL Saved Search for Splunk |
| `eql_for_technique(technique_id)` | Elastic Security rule (risk score, threat mapping, Kibana Detection Engine format) |

### Detection Generation — YARA

| Tool | What it does |
|---|---|
| `yara_for_technique(technique_id)` | YARA file-scanning rule for a technique |
| `generate_yara(rule_name, strings_csv, condition)` | Build a custom YARA rule from IOC strings |

### Coverage & Gap Analysis

| Tool | What it does |
|---|---|
| `detection_coverage_gap(techniques_csv, detections_csv)` | Find techniques you track but have no detection for |

### MISP Integration

| Tool | What it does |
|---|---|
| `misp_pull(tags, limit, threat_level)` | Pull MISP events filtered by tag/threat level → IOCs + pipeline-ready text. Requires `MISP_URL` + `MISP_KEY`. |
| `misp_push_sigma(event_id, sigma_yaml, technique_id)` | Push a generated Sigma rule as a MISP attribute back to an existing event. |
| `misp_create_event(pipeline_result)` | Create a new MISP event from `run_pipeline_tool` output — IOC attributes + ATT&CK tags auto-populated. |

### Storage & Search

| Tool | What it does |
|---|---|
| `search_intel_history(text_query, workflow)` | Search previously analyzed intel from local SQLite DB |
| `search_ingested_docs(text_query, source_name)` | Search normalized feed documents |
| `get_intel_by_id(row_id)` | Retrieve a full stored analysis product by ID |

### Utilities

| Tool | What it does |
|---|---|
| `timeline(text)` | Sort log lines or event notes into chronological order |

---

## Companion MCPs

This server is designed to work alongside:

| MCP | What it adds |
|---|---|
| **[mitre-attack-mcp](https://github.com/MHaggis/mitre-attack-mcp)** | Technique descriptions, mitigations, data sources, group attribution, Navigator layers |
| **[Security-Detections-MCP](https://github.com/MHaggis/Security-Detections-MCP)** | Search 8,200+ existing Sigma/Splunk/Elastic/KQL rules, coverage gap analysis |

Neither is required. This MCP works fully standalone.

### Fast path — one call does everything

```
"Connect to this TAXII feed, pull the latest intel, and give me hunt hypotheses
and detection rules for my Splunk + Sysmon environment."
```

Claude calls `run_pipeline_tool(sources_config="sources.yaml", log_sources="sysmon_process,script_block_logging,windows_event_4624")` and gets back IOCs, techniques, hypotheses, and Sigma rules in one shot.

### Typical multi-step workflow

1. Paste a threat report into Claude
2. Claude calls `run_pipeline_tool(text=..., log_sources="sysmon_process,dns_logs")` → IOCs + techniques + hypotheses + Sigma in one call
3. Claude calls `navigator_layer(map_attack_json=...)` → drag JSON into ATT&CK Navigator for heatmap
4. Claude calls `score_sigma(sigma_yaml=...)` → check FP risk before deploying to production
5. Claude calls `atomic_tests_for_technique(technique_id=...)` → confirm lab detections fire
6. Claude calls `enrich_ioc_tool` for any high-priority IOCs
7. Claude calls `misp_push_sigma` → attach generated rules back to the MISP event

---

## Setup

### Install

```bash
pip install -e .
```

### Configure Claude Desktop

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "threat-research-mcp": {
      "command": "python",
      "args": ["-m", "threat_research_mcp"],
      "env": {
        "VIRUSTOTAL_API_KEY": "your_key_here",
        "OTX_API_KEY": "your_key_here",
        "ABUSEIPDB_API_KEY": "your_key_here"
      }
    }
  }
}
```

### Docker (standard)

```bash
docker compose up -d
```

Set `VIRUSTOTAL_API_KEY`, `MISP_URL`, `MISP_KEY` in your environment or a `.env` file. The `playbook/` directory is bind-mounted for live edits.

### Docker (air-gapped SOC with Ollama)

For environments with no internet access:

```bash
docker compose -f docker-compose.ollama.yml up -d
```

This starts threat-research-mcp with `THREAT_MCP_OFFLINE=true` alongside an Ollama sidecar. No outbound calls are made. Pull your models into the Ollama volume before going air-gapped.

### Environment Variables

| Variable | Required | Purpose |
|---|---|---|
| `VIRUSTOTAL_API_KEY` | Optional | IOC enrichment via VirusTotal API v3 |
| `OTX_API_KEY` | Optional | IOC enrichment via AlienVault OTX |
| `ABUSEIPDB_API_KEY` | Optional | IP reputation via AbuseIPDB |
| `MISP_URL` | Optional | Base URL of your MISP instance (MISP tools) |
| `MISP_KEY` | Optional | MISP automation key (User → My Profile → Auth key) |
| `MISP_VERIFY_SSL` | Optional | Set `false` for self-signed certs in lab environments |
| `THREAT_MCP_OFFLINE` | Optional | Set `true` to skip all outbound API calls |
| `THREAT_RESEARCH_MCP_DB` | Optional | Path to SQLite DB for persisting intel history |

**URLhaus is free and requires no API key.** All enrichment sources are optional — sources that are not configured are simply skipped.

### Feed Sources Config

Create a YAML file to define your intel feeds (see `configs/sources.example.yaml`):

```yaml
sources:
  - type: taxii
    url: https://cti-taxii.mitre.org/taxii/
    collection: enterprise-attack

  - type: rss
    url: https://feeds.feedburner.com/TheHackersNews

  - type: local_file
    path: /path/to/incident_report.txt
```

Then call `ingest_feed("/path/to/sources.yaml")`.

---

## Contributing Techniques (no Python required)

The keyword → ATT&CK technique index and the Atomic Red Team test mappings live in plain YAML files that anyone can edit:

### `playbook/keywords.yaml` — Add keywords for a technique

```yaml
# Format: keyword (lowercase) → [technique_id, technique_name, tactic]
"living off the land":
  - ["T1218", "Signed Binary Proxy Execution", "defense-evasion"]

"mshta":
  - ["T1218.005", "Mshta", "defense-evasion"]
```

Word-boundary matching is applied automatically — you don't need to worry about substring false positives.

### `playbook/atomic_tests.yaml` — Add Atomic Red Team test IDs

```yaml
T1059.001:
  - T1059.001-1   # Mimikatz - Credential Dumping
  - T1059.001-2   # Run BloodHound from Local Disk

T1003.001:
  - T1003.001-1   # Dump LSASS via ProcDump
```

Submit a PR with new keywords or test mappings — no Python changes needed.

---

## Hunt Coverage

The hunt hypothesis engine covers **28 ATT&CK techniques** with playbooks for every major log source type:

| Log Source | Techniques |
|---|---|
| Sysmon Process Creation (EID 1) | T1059.001, T1059.003, T1053.005, T1566.001, T1021.001, T1021.002 |
| Sysmon Process Access (EID 10) | T1003.001 |
| Sysmon Registry (EID 13) | T1547.001 |
| Sysmon File Events (EID 11) | T1486 |
| Sysmon CreateRemoteThread (EID 8) | T1055 |
| PowerShell Script Block (EID 4104) | T1059.001, T1027 |
| Windows Security Events | T1053.005, T1021.001, T1021.002, T1078, T1110.003, T1558.003 |
| Windows System Events | T1543.003 |
| Web Proxy Logs | T1071.001, T1041, T1567.002 |
| DNS Query Logs | T1071.001, T1071.004 |
| Email Gateway Logs | T1566.001 |
| Web Server / WAF Logs | T1505.003, T1190 |
| Firewall / Flow Logs | T1046 |
| macOS Unified Log | T1059.002 (AppleScript), T1543.001 (LaunchAgent), T1548.006 (TCC), T1555.003 (Keychain) |
| EDR (macOS) | T1539 (session cookie), T1567.002 (Telegram exfil), T1204.002 (user execution), T1560.001 (archive) |

---

## ATT&CK Mapping Coverage

The `map_ttp` tool matches **150+ keywords and phrases** across all 14 ATT&CK tactics. Word-boundary regex matching prevents false positives (e.g., `tor` won't match "authorization").

- **Execution**: PowerShell, CMD, WMI, VBScript, JavaScript, Python, scheduled tasks, msiexec, rundll32, regsvr32, osascript, AppleScript, zsh, curl|bash
- **Persistence**: Run keys, Windows services, web shells, crontab, systemd, startup folder, LaunchAgent, launchd, launch daemon
- **Privilege Escalation**: UAC bypass, token impersonation, pass-the-hash, sudo, kerberoasting, TCC manipulation, TCC database
- **Defense Evasion**: Obfuscation, process injection, timestomp, LOLBins, masquerading, reflective DLL, Gatekeeper, quarantine attribute, fileless, in-memory execution
- **Credential Access**: Mimikatz, LSASS dumping, NTDS.dit, brute force, password spray, keylogging, Keychain, security find-generic-password, session hijack, session cookie
- **Discovery**: nmap, BloodHound, net commands, systeminfo, domain trust enumeration
- **Lateral Movement**: PsExec, SMB, RDP, SSH, WMI
- **Collection**: zip archive, archive collected, screen capture
- **C2**: DNS tunneling, domain fronting, Cobalt Strike, Sliver, Tor network, Telegram Bot, Telegram Bot API
- **Exfiltration**: rclone, MEGA, FTP, DNS exfil, Telegram Bot API
- **Initial Access**: Phishing, spearphishing link, drive-by, supply chain, valid accounts, SQL injection, remote code execution, LinkedIn lure, fake job, fake recruiter, Ledger Live, Exodus wallet, crypto wallet
- **Impact**: Ransomware, wipers, defacement, DDoS

---

## Tested With

| AI Assistant | Version | Notes |
|---|---|---|
| Claude | Sonnet 4.6 | Primary test target; tool calling via MCP |
| GPT-4o | 2024-11 | Via OpenAI Responses API with MCP support |
| Ollama | llama3.1:8b | Air-gapped mode; use `docker-compose.ollama.yml` |

---

## Development

```bash
# Install with dev deps
pip install -e ".[dev]"

# Run tests
pytest tests/ -q

# Run with coverage (must stay ≥65%)
pytest tests/ --cov=src/threat_research_mcp -q

# Lint
ruff check src/

# Format
ruff format src/
```

---

## Project Structure

```
src/threat_research_mcp/
├── server.py                        # MCP tool definitions (FastMCP) — ~33 tools
├── tools/
│   ├── extract_iocs.py              # Regex IOC extraction (macOS extension blocklist)
│   ├── map_attack.py                # ATT&CK keyword index (150+ keywords, word-boundary regex)
│   ├── generate_hunt_hypothesis.py  # Hunt hypothesis + SIEM query engine (28 techniques)
│   ├── generate_sigma.py            # Sigma rule generation
│   ├── parse_stix.py                # STIX 2.x bundle parser (no external deps)
│   ├── navigator_export.py          # ATT&CK Navigator 4.5 layer export
│   ├── score_sigma.py               # Sigma quality scorer + Atomic Red Team mapping
│   ├── misp_bridge.py               # MISP pull/push/create integration
│   ├── validate_sigma.py            # Sigma YAML validation (offline)
│   └── detection_gap_analysis.py    # Coverage gap calculator
├── enrichment/
│   └── enrich.py                    # Real API calls: VT, OTX, AbuseIPDB, URLhaus
├── ingestion/
│   └── adapters/                    # TAXII 2.1, RSS, HTML, local file adapters
├── detection/
│   └── generators/sigma.py          # SigmaRule dataclass + per-technique templates
└── storage/sqlite.py                # SQLite persistence for intel history

playbook/
├── keywords.yaml                    # Community-editable keyword → ATT&CK technique index
└── atomic_tests.yaml                # Atomic Red Team test IDs per technique

Dockerfile                           # Standard container image
docker-compose.yml                   # Standard deployment
docker-compose.ollama.yml            # Air-gapped SOC: MCP + Ollama sidecar
```

---

## License

MIT
