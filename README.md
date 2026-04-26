# Threat Research MCP

[![CI](https://github.com/harshthakur6293/threat-research-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/harshthakur6293/threat-research-mcp/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://img.shields.io/badge/tests-72%20passing-brightgreen.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A **Model Context Protocol (MCP) server** for threat intelligence analysis and detection engineering. Built for security analysts, threat hunters, and detection engineers who want to turn raw threat feeds into actionable hunt hypotheses and detection rules — without relying on external SaaS platforms.

---

## What This Does

```
[Raw Threat Intel Feeds]
  TAXII 2.1 · RSS/Atom · HTML reports · Local files · JSON
        ↓
[Normalize & Extract]
  IOCs: IPs · Domains · Hashes · URLs · Emails
        ↓
[Enrich IOCs]
  VirusTotal · AlienVault OTX · AbuseIPDB · URLhaus (free)
        ↓
[Map ATT&CK Techniques]
  100+ keyword index across all 14 ATT&CK tactics
  → pairs with mitre-attack-mcp for deep technique context
        ↓
[Declare Your Environment]
  list_log_sources() → pick your log source keys
  sysmon · windows_events · proxy · dns · email_gateway · edr
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

### IOC Extraction & Enrichment

| Tool | What it does |
|---|---|
| `extract_iocs(text)` | Extract IPs, domains, URLs, hashes, emails from any text |
| `enrich_ioc_tool(ioc)` | Check a single IOC against VT, OTX, AbuseIPDB, URLhaus |
| `enrich_iocs_tool(iocs_csv)` | Bulk enrich up to 20 IOCs, get aggregate malicious/clean counts |

### TTP Mapping

| Tool | What it does |
|---|---|
| `map_ttp(text)` | Map free-form threat text to ATT&CK technique IDs, names, tactics, and evidence |

### Full Pipeline (single call)

| Tool | What it does |
|---|---|
| `run_pipeline_tool(text, sources_config, log_sources, enrich)` | One call: feed ingestion → IOC extraction → enrichment → TTP mapping → hunt hypotheses → Sigma rules. Pass your log source keys to filter results to your environment. |
| `list_log_sources_tool()` | Catalog of all available log source keys + environment presets (windows_sysmon, network, perimeter, edr). Use these with `hunt_for_techniques` and `run_pipeline_tool`. |

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

### Detection Generation — Native SIEM formats

| Tool | What it does |
|---|---|
| `kql_for_technique(technique_id)` | KQL Analytics Rule for Microsoft Sentinel — with display name, severity, query frequency |
| `spl_for_technique(technique_id)` | SPL Saved Search for Splunk — with cron schedule, drilldown, recommended actions |
| `eql_for_technique(technique_id)` | Elastic Security rule — with risk score, threat mapping, Kibana Detection Engine format |

### Detection Generation — YARA

| Tool | What it does |
|---|---|
| `yara_for_technique(technique_id)` | YARA file-scanning rule for a technique (covers T1059.001, T1003.001, T1055, T1027, T1486, T1505.003, T1566.001, T1071.001, T1547.001, T1053.005) |
| `generate_yara(rule_name, strings_csv, condition)` | Build a custom YARA rule from IOC strings (hashes, malware strings, file patterns) |

### Coverage & Gap Analysis

| Tool | What it does |
|---|---|
| `detection_coverage_gap(techniques_csv, detections_csv)` | Find techniques you track but have no detection for |

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

### Step-by-step workflow with all three MCPs

1. Paste a threat report into Claude
2. Claude calls `run_pipeline_tool(text=..., log_sources="sysmon_process,dns_logs")` → IOCs + techniques + hypotheses + Sigma in one call
3. Claude calls `enrich_ioc_tool` for any high-priority IOCs
4. Claude calls `mitre-attack-mcp: get_technique` for rich technique context (mitigations, group attribution)
5. Claude calls `kql_for_technique` / `spl_for_technique` / `eql_for_technique` → SIEM-native rules ready to paste in
6. Claude calls `yara_for_technique` → file-scanning YARA rules for EDR/sandbox
7. Claude calls `Security-Detections-MCP: list_by_mitre` → checks existing coverage
8. Claude calls `detection_coverage_gap` → pinpoints exactly which techniques have no detection yet

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

### Environment Variables

| Variable | Required | Purpose |
|---|---|---|
| `VIRUSTOTAL_API_KEY` | Optional | IOC enrichment via VirusTotal API v3 |
| `OTX_API_KEY` | Optional | IOC enrichment via AlienVault OTX |
| `ABUSEIPDB_API_KEY` | Optional | IP reputation via AbuseIPDB |
| `THREAT_RESEARCH_MCP_DB` | Optional | Path to SQLite DB for persisting intel history |

**URLhaus is free and requires no API key.** All enrichment sources are optional — the server works without any keys, sources that are not configured are simply skipped.

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

## Hunt Coverage

The hunt hypothesis engine covers **20 ATT&CK techniques** with playbooks for every major log source type:

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
| Web Proxy Logs | T1071.001, T1041 |
| DNS Query Logs | T1071.001, T1071.004 |
| Email Gateway Logs | T1566.001 |
| Web Server / WAF Logs | T1505.003, T1190 |
| Firewall / Flow Logs | T1046 |

Techniques not in the built-in playbook can be enriched via `mitre-attack-mcp: get_datacomponents_detecting_technique`.

---

## ATT&CK Mapping Coverage

The `map_ttp` tool matches 100+ keywords and phrases across all 14 ATT&CK tactics including:

- **Execution**: PowerShell, CMD, WMI, VBScript, JavaScript, Python, scheduled tasks, msiexec, rundll32, regsvr32
- **Persistence**: Run keys, Windows services, web shells, crontab, systemd, startup folder
- **Privilege Escalation**: UAC bypass, token impersonation, pass-the-hash, sudo, kerberoasting
- **Defense Evasion**: Obfuscation, process injection, timestomp, LOLBins, masquerading, reflective DLL
- **Credential Access**: Mimikatz, LSASS dumping, NTDS.dit, brute force, password spray, keylogging
- **Discovery**: nmap, BloodHound, net commands, systeminfo, domain trust enumeration
- **Lateral Movement**: PsExec, SMB, RDP, SSH, WMI
- **C2**: DNS tunneling, domain fronting, Cobalt Strike, Sliver, Tor
- **Exfiltration**: rclone, MEGA, FTP, DNS exfil
- **Initial Access**: Phishing, drive-by, supply chain, valid accounts, SQL injection, RCE
- **Impact**: Ransomware, wipers, defacement, DDoS

---

## Development

```bash
# Install with dev deps
pip install -e ".[dev]"

# Run tests
pytest tests/ -q

# Lint
ruff check src/

# Format
ruff format src/
```

---

## Project Structure

```
src/threat_research_mcp/
├── server.py                        # MCP tool definitions (FastMCP)
├── tools/
│   ├── extract_iocs.py              # Regex IOC extraction
│   ├── map_attack.py                # ATT&CK keyword index (100+ keywords)
│   ├── generate_hunt_hypothesis.py  # Hunt hypothesis + SIEM query engine
│   ├── generate_sigma.py            # Sigma rule generation
│   ├── validate_sigma.py            # Sigma YAML validation (offline)
│   ├── detection_gap_analysis.py    # Coverage gap calculator
│   └── reconstruct_timeline.py      # Log timeline sorter
├── enrichment/
│   └── enrich.py                    # Real API calls: VT, OTX, AbuseIPDB, URLhaus
├── ingestion/
│   └── adapters/                    # TAXII 2.1, RSS, HTML, local file adapters
├── detection/
│   └── generators/sigma.py          # SigmaRule dataclass + per-technique templates
└── storage/sqlite.py                # SQLite persistence for intel history
```

---

## License

MIT
