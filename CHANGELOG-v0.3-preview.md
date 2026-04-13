# v0.3 Preview: Log Source Recommendations

## Release Date
April 11, 2026 (Preview/Prototype)

## Overview

This preview release introduces **Log Source Recommendations**, a feature that bridges the gap between ATT&CK technique detection and operational log collection. Instead of generic "Process Creation" guidance, security engineers now get specific event IDs, cloud service logs, and ready-to-run SIEM queries.

## What's New

### Core Feature: Log Source Mapper

**File:** `src/threat_research_mcp/detection/log_source_mapper.py`

- Maps **20 common ATT&CK techniques** to specific log sources
- Supports multiple platforms:
  - **Windows**: Event Logs (Security, PowerShell, TaskScheduler, TerminalServices), Sysmon
  - **AWS**: CloudTrail, VPC Flow Logs, CloudWatch, ALB/CloudFront, WAF
  - **Azure**: Activity Logs, Sign-in Logs, NSG Flow Logs, Application Gateway
  - **GCP**: Cloud Logging, VPC Flow Logs, Cloud Scheduler, Cloud Armor
  - **Network**: Firewall, Proxy, IDS/IPS (Zeek, Snort, Suricata)
  - **Email**: Proofpoint, Mimecast, Microsoft Defender for Office 365, Office 365, Google Workspace
  - **EDR**: CrowdStrike, Microsoft Defender, Carbon Black, SentinelOne

- Provides detailed configuration guidance (e.g., GPO settings, event IDs)
- Prioritizes sources (critical, high, medium) for deployment planning

### Query Generator

**File:** `src/threat_research_mcp/detection/query_generator.py`

- Generates **ready-to-run hunt queries** for 5 SIEM platforms:
  - **Splunk** (SPL)
  - **Microsoft Sentinel** (KQL)
  - **Elastic** (EQL/JSON DSL)
  - **AWS Athena** (SQL for CloudTrail/VPC Flow Logs)
  - **Chronicle** (YARA-L/UDM)

- Includes query templates for all 20 supported techniques
- Provides deployment checklists with prioritized actions

### New MCP Tool

**File:** `src/threat_research_mcp/tools/recommend_log_sources.py`

```python
recommend_log_sources(
    technique_ids="T1059.001,T1566.001,T1003.001",
    environment="hybrid",  # aws, azure, gcp, on-prem, hybrid
    siem_platforms="splunk,sentinel,elastic"
)
```

**Returns:**
- Prioritized log sources by platform
- SIEM-specific hunt queries
- Deployment checklist with configuration steps
- Blind spot identification

### Automatic Integration

**File:** `src/threat_research_mcp/orchestrator/analysis_product_builder.py`

- `analysis_product` and `intel_to_analysis_product` workflows now **automatically generate log source guidance** when ATT&CK techniques are detected
- New `LogSourceGuidance` schema in `detection_delivery` bundle
- Seamless integration with existing workflows

### Schema Updates

**File:** `src/threat_research_mcp/schemas/detection_delivery.py`

Added `LogSourceGuidance` model:
```python
class LogSourceGuidance(BaseModel):
    techniques: List[str]
    environment: str
    priority_summary: dict  # critical, high, medium sources
    log_sources: dict       # detailed sources by platform
    hunt_queries: dict      # SIEM-specific queries
    deployment_checklist: List[dict]
    blind_spots: List[str]
```

## Supported Techniques (v0.3 Preview)

### Initial Access & Execution
- T1566.001 - Phishing: Spearphishing Attachment
- T1190 - Exploit Public-Facing Application
- T1059.001 - PowerShell

### Persistence & Privilege Escalation
- T1053.005 - Scheduled Task/Job
- T1547.001 - Registry Run Keys
- T1543.003 - Windows Service

### Defense Evasion
- T1070.001 - Clear Windows Event Logs
- T1562.001 - Impair Defenses

### Credential Access
- T1003.001 - LSASS Memory Dumping
- T1110.003 - Password Spraying

### Discovery & Lateral Movement
- T1078 - Valid Accounts
- T1021.001 - Remote Desktop Protocol

### Command and Control
- T1071.001 - Web Protocols
- T1105 - Ingress Tool Transfer

### Exfiltration & Impact
- T1567.002 - Exfiltration to Cloud Storage
- T1486 - Ransomware

### Account Manipulation
- T1136.001 - Create Local Account
- T1098 - Account Manipulation
- T1569.002 - Service Execution

## Testing

**File:** `tests/test_log_source_mapper.py`

- **12 new tests** covering:
  - Log source mapping for single and multiple techniques
  - Environment filtering (aws, azure, gcp, on-prem, hybrid)
  - Query generation for all SIEM platforms
  - Deployment checklist generation
  - MCP tool wrapper
  - Coverage validation for common techniques

**Test Results:** All 51 tests pass (39 existing + 12 new)

## Documentation

### New Documentation

1. **[Log Source Recommendations Guide](docs/log-source-recommendations.md)**
   - Complete feature documentation
   - Usage examples for common scenarios (phishing, ransomware, cloud compromise)
   - API reference
   - Best practices and troubleshooting

2. **Updated README.md**
   - Added `recommend_log_sources` to tool list (16 tools total)
   - Updated "What You Get Today" section with v0.3 preview
   - Updated roadmap with implementation status

3. **Updated ROADMAP.md**
   - Marked core v0.3 features as implemented
   - Identified remaining work (environment profiler, coverage gap detection)

## Breaking Changes

None. This is a purely additive release.

## Migration Guide

No migration needed. Existing workflows continue to work unchanged. The new `log_source_guidance` field is automatically populated in `DetectionDeliveryBundle` when techniques are present.

## Known Limitations

1. **Technique Coverage**: 20 techniques in v0.3 preview (expanding to 100+ in full v0.3)
2. **Query Templates**: SIEM queries are templates and require customization for your environment (index names, field names, thresholds)
3. **Environment Profiler**: Not yet implemented (planned for full v0.3)
4. **Coverage Gap Detection**: Not yet implemented (planned for full v0.3)

## Performance Impact

- Minimal: Log source mapping and query generation add ~50-100ms to `analysis_product` workflow
- No impact on workflows that don't detect ATT&CK techniques

## Upgrade Instructions

```bash
cd threat-research-mcp
git pull
pip install -e ".[dev]"
python -m pytest tests/  # Verify all tests pass
```

## Example Usage

### Direct Tool Usage

```python
# In your MCP client (Cursor, VS Code + Cline)
recommend_log_sources(
    technique_ids="T1059.001,T1566.001",
    environment="hybrid",
    siem_platforms="splunk,sentinel"
)
```

### Automatic Integration

```python
# Log guidance is automatically included
analysis_product(text="Phishing incident with PowerShell payload...")
```

The resulting `AnalysisProduct` JSON will include:
```json
{
  "detection_delivery": {
    "rules": [...],
    "log_source_guidance": {
      "techniques": ["T1059.001", "T1566.001"],
      "priority_summary": {...},
      "log_sources": {...},
      "hunt_queries": {...},
      "deployment_checklist": [...]
    }
  }
}
```

## Bonus Feature: Automatic Technique Detection

**File:** `src/threat_research_mcp/extensions/mitre_attack_integration.py`

Added `intel_to_log_sources` tool that automatically:
1. Analyzes threat intelligence text
2. Detects relevant ATT&CK techniques (40+ patterns)
3. Generates log source recommendations
4. Provides SIEM-specific queries

**Example:**
```python
intel_to_log_sources(
    intel_text="ICP Canister C2 using blockchain for censorship-resistant C2"
)
# Auto-detects: T1071.001, T1090, T1573.002
# Generates: Log sources + queries + deployment checklist
```

## MCP Ecosystem Integration

**New Documentation:**
- `docs/complete-mcp-ecosystem.md` - Complete 4-MCP integration guide
- `docs/splunk-mcp-integration.md` - Splunk MCP integration
- `docs/automatic-technique-detection.md` - Auto-detection feature guide

**Recommended MCP Stack:**
1. **threat-research-mcp** (this project) - Technique detection + log sources
2. **fastmcp-threatintel** - IOC enrichment (VirusTotal, OTX, AbuseIPDB)
3. **Security-Detections-MCP** - 8,200+ existing detection rules
4. **Splunk MCP** - Query validation + safe execution

**Complete Pipeline:**
```
Threat Intel → Auto-Detect Techniques → Enrich IOCs → Check Coverage → 
Generate Queries → Validate → Execute → Results
```

## What's Next (Full v0.3)

1. **Environment Profiler**: Define your environment once, get tailored recommendations
2. **Coverage Gap Detection**: Identify missing logs based on your environment
3. **Expanded Coverage**: 100+ techniques with comprehensive mappings
4. **SIEM-Specific Tuning**: Platform-specific query optimizations
5. **Direct MCP Integration**: Call other MCPs directly from tools

## Contributors

- Harsh Thakur (@harshdthakur6293)

## Feedback

This is a preview release. Please report issues, request additional techniques, or suggest improvements via GitHub Issues.

---

**Full v0.3 Release Target:** Q3 2026
