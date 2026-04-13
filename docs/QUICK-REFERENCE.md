# Quick Reference: Complete MCP Ecosystem

## 🎯 One-Page Cheat Sheet

### Your ICP Canister C2 Case - Complete Solution

```python
# 1. AUTO-DETECT TECHNIQUES (threat-research-mcp)
intel_to_log_sources(
    intel_text="ICP Canister ID: tdtqy-oyaaa-aaaae-af2dq-cai. Blockchain C2.",
    siem_platforms="splunk"
)
# → Detects: T1071.001, T1090, T1573.002
# → Generates: Proxy/firewall log sources + Splunk query

# 2. BEHAVIORAL HUNT (threat-hunting-mcp) ⭐ NEW
search_community_hunts(tactic="Command and Control", keyword="beaconing")
create_behavioral_hunt(
    technique_id="T1071.001",
    hypothesis="Hunt for C2 beaconing patterns regardless of Canister ID"
)
# → Generates: Behavioral query detecting regular beaconing patterns
# → Survives infrastructure changes (Canister ID rotation)

# 3. ENRICH IOCs (fastmcp-threatintel)
analyze(ioc="185.220.101.45")
# → VirusTotal: 15/70 malicious
# → AbuseIPDB: 85% abuse confidence
# → Geolocation: Amsterdam, Netherlands

# 4. CHECK EXISTING COVERAGE (Security-Detections-MCP)
list_by_mitre(technique_id="T1071.001")
# → 109 existing detections
# → Gap: Blockchain/Web3 C2 behavioral patterns

# 5. VALIDATE QUERIES (Splunk MCP)
validate_spl(query="<behavioral hunt query>")
# → Risk score: 5/100 (safe)
# → Recommendations: None

# 6. EXECUTE HUNTS (Splunk MCP)
search_oneshot(query="<validated behavioral query>")
# → Result: 3 hosts with beaconing patterns (survives Canister ID changes!)
```

## 🔧 Tool Quick Reference

### threat-research-mcp (17 tools)

**Auto-Detection:**
- `intel_to_log_sources` - Intel → techniques → log sources → queries

**Manual Mapping:**
- `recommend_log_sources` - Techniques → log sources → queries
- `extract_iocs` - Extract IPs, domains, URLs, hashes
- `attack_map` - Map behaviors to ATT&CK

**Detection Generation:**
- `generate_sigma` - Generate Sigma rules
- `validate_sigma` - Validate Sigma YAML

**Analysis:**
- `analysis_product` - Full workflow analysis
- `hunt` - Generate hunt hypotheses
- `timeline` - Reconstruct timelines

### fastmcp-threatintel (7 tools)

**IOC Analysis:**
- `analyze` - Comprehensive IOC analysis (all sources)
- `virustotal_scan` - File/URL reputation
- `otx_lookup` - AlienVault threat intelligence
- `abuseipdb_check` - IP reputation
- `ipinfo_lookup` - Geolocation, ASN

**Batch & Reports:**
- `batch_analyze` - Bulk IOC analysis
- `generate_report` - HTML/PDF reports

### Security-Detections-MCP (71+ tools)

**Coverage Analysis:**
- `analyze_coverage` - Coverage by tactic
- `identify_gaps` - Find detection gaps
- `analyze_procedure_coverage` - Procedure-level gaps
- `analyze_actor_coverage` - APT coverage analysis

**Detection Search:**
- `search` - Full-text search (8,200+ rules)
- `list_by_mitre` - Filter by technique
- `list_by_cve` - Find CVE detections
- `list_by_source` - Filter by Sigma/Splunk/Elastic/KQL

**Detection Engineering:**
- `generate_template` - Detection templates
- `extract_patterns` - Learn from existing detections
- `suggest_improvements` - AI-enhanced suggestions

**MCP Prompts (11):**
- `ransomware-readiness-assessment`
- `apt-threat-emulation`
- `purple-team-exercise`
- `soc-investigation-assist`
- `detection-engineering-sprint`

### Splunk MCP (7 tools)

**Query Validation:**
- `validate_spl` - Risk scoring 0-100

**Query Execution:**
- `search_oneshot` - Blocking searches
- `search_export` - Stream large results

**Discovery:**
- `get_indexes` - List available indexes
- `get_saved_searches` - Access saved searches
- `run_saved_search` - Execute saved searches

## 🎯 Common Workflows

### Workflow 1: New Threat Intelligence

```
1. intel_to_log_sources(intel_text="...")        [threat-research-mcp]
2. analyze(ioc="...")                            [fastmcp-threatintel]
3. list_by_mitre(technique_id="...")             [Security-Detections-MCP]
4. validate_spl(query="...")                     [Splunk MCP]
5. search_oneshot(query="...")                   [Splunk MCP]
```

### Workflow 2: APT Campaign Analysis

```
1. analyze_actor_coverage(actor="APT29")         [Security-Detections-MCP]
2. recommend_log_sources(technique_ids="...")    [threat-research-mcp]
3. validate_spl(query="...")                     [Splunk MCP]
4. search_oneshot(query="...")                   [Splunk MCP]
```

### Workflow 3: Ransomware Readiness

```
1. Use ransomware-readiness-assessment prompt    [Security-Detections-MCP]
2. recommend_log_sources(technique_ids="T1486,T1070.001,T1562.001") [threat-research-mcp]
3. validate_spl(query="...")                     [Splunk MCP]
4. search_oneshot(query="...")                   [Splunk MCP]
```

### Workflow 4: CVE Response

```
1. list_by_cve(cve_id="CVE-2024-27198")          [Security-Detections-MCP]
2. intel_to_log_sources(intel_text="CVE intel")  [threat-research-mcp]
3. validate_spl(query="...")                     [Splunk MCP]
4. search_oneshot(query="...")                   [Splunk MCP]
```

## 🚀 Quick Start Commands

### Setup All MCPs (One-Time)

```bash
# 1. threat-research-mcp (already done)
cd c:\Dev\Vibe Coding\threat-research-mcp
pip install -e ".[dev]"

# 2. fastmcp-threatintel
pip install fastmcp-threatintel
threatintel setup

# 3. Security-Detections-MCP (download detection content)
mkdir detections && cd detections
git clone --depth 1 --filter=blob:none --sparse https://github.com/SigmaHQ/sigma.git
cd sigma && git sparse-checkout set rules && cd ../..

# 4. Splunk MCP
git clone https://github.com/splunk/splunk-mcp-server2.git
cd splunk-mcp-server2/python
cp .env.example .env  # Add Splunk credentials
pip install -e .
```

### Configure in Cursor (One-Time)

Add all 4 to your MCP config:

```json
{
  "mcpServers": {
    "threat-research": { "command": "python", "args": ["-m", "threat_research_mcp.server"], "cwd": "c:\\Dev\\Vibe Coding\\threat-research-mcp" },
    "threatintel": { "command": "threatintel", "args": ["server"], "env": { "VIRUSTOTAL_API_KEY": "...", "OTX_API_KEY": "..." } },
    "security-detections": { "command": "npx", "args": ["-y", "security-detections-mcp"], "env": { "SIGMA_PATHS": "..." } },
    "splunk": { "command": "python", "args": ["server.py"], "cwd": "...", "env": { "SPLUNK_HOST": "..." } }
  }
}
```

## 📊 Feature Matrix

| Feature | threat-research-mcp | fastmcp-threatintel | Security-Detections-MCP | Splunk MCP |
|---------|-------------------|-------------------|----------------------|-----------|
| **Auto-detect techniques** | ✅ | ❌ | ❌ | ❌ |
| **Log source recommendations** | ✅ | ❌ | ❌ | ❌ |
| **Query generation** | ✅ | ❌ | ✅ Templates | ❌ |
| **IOC enrichment** | ❌ | ✅ | ❌ | ❌ |
| **Reputation scoring** | ❌ | ✅ | ❌ | ❌ |
| **APT attribution** | ❌ | ✅ | ✅ | ❌ |
| **Existing detection search** | ❌ | ❌ | ✅ 8,200+ | ❌ |
| **Coverage gap analysis** | ❌ | ❌ | ✅ | ❌ |
| **Query validation** | ❌ | ❌ | ❌ | ✅ |
| **Query execution** | ❌ | ❌ | ❌ | ✅ |
| **Index discovery** | ❌ | ❌ | ❌ | ✅ |

## 🎓 When to Use Which MCP

### Use threat-research-mcp when:
- ✅ You have raw threat intelligence to analyze
- ✅ You need to know which logs to collect
- ✅ You want SIEM queries for specific techniques
- ✅ You need IOC extraction from reports

### Use fastmcp-threatintel when:
- ✅ You have IOCs to enrich (IPs, domains, hashes, URLs)
- ✅ You need reputation scores
- ✅ You want geolocation and ASN data
- ✅ You need APT attribution

### Use Security-Detections-MCP when:
- ✅ You want to check existing coverage
- ✅ You need to find detection gaps
- ✅ You want production-quality detection templates
- ✅ You're doing APT threat emulation
- ✅ You need procedure-level coverage analysis

### Use Splunk MCP when:
- ✅ You need to validate SPL queries
- ✅ You want to execute queries safely
- ✅ You need to discover available indexes
- ✅ You want to run saved searches

## 💡 Pro Tips

### Tip 1: Start with Auto-Detection
```python
# ❌ Don't manually map techniques
recommend_log_sources(technique_ids="T1071.001,T1090")

# ✅ Let it auto-detect
intel_to_log_sources(intel_text="<paste threat intel>")
```

### Tip 2: Check Coverage Before Creating
```python
# ❌ Don't create duplicate detections
generate_sigma(...)

# ✅ Check existing coverage first
list_by_mitre(technique_id="T1071.001")
# → 109 existing detections, focus on gaps
```

### Tip 3: Always Validate Before Executing
```python
# ❌ Don't execute untested queries
search_oneshot(query="...")

# ✅ Validate first
validation = validate_spl(query="...")
if validation["is_safe"]:
    search_oneshot(query="...")
```

### Tip 4: Enrich IOCs Early
```python
# ✅ Enrich before hunting
analyze(ioc="185.220.101.45")
# → Get reputation, then search with context
```

### Tip 5: Use MCP Prompts for Complex Tasks
```python
# ❌ Don't manually orchestrate 20+ tool calls
# ✅ Use pre-built prompts
"Use ransomware-readiness-assessment prompt"
"Run apt-threat-emulation for APT29"
```

## 📚 Documentation Index

### threat-research-mcp (This Project)
- `docs/complete-mcp-ecosystem.md` - **START HERE**: Complete 4-MCP integration
- `docs/automatic-technique-detection.md` - Auto-detection feature
- `docs/log-source-recommendations.md` - Log source guidance
- `docs/splunk-mcp-integration.md` - Splunk integration
- `docs/using-as-a-security-engineer.md` - Setup guide

### External MCPs
- [fastmcp-threatintel docs](https://github.com/4R9UN/fastmcp-threatintel)
- [Security-Detections-MCP docs](https://github.com/MHaggis/Security-Detections-MCP)
- [Splunk MCP docs](https://github.com/splunk/splunk-mcp-server2)

## 🆘 Quick Troubleshooting

| Problem | Solution |
|---------|----------|
| "No techniques detected" | Provide more detailed threat intel with specific actions/tools |
| "API rate limit hit" | Enable caching: `CACHE_TTL=3600` in fastmcp-threatintel |
| "Query validation failed" | Review `validation["recommendations"]` and apply fixes |
| "No existing coverage found" | Good! Generate new detection with threat-research-mcp |
| "Splunk connection refused" | Check `.env` credentials and network connectivity |
| "MCP server not responding" | Restart MCP client, check server logs |

## 🎉 Success Metrics

After setting up all 4 MCPs, you should be able to:

- ✅ Paste threat intel → get techniques in <5 seconds
- ✅ Enrich IOCs → get reputation in <10 seconds
- ✅ Check coverage → find gaps in <5 seconds
- ✅ Generate query → validate → execute in <30 seconds
- ✅ Complete investigation in <2 minutes (vs hours manually)

---

**Need help?** See `docs/complete-mcp-ecosystem.md` for detailed workflows and examples.
