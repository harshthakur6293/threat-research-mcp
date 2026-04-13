# Complete MCP Ecosystem Integration

## Overview

This guide shows how to integrate **4 complementary MCPs** to create a complete, automated threat intelligence → detection → validation → execution pipeline.

## The Five MCPs

### 1. threat-research-mcp (This Project)
**Purpose:** Threat intelligence analysis and log source recommendations

**Key Features:**
- Auto-detect ATT&CK techniques from threat intel
- Generate log source recommendations (AWS, Azure, GCP, Windows, Linux)
- Create SIEM-specific queries (Splunk, Sentinel, Elastic, Athena, Chronicle)
- IOC extraction and analysis product generation

**Use For:** Starting point for any threat intelligence analysis

### 1.5. [threat-hunting-mcp](https://github.com/THORCollective/threat-hunting-mcp-server)
**Purpose:** Behavioral threat hunting (TTPs at top of Pyramid of Pain)

**Key Features:**
- Behavioral hunt hypotheses (hunt behaviors, not IOCs)
- HEARTH community hunts (50+ curated hypotheses)
- Cognitive bias detection (confirmation, anchoring, availability)
- Graph-based attack analysis (attack paths, LOLBins, pivot points)
- Deception technology (honeytokens, decoys, canary files)
- Hunt frameworks (PEAK, SQRRL, TaHiTI)

**Use For:** Converting techniques into durable behavioral hunts

### 2. [fastmcp-threatintel](https://github.com/4R9UN/fastmcp-threatintel)
**Purpose:** IOC enrichment and reputation analysis

**Key Features:**
- VirusTotal: File/URL reputation (70+ AV engines)
- AlienVault OTX: Community threat intelligence
- AbuseIPDB: IP reputation and abuse confidence
- IPinfo: Geolocation, ASN, infrastructure data
- APT attribution with confidence scoring

**Use For:** Enriching extracted IOCs with reputation and context

### 3. [Security-Detections-MCP](https://github.com/MHaggis/Security-Detections-MCP)
**Purpose:** Query 8,200+ existing detection rules

**Key Features:**
- 3,200+ Sigma rules
- 2,000+ Splunk ESCU detections
- 1,500+ Elastic rules
- 420+ KQL queries
- 900+ Sublime email rules
- 139+ CrowdStrike CQL queries
- Coverage gap analysis
- Procedure-level coverage analysis

**Use For:** Checking existing coverage before creating new detections

### 4. [Splunk MCP](https://github.com/splunk/splunk-mcp-server2)
**Purpose:** Query validation and execution

**Key Features:**
- SPL query validation with risk scoring (0-100)
- Direct Splunk query execution
- Index discovery
- Saved search management
- Data sanitization (credit cards, SSNs)

**Use For:** Validating and executing generated queries safely

## Complete Setup

### Install All Four MCPs

#### 1. threat-research-mcp (Already Installed)
```bash
cd c:\Dev\Vibe Coding\threat-research-mcp
pip install -e ".[dev]"
```

#### 2. fastmcp-threatintel
```bash
# Install from PyPI
pip install fastmcp-threatintel

# Setup API keys
threatintel setup

# Or use .env file
# VIRUSTOTAL_API_KEY=your_key
# OTX_API_KEY=your_key
# ABUSEIPDB_API_KEY=your_key (optional)
# IPINFO_API_KEY=your_key (optional)
```

#### 3. Security-Detections-MCP
```bash
# No installation needed - uses npx
# Just download detection content

mkdir -p detections && cd detections

# Sigma rules (~3,000+)
git clone --depth 1 --filter=blob:none --sparse https://github.com/SigmaHQ/sigma.git
cd sigma && git sparse-checkout set rules rules-threat-hunting && cd ..

# Splunk ESCU (~2,000+)
git clone --depth 1 --filter=blob:none --sparse https://github.com/splunk/security_content.git
cd security_content && git sparse-checkout set detections stories && cd ..

# Elastic rules (~1,500+)
git clone --depth 1 --filter=blob:none --sparse https://github.com/elastic/detection-rules.git
cd detection-rules && git sparse-checkout set rules && cd ..

# KQL queries (~400+)
git clone --depth 1 https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules.git kql-bertjanp
```

#### 4. Splunk MCP
```bash
git clone https://github.com/splunk/splunk-mcp-server2.git
cd splunk-mcp-server2/python
cp .env.example .env
# Edit .env with Splunk credentials
pip install -e .
```

### Configure All MCPs in Cursor

Edit your MCP configuration file:

```json
{
  "mcpServers": {
    "threat-research": {
      "command": "python",
      "args": ["-m", "threat_research_mcp.server"],
      "cwd": "c:\\Dev\\Vibe Coding\\threat-research-mcp"
    },
    "threatintel": {
      "command": "threatintel",
      "args": ["server"],
      "env": {
        "VIRUSTOTAL_API_KEY": "your_vt_key",
        "OTX_API_KEY": "your_otx_key",
        "ABUSEIPDB_API_KEY": "your_abuseipdb_key",
        "IPINFO_API_KEY": "your_ipinfo_key"
      }
    },
    "security-detections": {
      "command": "npx",
      "args": ["-y", "security-detections-mcp"],
      "env": {
        "SIGMA_PATHS": "c:\\path\\to\\detections\\sigma\\rules",
        "SPLUNK_PATHS": "c:\\path\\to\\detections\\security_content\\detections",
        "ELASTIC_PATHS": "c:\\path\\to\\detections\\detection-rules\\rules",
        "KQL_PATHS": "c:\\path\\to\\detections\\kql-bertjanp"
      }
    },
    "splunk": {
      "command": "python",
      "args": ["server.py"],
      "cwd": "c:\\path\\to\\splunk-mcp-server2\\python",
      "env": {
        "SPLUNK_HOST": "your-splunk-instance.com",
        "SPLUNK_PORT": "8089",
        "SPLUNK_USERNAME": "your-username",
        "SPLUNK_PASSWORD": "your-password"
      }
    }
  }
}
```

## Complete Workflow: ICP Canister C2 Case

Let's walk through your real-world ICP Canister C2 case using all 5 MCPs.

### Step 1: Auto-Detect Techniques (threat-research-mcp)

```python
# In your MCP client (Cursor, VS Code + Cline)
intel_to_log_sources(
    intel_text="""
    ICP Canister ID: tdtqy-oyaaa-aaaae-af2dq-cai
    
    Decentralized C2 using Internet Computer Protocol for censorship-resistant 
    command and control. Threat actor leveraging Web3/blockchain infrastructure.
    Encrypted communication channels. Proxy-like behavior through decentralized nodes.
    
    IOCs:
    - Domain: tdtqy-oyaaa-aaaae-af2dq-cai.ic0.app
    - IP: 185.220.101.45
    """,
    environment="hybrid",
    siem_platforms="splunk"
)
```

**Result:**
```json
{
  "detected_techniques": ["T1071.001", "T1090", "T1573.002"],
  "log_sources": {
    "network": {
      "proxy": {"priority": "high", "description": "Web proxy logs for C2 communication"},
      "firewall": {"priority": "high", "description": "Outbound web traffic"}
    }
  },
  "hunt_queries": {
    "T1071.001": {
      "splunk": {
        "query": "index=proxy url=*ic0.app* OR url=*tdtqy-oyaaa-aaaae-af2dq-cai* | stats count by src_ip, dest, url",
        "ready_to_run": true
      }
    }
  }
}
```

### Step 2: Generate Behavioral Hunt (threat-hunting-mcp)

```python
# Search HEARTH for C2 behavioral hunts
search_community_hunts(
    tactic="Command and Control",
    keyword="beaconing"
)

# Create behavioral hunt (survives Canister ID rotation)
create_behavioral_hunt(
    technique_id="T1071.001",
    hypothesis="Hunt for C2 beaconing patterns with regular intervals, regardless of specific Canister IDs",
    framework="PEAK"
)
```

**Result:**
```json
{
  "hunt_type": "behavioral",
  "hypothesis": "Blockchain C2 exhibits statistical regularity in beaconing patterns",
  "behavioral_indicators": [
    "Regular connection intervals (statistical analysis)",
    "Consistent payload sizes",
    "Limited unique destinations",
    "Traffic to blockchain infrastructure"
  ],
  "detection_logic": "Hunt for statistical patterns, not specific Canister IDs",
  "query": "index=proxy | stats count, stdev(bytes_out) by src_ip, dest | where stdev < 100 AND count > 20"
}
```

**Key Benefit:** This behavioral detection **survives Canister ID rotation** (adversary would need to change fundamental C2 behavior)

### Step 3: Enrich IOCs (fastmcp-threatintel)

```python
# Enrich the IP address
analyze(
    ioc="185.220.101.45",
    output_format="json"
)

# Enrich the domain
analyze(
    ioc="tdtqy-oyaaa-aaaae-af2dq-cai.ic0.app",
    output_format="json"
)
```

**Result:**
```json
{
  "ioc": "185.220.101.45",
  "type": "ip",
  "virustotal": {
    "malicious": 15,
    "suspicious": 5,
    "clean": 50,
    "reputation": "malicious"
  },
  "otx": {
    "pulses": 3,
    "tags": ["c2", "blockchain", "icp"],
    "threat_score": 8.5
  },
  "abuseipdb": {
    "abuse_confidence_score": 85,
    "total_reports": 127,
    "country": "Netherlands"
  },
  "ipinfo": {
    "asn": "AS16276",
    "org": "OVH SAS",
    "city": "Amsterdam"
  },
  "apt_attribution": {
    "confidence": "medium",
    "groups": ["Unknown APT"],
    "techniques": ["T1071.001", "T1090"]
  }
}
```

### Step 4: Check Existing Coverage (Security-Detections-MCP)

```python
# Check coverage for detected techniques
list_by_mitre(technique_id="T1071.001")

# Analyze coverage gaps
analyze_coverage(source_type="splunk")

# Check for blockchain/Web3 specific detections
search(query="blockchain web3 c2", limit=10)
```

**Result:**
```json
{
  "T1071.001": {
    "total_detections": 109,
    "by_source": {
      "sigma": 45,
      "splunk_escu": 32,
      "elastic": 22,
      "kql": 10
    },
    "coverage_gaps": [
      "Blockchain-based C2 (ICP, Ethereum)",
      "Decentralized protocols (IPFS, Tor)",
      "Web3 infrastructure abuse"
    ]
  },
  "coverage_analysis": {
    "tactic": "command-and-control",
    "coverage_percentage": 73,
    "weak_spots": ["Web3/blockchain C2", "Decentralized protocols"]
  }
}
```

### Step 5: Generate Custom Detection (threat-research-mcp + Security-Detections-MCP)

Since there's a gap for blockchain C2, generate a custom detection:

```python
# Get detection template from Security-Detections-MCP
generate_template(
    technique_id="T1071.001",
    format="splunk",
    data_source="proxy"
)

# Or use threat-research-mcp's generated query (from Step 1)
# Customize it based on the gap analysis
```

**Generated Detection:**
```spl
index=proxy earliest=-24h latest=now
(url="*ic0.app*" OR url="*raw.ic0.app*" OR url="*tdtqy-oyaaa-aaaae-af2dq-cai*")
| stats count by src_ip, dest, url, user, bytes_out
| where count > 5 OR bytes_out > 1048576
| eval threat_type="Blockchain C2 - ICP Canister"
| eval severity="high"
| table _time, src_ip, dest, url, user, count, bytes_out, threat_type, severity
```

### Step 5: Validate Query (Splunk MCP)

```python
# Validate the generated query
validate_spl(
    query="""
    index=proxy earliest=-24h latest=now
    (url="*ic0.app*" OR url="*raw.ic0.app*" OR url="*tdtqy-oyaaa-aaaae-af2dq-cai*")
    | stats count by src_ip, dest, url, user, bytes_out
    | where count > 5 OR bytes_out > 1048576
    | eval threat_type="Blockchain C2 - ICP Canister"
    | eval severity="high"
    | table _time, src_ip, dest, url, user, count, bytes_out, threat_type, severity
    """
)
```

**Result:**
```json
{
  "is_safe": true,
  "risk_score": 5,
  "risks": [],
  "recommendations": [],
  "performance_notes": [
    "Time constraint present (earliest=-24h)",
    "Reasonable field selection",
    "Efficient aggregation"
  ]
}
```

### Step 7: Execute Query (Splunk MCP)

```python
# Execute the validated query
search_oneshot(
    query="""
    index=proxy earliest=-24h latest=now
    (url="*ic0.app*" OR url="*raw.ic0.app*" OR url="*tdtqy-oyaaa-aaaae-af2dq-cai*")
    | stats count by src_ip, dest, url, user, bytes_out
    | where count > 5 OR bytes_out > 1048576
    | eval threat_type="Blockchain C2 - ICP Canister"
    | eval severity="high"
    | table _time, src_ip, dest, url, user, count, bytes_out, threat_type, severity
    """,
    output_format="markdown"
)
```

**Result:**
```markdown
| _time | src_ip | dest | url | user | count | bytes_out | threat_type | severity |
|-------|--------|------|-----|------|-------|-----------|-------------|----------|
| 2026-04-11 10:23:45 | 10.0.1.50 | 185.220.101.45 | https://tdtqy-oyaaa-aaaae-af2dq-cai.ic0.app | jdoe | 127 | 2456789 | Blockchain C2 - ICP Canister | high |
| 2026-04-11 10:25:12 | 10.0.1.51 | 185.220.101.45 | https://tdtqy-oyaaa-aaaae-af2dq-cai.raw.ic0.app | msmith | 45 | 987654 | Blockchain C2 - ICP Canister | high |
| 2026-04-11 10:27:33 | 10.0.2.10 | 185.220.101.46 | https://tdtqy-oyaaa-aaaae-af2dq-cai.ic0.app | admin | 23 | 1234567 | Blockchain C2 - ICP Canister | high |
```

🎯 **Detection confirmed!** Three hosts are communicating with the malicious ICP Canister.

### Step 8: Create Production Detection (Security-Detections-MCP)

```python
# Save as a production detection
# This would be done via your detection repo workflow
# Security-Detections-MCP can help generate the proper format

# For Splunk ESCU format:
# - Create YAML with proper metadata
# - Include MITRE mappings
# - Add analytic story
# - Submit PR to security_content repo
```

## Workflow Patterns

### Pattern 1: Phishing Incident Investigation

```
1. threat-research-mcp: Auto-detect techniques from phishing report
   → T1566.001, T1059.001, T1105

2. fastmcp-threatintel: Enrich email IOCs
   → Sender IP reputation, domain age, malware hashes

3. Security-Detections-MCP: Check existing coverage
   → 45 Sigma rules for T1566.001, 32 for T1059.001

4. threat-research-mcp: Generate log source recommendations
   → Email gateway logs, PowerShell logging, proxy logs

5. Splunk MCP: Validate and execute queries
   → Find affected users, timeline reconstruction
```

### Pattern 2: Ransomware Detection

```
1. threat-research-mcp: Auto-detect from ransomware intel
   → T1486, T1070.001, T1562.001

2. Security-Detections-MCP: Analyze procedure coverage
   → 109 detections for T1486, gaps for NanoDump

3. threat-research-mcp: Generate queries for gaps
   → Sysmon Event ID 11 for mass file operations

4. Splunk MCP: Validate and test
   → Execute against test data, tune thresholds

5. fastmcp-threatintel: Enrich ransomware IOCs
   → Ransom note Bitcoin addresses, C2 IPs
```

### Pattern 3: APT Campaign Analysis

```
1. Security-Detections-MCP: Get APT29 techniques
   → 66 techniques used by APT29

2. Security-Detections-MCP: Analyze coverage
   → 48 covered, 18 gaps, 73% coverage

3. threat-research-mcp: Generate queries for gaps
   → T1021.007 (Cloud Services), T1556.006 (MFA)

4. fastmcp-threatintel: Enrich APT29 IOCs
   → Known infrastructure, TTPs, attribution

5. Splunk MCP: Execute hunt queries
   → Search for APT29 indicators in environment
```

## Integration Benefits

### 1. Complete Automation
- **Before:** Manual technique mapping, manual IOC enrichment, manual detection search
- **After:** Paste threat intel → get techniques → enriched IOCs → existing coverage → validated queries → results

### 2. No Duplicate Work
- Security-Detections-MCP shows you 8,200+ existing detections
- Don't recreate what already exists
- Focus on actual gaps

### 3. Safe Query Execution
- Splunk MCP validates before execution
- Risk scoring prevents destructive queries
- Data sanitization protects sensitive info

### 4. Rich Context
- fastmcp-threatintel adds reputation, geolocation, APT attribution
- Security-Detections-MCP shows procedure-level coverage
- threat-research-mcp provides log source guidance

## Best Practices

### 1. Always Start with threat-research-mcp
```python
# Start here for any threat intelligence
intel_to_log_sources(intel_text="...")
```

### 2. Enrich IOCs Early
```python
# Enrich before searching/hunting
analyze(ioc="185.220.101.45")
```

### 3. Check Existing Coverage Before Creating
```python
# Don't recreate existing detections
list_by_mitre(technique_id="T1071.001")
analyze_coverage()
```

### 4. Always Validate Before Executing
```python
# Validate first
validation = validate_spl(query="...")
if validation["is_safe"]:
    search_oneshot(query="...")
```

### 5. Use Procedure-Level Analysis
```python
# Go beyond technique-level
analyze_procedure_coverage(technique_id="T1003.001")
# Shows: LSASS access ✓, Mimikatz ✓, NanoDump ✗
```

## Tool Reference

### threat-research-mcp (17 tools)
- `intel_to_log_sources` - Auto-detect techniques → log sources
- `recommend_log_sources` - Get log sources for known techniques
- `extract_iocs` - Extract IOCs from text
- `analysis_product` - Full workflow analysis
- `attack_map` - Map behaviors to ATT&CK
- `generate_sigma` - Generate Sigma rules
- `validate_sigma` - Validate Sigma YAML
- And 10 more...

### fastmcp-threatintel (7 tools)
- `analyze` - Comprehensive IOC analysis
- `virustotal_scan` - VirusTotal reputation
- `otx_lookup` - AlienVault OTX intelligence
- `abuseipdb_check` - IP reputation
- `ipinfo_lookup` - Geolocation and ASN
- `batch_analyze` - Bulk IOC analysis
- `generate_report` - HTML/PDF reports

### Security-Detections-MCP (71+ tools)
- `search` - Full-text search across 8,200+ rules
- `list_by_mitre` - Filter by technique
- `analyze_coverage` - Coverage by tactic
- `identify_gaps` - Find detection gaps
- `analyze_procedure_coverage` - Procedure-level analysis
- `generate_template` - Detection templates
- `analyze_actor_coverage` - APT coverage analysis
- And 64 more...

### Splunk MCP (7 tools)
- `validate_spl` - Query validation with risk scoring
- `search_oneshot` - Execute blocking searches
- `search_export` - Stream large results
- `get_indexes` - List available indexes
- `get_saved_searches` - Access saved searches
- `run_saved_search` - Execute saved searches
- `get_config` - Server configuration

## Troubleshooting

### Issue: "Too many MCP servers, slow startup"

**Solution:** Only enable the MCPs you need for your current task
```json
{
  "mcpServers": {
    "threat-research": { ... },  // Always enable
    "security-detections": { ... }  // Enable when checking coverage
    // Disable threatintel and splunk if not needed
  }
}
```

### Issue: "API rate limits hit"

**Solution:** Use caching and batch operations
```python
# fastmcp-threatintel has built-in caching
# Set CACHE_TTL=3600 in .env

# Batch analyze multiple IOCs at once
batch_analyze(iocs=["ip1", "ip2", "ip3"])
```

### Issue: "Query validation fails"

**Solution:** Review Splunk MCP recommendations
```python
validation = validate_spl(query="...")
print(validation["recommendations"])
# Apply recommendations and re-validate
```

## Future Enhancements

### Planned Integrations

1. **Direct API Integration**: MCPs call each other directly
2. **Shared Context**: Pass context between MCPs automatically
3. **Unified Dashboard**: Single interface for all 4 MCPs
4. **Automated Workflows**: Pre-built pipelines for common scenarios

## References

- [threat-research-mcp](https://github.com/harshdthakur6293/threat-research-mcp)
- [fastmcp-threatintel](https://github.com/4R9UN/fastmcp-threatintel)
- [Security-Detections-MCP](https://github.com/MHaggis/Security-Detections-MCP)
- [Splunk MCP](https://github.com/splunk/splunk-mcp-server2)
- [Model Context Protocol](https://modelcontextprotocol.io/)
