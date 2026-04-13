# Optional MCP Integrations

`threat-research-mcp` works **completely standalone** with no dependencies on other MCPs. However, you can optionally install additional MCPs to unlock enhanced features.

## Overview

The integration layer provides:
- **Graceful degradation**: Works without any optional MCPs installed
- **Automatic detection**: Detects which MCPs are available at runtime
- **Enhanced workflows**: Orchestrates multiple MCPs when available
- **Easy setup**: Simple environment variables to enable integrations

## Available Integrations

### 1. fastmcp-threatintel (IOC Enrichment)

**Purpose**: Enrich IOCs with reputation data from VirusTotal, OTX, AbuseIPDB, IPinfo

**Install**:
```bash
pip install fastmcp-threatintel
threatintel setup  # Configure API keys
```

**Configure**:
```bash
# .env or environment
export ENABLE_FASTMCP_THREATINTEL=true
export VIRUSTOTAL_API_KEY=your_key_here
export OTX_API_KEY=your_key_here
export ABUSEIPDB_API_KEY=your_key_here  # optional
export IPINFO_API_KEY=your_key_here     # optional
```

**Features Unlocked**:
- Automatic IOC enrichment in `enhanced_intel_analysis`
- APT attribution for threat actors
- Malware family identification

---

### 2. Security-Detections-MCP (Coverage Analysis)

**Purpose**: Search 8,200+ existing detection rules, analyze coverage gaps

**Install**:
```bash
# No installation needed - uses npx
# Just set up your detection rule paths
```

**Configure**:
```bash
# .env or environment
export ENABLE_SECURITY_DETECTIONS_MCP=true
export SIGMA_PATHS=/path/to/sigma/rules
export SPLUNK_PATHS=/path/to/splunk/rules      # optional
export ELASTIC_PATHS=/path/to/elastic/rules    # optional
```

**Features Unlocked**:
- Check existing coverage for detected techniques
- Find procedure-level gaps in detections
- Get production-ready Sigma/SPL templates

---

### 3. threat-hunting-mcp-server (Behavioral Hunting)

**Purpose**: Generate behavioral hunt hypotheses, HEARTH community hunts

**Install**:
```bash
git clone https://github.com/THORCollective/threat-hunting-mcp-server
cd threat-hunting-mcp-server
pip install -r requirements.txt
```

**Configure**:
```bash
# .env or environment
export ENABLE_THREAT_HUNTING_MCP=true
export THREAT_HUNTING_MCP_PATH=/path/to/threat-hunting-mcp-server
```

**Features Unlocked**:
- Behavioral hunt hypotheses (Pyramid of Pain)
- HEARTH community hunt library
- Cognitive bias detection
- Graph-based attack analysis

---

### 4. splunk-mcp-server2 (Query Validation)

**Purpose**: Validate SPL queries with risk scoring, safe execution

**Install**:
```bash
git clone https://github.com/splunk/splunk-mcp-server2
cd splunk-mcp-server2
pip install -r requirements.txt
```

**Configure**:
```bash
# .env or environment
export ENABLE_SPLUNK_MCP=true
export SPLUNK_MCP_PATH=/path/to/splunk-mcp-server2
export SPLUNK_HOST=your-splunk-host.com
export SPLUNK_PORT=8089
export SPLUNK_USERNAME=your_username
export SPLUNK_PASSWORD=your_password
```

**Features Unlocked**:
- Automatic SPL query validation (risk scoring 0-100)
- Safe query execution against live Splunk
- Index and saved search discovery

---

## Usage

### Check Integration Status

```python
# Via MCP tool
{
  "tool": "get_integration_status_tool",
  "arguments": {}
}
```

Example output:
```json
{
  "integrations": {
    "fastmcp-threatintel": {
      "available": true,
      "purpose": "IOC enrichment (VirusTotal, OTX, AbuseIPDB, IPinfo)"
    },
    "security-detections": {
      "available": false,
      "install": "npx -y security-detections-mcp"
    }
  },
  "summary": {
    "available_count": 1,
    "standalone_mode": false
  }
}
```

### Enhanced Analysis (All Integrations)

```python
# Via MCP tool
{
  "tool": "enhanced_intel_analysis_tool",
  "arguments": {
    "intel_text": "APT29 using ICP Canister C2...",
    "environment": "hybrid",
    "siem_platforms": "splunk,sentinel",
    "enrich_iocs": true,
    "check_coverage": true,
    "generate_behavioral_hunts": true
  }
}
```

This single tool call will:
1. **Auto-detect techniques** (built-in)
2. **Generate log sources** (built-in)
3. **Enrich IOCs** (if fastmcp-threatintel available)
4. **Check coverage** (if Security-Detections-MCP available)
5. **Generate behavioral hunts** (if threat-hunting-mcp available)

### Standalone Mode

If no optional MCPs are installed, `enhanced_intel_analysis_tool` still works:

```json
{
  "core_analysis": {
    "detected_techniques": ["T1059.001", "T1071.001"],
    "log_sources": {...},
    "hunt_queries": {...}
  },
  "enhanced_features": {
    "ioc_enrichment": {
      "enabled": false,
      "message": "fastmcp-threatintel not available. Install: pip install fastmcp-threatintel"
    }
  }
}
```

---

## Complete Setup Example

```bash
# 1. Install threat-research-mcp (required)
git clone https://github.com/harshthakur6293/threat-research-mcp
cd threat-research-mcp
pip install -e .[dev]

# 2. Install optional MCPs (choose which ones you want)

# IOC enrichment
pip install fastmcp-threatintel
threatintel setup

# Coverage analysis (no install needed)
export SIGMA_PATHS=/path/to/sigma/rules

# Behavioral hunting
git clone https://github.com/THORCollective/threat-hunting-mcp-server ../threat-hunting-mcp-server
cd ../threat-hunting-mcp-server && pip install -r requirements.txt

# Query validation
git clone https://github.com/splunk/splunk-mcp-server2 ../splunk-mcp-server2
cd ../splunk-mcp-server2 && pip install -r requirements.txt

# 3. Configure environment
cat > .env << EOF
# Enable optional integrations
ENABLE_FASTMCP_THREATINTEL=true
ENABLE_SECURITY_DETECTIONS_MCP=true
ENABLE_THREAT_HUNTING_MCP=true
ENABLE_SPLUNK_MCP=true

# API keys
VIRUSTOTAL_API_KEY=your_key
OTX_API_KEY=your_key

# Paths
SIGMA_PATHS=/path/to/sigma/rules
THREAT_HUNTING_MCP_PATH=/path/to/threat-hunting-mcp-server
SPLUNK_MCP_PATH=/path/to/splunk-mcp-server2

# Splunk connection
SPLUNK_HOST=your-splunk.com
SPLUNK_PORT=8089
EOF

# 4. Start threat-research-mcp
cd threat-research-mcp
python -m threat_research_mcp.server
```

---

## Integration Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                  threat-research-mcp                        │
│                  (Standalone Core)                          │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Core Features (Always Available)                    │   │
│  │ - IOC extraction                                    │   │
│  │ - ATT&CK technique detection                        │   │
│  │ - Log source recommendations                        │   │
│  │ - SIEM query generation                             │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Optional Integration Layer (MCPClient)              │   │
│  │ - Auto-detects available MCPs                       │   │
│  │ - Graceful degradation                              │   │
│  │ - Environment-based configuration                   │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
        ▼                   ▼                   ▼
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│ fastmcp-     │    │ Security-    │    │ threat-      │
│ threatintel  │    │ Detections-  │    │ hunting-mcp  │
│              │    │ MCP          │    │              │
│ (optional)   │    │ (optional)   │    │ (optional)   │
└──────────────┘    └──────────────┘    └──────────────┘
```

---

## FAQ

### Do I need to install all optional MCPs?

No! Install only the ones you need. `threat-research-mcp` works perfectly standalone.

### What happens if an optional MCP is not available?

The tool gracefully degrades and provides helpful installation instructions in the output.

### Can I use threat-research-mcp in parallel with these MCPs?

Yes! You can:
1. Use the **integration layer** (recommended) - automatic orchestration
2. Use **manual chaining** - call each MCP separately via your MCP client

### How do I disable an integration?

Set the environment variable to `false`:
```bash
export ENABLE_FASTMCP_THREATINTEL=false
```

### Can I add my own custom MCP integrations?

Yes! Edit `src/threat_research_mcp/integrations/mcp_client.py` and add your MCP to the `MCPIntegrationManager._initialize_clients()` method.

---

## Next Steps

1. **Start simple**: Use `threat-research-mcp` standalone
2. **Add IOC enrichment**: Install `fastmcp-threatintel` for reputation data
3. **Check coverage**: Add `Security-Detections-MCP` to find existing rules
4. **Go behavioral**: Add `threat-hunting-mcp` for Pyramid of Pain hunting
5. **Validate queries**: Add `splunk-mcp-server2` for production-ready SPL

See [complete-mcp-ecosystem.md](./complete-mcp-ecosystem.md) for detailed workflow examples.
