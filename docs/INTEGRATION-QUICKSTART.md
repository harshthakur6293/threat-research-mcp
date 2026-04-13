# Integration Quick Start

## TL;DR

`threat-research-mcp` now supports **optional** integration with 4 specialist MCPs. You can use it standalone or unlock enhanced features by installing additional MCPs.

## Quick Decision Tree

```
Do you need IOC reputation data (VirusTotal, OTX)?
├─ YES → Install fastmcp-threatintel
└─ NO  → Skip it

Do you need to check existing detection coverage?
├─ YES → Install Security-Detections-MCP
└─ NO  → Skip it

Do you need behavioral hunting (Pyramid of Pain)?
├─ YES → Install threat-hunting-mcp
└─ NO  → Skip it

Do you need to validate Splunk queries?
├─ YES → Install Splunk MCP
└─ NO  → Skip it
```

## Installation Paths

### Minimal (Standalone)
```bash
# Just threat-research-mcp
git clone https://github.com/harshthakur6293/threat-research-mcp
cd threat-research-mcp
pip install -e ".[dev]"
```

**You get**: IOC extraction, technique detection, log sources, SIEM queries, Sigma drafts

---

### + IOC Enrichment
```bash
# Add fastmcp-threatintel
pip install fastmcp-threatintel
threatintel setup  # Configure API keys

# Enable integration
export ENABLE_FASTMCP_THREATINTEL=true
export VIRUSTOTAL_API_KEY=your_key
export OTX_API_KEY=your_key
```

**You get**: + Reputation scores, malware families, APT attribution

---

### + Coverage Analysis
```bash
# Add Security-Detections-MCP (no install needed)
export ENABLE_SECURITY_DETECTIONS_MCP=true
export SIGMA_PATHS=/path/to/sigma/rules
```

**You get**: + Check against 8,200+ existing rules, find gaps

---

### + Behavioral Hunting
```bash
# Add threat-hunting-mcp
git clone https://github.com/THORCollective/threat-hunting-mcp-server
cd threat-hunting-mcp-server
pip install -r requirements.txt

# Enable integration
export ENABLE_THREAT_HUNTING_MCP=true
export THREAT_HUNTING_MCP_PATH=/path/to/threat-hunting-mcp-server
```

**You get**: + Behavioral hunt hypotheses, HEARTH community hunts

---

### + Query Validation
```bash
# Add Splunk MCP
git clone https://github.com/splunk/splunk-mcp-server2
cd splunk-mcp-server2
pip install -r requirements.txt

# Enable integration
export ENABLE_SPLUNK_MCP=true
export SPLUNK_MCP_PATH=/path/to/splunk-mcp-server2
export SPLUNK_HOST=your-splunk.com
export SPLUNK_PORT=8089
```

**You get**: + Query risk scoring, safe execution

---

## Usage

### Check What's Available
```json
{
  "tool": "get_integration_status",
  "arguments": {}
}
```

### One-Click Analysis (All Available MCPs)
```json
{
  "tool": "enhanced_intel_analysis",
  "arguments": {
    "intel_text": "Paste your threat intel here...",
    "enrich_iocs": true,
    "check_coverage": true,
    "generate_behavioral_hunts": true
  }
}
```

This automatically uses all available MCPs and gracefully degrades if any are missing.

### Manual Chaining (Advanced)
Call each MCP tool separately via your MCP client (Cursor, VS Code, Cline).

---

## Environment Variables Cheat Sheet

```bash
# Enable integrations (set to "true" to enable)
ENABLE_FASTMCP_THREATINTEL=true
ENABLE_SECURITY_DETECTIONS_MCP=true
ENABLE_THREAT_HUNTING_MCP=true
ENABLE_SPLUNK_MCP=true

# fastmcp-threatintel
VIRUSTOTAL_API_KEY=your_key
OTX_API_KEY=your_key
ABUSEIPDB_API_KEY=your_key  # optional
IPINFO_API_KEY=your_key     # optional

# Security-Detections-MCP
SIGMA_PATHS=/path/to/sigma/rules
SPLUNK_PATHS=/path/to/splunk/rules      # optional
ELASTIC_PATHS=/path/to/elastic/rules    # optional

# threat-hunting-mcp
THREAT_HUNTING_MCP_PATH=/path/to/threat-hunting-mcp-server

# Splunk MCP
SPLUNK_MCP_PATH=/path/to/splunk-mcp-server2
SPLUNK_HOST=your-splunk.com
SPLUNK_PORT=8089
SPLUNK_USERNAME=your_username
SPLUNK_PASSWORD=your_password
```

---

## What Happens When MCPs Are Missing?

The tool **gracefully degrades** and provides helpful messages:

```json
{
  "core_analysis": {
    "detected_techniques": ["T1059.001"],
    "log_sources": [...],
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

## Recommended Setups

### Security Analyst (Minimal)
- `threat-research-mcp` only
- **Use case**: Quick IOC extraction, technique mapping, log source recommendations

### Detection Engineer (Standard)
- `threat-research-mcp`
- `Security-Detections-MCP` (coverage checks)
- **Use case**: Build detections without duplicating existing rules

### Threat Hunter (Advanced)
- `threat-research-mcp`
- `fastmcp-threatintel` (IOC enrichment)
- `threat-hunting-mcp` (behavioral hunting)
- **Use case**: Hunt for persistent threats that survive IOC rotation

### SOC Lead (Enterprise)
- All 5 MCPs
- **Use case**: Complete threat intel pipeline from ingestion to validated production detections

---

## Next Steps

1. **Start simple**: Use standalone mode to understand the core features
2. **Add one integration**: Pick the one that solves your biggest pain point
3. **Test it**: Run `get_integration_status` to verify setup
4. **Use enhanced_intel_analysis**: Let the tool orchestrate everything
5. **Iterate**: Add more integrations as needed

See [`docs/OPTIONAL-INTEGRATIONS.md`](./OPTIONAL-INTEGRATIONS.md) for detailed setup instructions.
