# Threat Research MCP v0.5.0-dev

[![CI](https://github.com/harshdthakur6293/threat-research-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/harshdthakur6293/threat-research-mcp/actions/workflows/ci.yml)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://img.shields.io/badge/tests-138%20passing-brightgreen.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**A Model Context Protocol (MCP) server for defensive threat intelligence analysis and detection engineering.**

This tool helps security analysts extract IOCs from threat intelligence, enrich them with multiple sources, map to ATT&CK techniques, and generate detection rules. It's designed for SOC analysts, threat hunters, and detection engineers who need to quickly analyze threat reports and create actionable detections.

**Current Status:** v0.5.0-dev (Phase 1 complete: LangGraph foundation + Research Agent v2)

---

## What This Tool Does

### Core Functionality

1. **IOC Extraction**
   - Extracts IPs, domains, URLs, file hashes (MD5/SHA1/SHA256) from text
   - Uses regex patterns (not ML/AI)
   - Returns structured JSON with IOC types

2. **Multi-Source Enrichment** (NEW in v0.5.0)
   - Enriches IOCs with 7+ threat intelligence sources
   - Tier 1: VirusTotal, AlienVault OTX, AbuseIPDB, URLhaus, ThreatFox
   - Tier 2: Shodan, GreyNoise (requires API keys)
   - Returns reputation, tags, first/last seen dates
   - **Note:** Currently returns mock data for testing; real API integration in progress

3. **Confidence Scoring** (NEW in v0.5.0)
   - Calculates confidence based on:
     - Number of sources (more sources = higher confidence)
     - Source agreement (consistent results = higher confidence)
     - Source reputation (reliable sources = higher confidence)
     - Data freshness (recent data = higher confidence)
   - Returns score 0.0-1.0 with factor breakdown

4. **ATT&CK Technique Mapping**
   - Extracts technique IDs (e.g., T1059.001) from text
   - Keyword-based heuristics (not ML/AI)
   - Maps to MITRE ATT&CK framework

5. **Log Source Recommendations**
   - Provides specific log sources for 20+ common techniques
   - Includes Windows Event IDs, Sysmon events, CloudTrail, etc.
   - Environment-specific (AWS, Azure, GCP, on-prem)

6. **SIEM Query Generation**
   - Generates hunt queries for Splunk, Sentinel, Elastic
   - Based on ATT&CK techniques
   - Ready to copy-paste into SIEM

7. **Detection Rule Drafting**
   - Generates Sigma rules (universal format)
   - Includes KQL (Sentinel) and SPL (Splunk) variants
   - Basic validation included

8. **Threat Actor Profiles**
   - 6 pre-built profiles (APT29, APT28, APT41, UNC2452, UNC3890, Lazarus)
   - Based on public intelligence reports
   - Useful for testing detections

---

## What This Tool Does NOT Do

- ❌ Does not perform active scanning or reconnaissance
- ❌ Does not execute malware or analyze binaries
- ❌ Does not access live threat feeds automatically (you provide the text)
- ❌ Does not make attribution claims (only provides "assessed" confidence)
- ❌ Does not replace human analysis (it's a tool to assist analysts)
- ❌ Does not guarantee 100% accuracy (always validate results)

---

## Architecture

### v0.5.0: Multi-Agent System (Current)

```
┌─────────────────────────────────────────────────────────┐
│  LangGraph Orchestrator                                 │
│  ┌───────────────────────────────────────────────────┐ │
│  │  Research Agent v2                                │ │
│  │  - Extracts IOCs                                  │ │
│  │  - Enriches with 7+ sources                       │ │
│  │  - Calculates confidence                          │ │
│  └───────────────────────────────────────────────────┘ │
│                                                         │
│  ┌───────────────────────────────────────────────────┐ │
│  │  Hunting Agent (Coming in Week 5-6)              │ │
│  │  - Generates hunt hypotheses                      │ │
│  │  - Framework-based (PEAK, TaHiTI, SQRRL)         │ │
│  └───────────────────────────────────────────────────┘ │
│                                                         │
│  ┌───────────────────────────────────────────────────┐ │
│  │  Detection Agent (Coming in Week 5-6)            │ │
│  │  - Generates Sigma/KQL/SPL rules                  │ │
│  │  - Multi-schema support                           │ │
│  └───────────────────────────────────────────────────┘ │
│                                                         │
│  ┌───────────────────────────────────────────────────┐ │
│  │  Reviewer Agent (Coming in Week 7-8)             │ │
│  │  - Validates outputs                              │ │
│  │  - Triggers refinement loops                      │ │
│  └───────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

**Key Difference from v0.4:**
- v0.4: Sequential pipeline (agents don't communicate)
- v0.5.0: True multi-agent (agents share state, validation loops, human-in-the-loop)

---

## Installation

### Prerequisites

- **Python 3.9+** (required for LangGraph)
- **Python 3.10+** (recommended for MCP server features)

```bash
python --version  # Check your version
```

### Quick Install

```bash
git clone https://github.com/harshdthakur6293/threat-research-mcp.git
cd threat-research-mcp

# Create virtual environment
python3.10 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Install
pip install -e ".[dev]"
```

### Verify Installation

```bash
# Run tests (138 tests should pass)
pytest tests/ --ignore=tests/test_langgraph_orchestrator.py -v

# Test enrichment framework
pytest tests/test_enrichment.py -v

# Test Research Agent v2
pytest tests/test_research_agent_v2.py -v
```

---

## Usage

### 1. Basic IOC Extraction

```python
from threat_research_mcp.tools.extract_iocs import extract_iocs_json

intel_text = """
APT29 campaign detected.
IOCs: 185.220.101.45, malicious-c2.com
Hash: 1234567890abcdef1234567890abcdef
"""

result = extract_iocs_json(intel_text)
# Returns: {"ips": ["185.220.101.45"], "domains": ["malicious-c2.com"], ...}
```

### 2. Multi-Source Enrichment (NEW)

```python
from threat_research_mcp.agents.research_agent_v2 import ResearchAgentV2
from threat_research_mcp.schemas.workflow_state import create_initial_state

# Initialize agent
agent = ResearchAgentV2(api_keys={
    "VirusTotal": "your_api_key",  # Optional
    "Shodan": "your_api_key",       # Optional
})

# Create state
state = create_initial_state(
    intel_text="APT29 campaign: IP 185.220.101.45"
)

# Execute
result = agent.execute(state)

# Access results
findings = result["research_findings"]["findings"]
print(f"IOCs: {findings['iocs']}")
print(f"Confidence: {findings['confidence_analysis']['overall_confidence']}")
```

### 3. ATT&CK Technique Mapping

```python
from threat_research_mcp.extensions.mitre_attack_integration import extract_techniques_from_intel

intel_text = "Adversary used PowerShell for execution (T1059.001)"
techniques = extract_techniques_from_intel(intel_text)
# Returns: [{"technique_id": "T1059.001", "name": "PowerShell", ...}]
```

### 4. Generate SIEM Queries

```python
from threat_research_mcp.detection.log_source_mapper import generate_hunt_queries

queries = generate_hunt_queries(
    techniques=["T1059.001"],
    siem_platforms=["splunk", "sentinel"]
)
# Returns ready-to-run Splunk and Sentinel queries
```

### 5. Generate Sigma Rule

```python
from threat_research_mcp.detection.sigma_generator import generate_sigma_rule

rule = generate_sigma_rule(
    title="PowerShell Encoded Command",
    description="Detects encoded PowerShell execution",
    techniques=["T1059.001"],
    log_source="windows",
    detection_logic={
        "selection": {
            "EventID": 4688,
            "CommandLine|contains": "powershell -enc"
        }
    }
)
```

---

## Test Coverage

**138 tests passing** across:

- ✅ IOC extraction (2 tests)
- ✅ Enrichment framework (25 tests)
- ✅ Research Agent v2 (13 tests)
- ✅ Threat actor scenarios (29 tests)
- ✅ Log source mapping (12 tests)
- ✅ MCP integrations (20 tests)
- ✅ Detection generation (3 tests)
- ✅ Ingestion (20 tests)
- ✅ Storage (3 tests)
- ✅ Workflow (11 tests)

```bash
# Run all tests
pytest tests/ --ignore=tests/test_langgraph_orchestrator.py -v

# Run specific test suite
pytest tests/test_enrichment.py -v
pytest tests/test_research_agent_v2.py -v
pytest tests/test_threat_actor_scenarios.py -v
```

---

## Documentation

### Getting Started
- [`docs/LANGGRAPH-QUICKSTART.md`](docs/LANGGRAPH-QUICKSTART.md) - LangGraph setup and usage
- [`docs/MIGRATION-V04-TO-V05.md`](docs/MIGRATION-V04-TO-V05.md) - Upgrading from v0.4
- [`docs/using-as-a-security-engineer.md`](docs/using-as-a-security-engineer.md) - End-to-end workflows

### Architecture
- [`docs/ROADMAP-V2-PLAN.md`](docs/ROADMAP-V2-PLAN.md) - Complete v2.0 roadmap (150+ pages)
- [`docs/TRUE-MULTI-AGENT-DESIGN.md`](docs/TRUE-MULTI-AGENT-DESIGN.md) - Multi-agent architecture
- [`docs/architecture.md`](docs/architecture.md) - System design

### Features
- [`docs/log-source-recommendations.md`](docs/log-source-recommendations.md) - Log source mapping
- [`docs/automatic-technique-detection.md`](docs/automatic-technique-detection.md) - ATT&CK mapping
- [`docs/THREAT-ACTOR-TESTING.md`](docs/THREAT-ACTOR-TESTING.md) - Threat actor profiles

### Development
- [`PHASE1-SUMMARY.md`](PHASE1-SUMMARY.md) - Phase 1 completion summary
- [`WEEK3-4-SUMMARY.md`](WEEK3-4-SUMMARY.md) - Week 3-4 completion summary
- [`docs/tool-contracts.md`](docs/tool-contracts.md) - MCP tool specifications

---

## Roadmap

### ✅ Phase 1: Foundation (Complete)
- **Week 1-2:** LangGraph infrastructure, base agent framework
- **Week 3-4:** Research Agent v2 with multi-source enrichment

### 🚧 Phase 1: Remaining (In Progress)
- **Week 5-6:** Hunting & Detection Agents v2
  - Framework-based hunting (PEAK, TaHiTI, SQRRL)
  - Multi-schema detection (Sigma, KQL, SPL, EQL)
  - HEARTH integration (50+ community hunts)

- **Week 7-8:** Reviewer Agent & Validation
  - Multi-factor validation
  - Attribution confidence engine
  - Alternative hypotheses
  - Human-in-the-loop prompts

### 📅 Future Phases
- **Phase 2:** CRADLE integration (visualization, collaboration)
- **Phase 3:** Graph intelligence (NetworkX → Neo4j)
- **Phase 4:** Advanced features (ML, temporal analysis)

See [`docs/ROADMAP-V2-PLAN.md`](docs/ROADMAP-V2-PLAN.md) for complete details.

---

## Limitations & Caveats

### Current Limitations

1. **Enrichment Sources**
   - Currently returns mock data for testing
   - Real API integration in progress
   - Requires API keys for Tier 2 sources (Shodan, GreyNoise)

2. **IOC Extraction**
   - Regex-based (not ML/AI)
   - May have false positives/negatives
   - Does not defang IOCs automatically

3. **ATT&CK Mapping**
   - Keyword-based heuristics
   - May miss techniques without explicit IDs
   - Requires manual validation

4. **Detection Rules**
   - Generated rules are drafts, not production-ready
   - Require tuning for your environment
   - May have false positives

5. **Attribution**
   - Never claims "confirmed" attribution
   - Always uses "assessed" or "potential"
   - Confidence scores are estimates, not guarantees

### Best Practices

- ✅ Always validate IOC extraction results
- ✅ Review enrichment data before taking action
- ✅ Test detection rules in dev/test environment first
- ✅ Tune rules for your specific environment
- ✅ Treat attribution as hypothesis, not fact
- ✅ Use confidence scores as guidance, not absolute truth

---

## Contributing

We welcome contributions! See areas where you can help:

1. **Add Real API Integrations**
   - Replace mock data with real API calls
   - Add error handling and rate limiting
   - See `src/threat_research_mcp/enrichment/tier1/`

2. **Add More Enrichment Sources**
   - Tier 3: C2 trackers, phishing feeds, malware sandboxes
   - Tier 4: LOLBins (LOLBAS, GTFOBins, WADComs)
   - See `src/threat_research_mcp/enrichment/`

3. **Improve IOC Extraction**
   - Better regex patterns
   - Support for more IOC types
   - Defanging support
   - See `src/threat_research_mcp/tools/extract_iocs.py`

4. **Add Threat Actor Profiles**
   - Based on public intelligence reports
   - See `tests/threat_actor_profiles.py`

5. **Improve Detection Rules**
   - Better Sigma rule generation
   - More schema support (EQL, YARA, etc.)
   - See `src/threat_research_mcp/detection/`

### Development Setup

```bash
git clone https://github.com/harshdthakur6293/threat-research-mcp.git
cd threat-research-mcp
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install

# Run tests
pytest tests/ -v

# Run linting
ruff check src/ tests/

# Run security scan
bandit -r src/
```

---

## Security

**Defensive Use Only:** This tool is designed for defensive security operations in authorized environments.

- ❌ Do not use for offensive security operations
- ❌ Do not use for unauthorized access or reconnaissance
- ❌ Do not use to generate malware or exploits

**Reporting Vulnerabilities:** Use GitHub's Security → Report a vulnerability feature.

See [`SECURITY.md`](SECURITY.md) for full security policy.

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

## Acknowledgments

Built on:
- [Model Context Protocol](https://modelcontextprotocol.io/) by Anthropic
- [LangGraph](https://github.com/langchain-ai/langgraph) for multi-agent orchestration
- [MITRE ATT&CK](https://attack.mitre.org/) framework
- [Sigma Rules](https://github.com/SigmaHQ/sigma)

Special thanks to the threat intelligence community for public reporting.

---

## Support

- **Documentation:** [`docs/`](docs/)
- **Issues:** [GitHub Issues](https://github.com/harshdthakur6293/threat-research-mcp/issues)
- **Discussions:** [GitHub Discussions](https://github.com/harshdthakur6293/threat-research-mcp/discussions)

---

**Built for security analysts, by security analysts. Contributions welcome.**
