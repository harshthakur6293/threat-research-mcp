# Threat Actor Scenario Testing

## Overview

`threat-research-mcp` includes comprehensive testing against realistic threat actor profiles for APT groups and UNC (Uncategorized) groups. This allows you to validate the MCP tools against known threat intelligence and ensure accurate IOC extraction, technique detection, and log source recommendations.

## Threat Actor Profiles

The repository includes detailed profiles for 6 major threat actors:

| Actor | Attribution | Motivation | Sophistication | Targets |
|-------|-------------|------------|----------------|---------|
| **APT29** | Russian SVR | Espionage | Advanced | Government, Think Tanks, Healthcare |
| **APT28** | Russian GRU | Espionage, Disruption | Advanced | Government, Military, Media |
| **APT41** | Chinese State + Financial | Espionage, Financial Gain | Advanced | Healthcare, Telecom, Gaming |
| **UNC2452** | Russian SVR (Suspected) | Espionage | Advanced | Government, Technology, Consulting |
| **UNC3890** | Chinese Nexus (Suspected) | Espionage | Advanced | Government, Defense, Technology |
| **Lazarus Group** | North Korean State | Financial Gain, Espionage | Advanced | Financial, Cryptocurrency, Media |

Each profile includes:
- **Aliases**: Known names for the threat actor
- **Attribution**: Suspected nation-state or organization
- **TTPs**: Mapped to MITRE ATT&CK framework (100+ techniques)
- **Tools**: Known malware families and utilities
- **IOCs**: Domains, IPs, and hashes from public reporting
- **Sample Intelligence**: Realistic threat intelligence text for testing

## Running Tests

### Automated Test Suite

Run the comprehensive test suite:

```bash
cd threat-research-mcp
python -m pytest tests/test_threat_actor_scenarios.py -v
```

**Test Coverage** (29 tests):
- IOC extraction validation
- ATT&CK technique detection
- Log source recommendation generation
- Profile completeness checks
- Cross-actor comparisons

**Example Output**:
```
tests/test_threat_actor_scenarios.py::TestAPT29Scenario::test_extract_iocs_from_apt29_intel PASSED
tests/test_threat_actor_scenarios.py::TestAPT29Scenario::test_detect_apt29_techniques PASSED
tests/test_threat_actor_scenarios.py::TestAPT29Scenario::test_generate_log_sources_for_apt29 PASSED
...
29 passed in 0.20s
```

### Interactive Demo

Run the interactive demo to see detailed analysis for each threat actor:

```bash
cd threat-research-mcp
python examples/demo_threat_actor_testing.py
```

**Demo Output Includes**:
1. **IOC Extraction**: Domains, IPs, hashes extracted from intelligence
2. **Technique Detection**: Auto-detected ATT&CK techniques
3. **Log Source Recommendations**: Specific log sources and SIEM queries
4. **Detection Summary**: Tactic coverage and detection gaps
5. **Comparison Report**: Side-by-side comparison of all actors

**Sample Output**:
```
================================================================================
Analyzing: APT29
================================================================================

Aliases: Cozy Bear, The Dukes, YTTRIUM, UNC2452
Attribution: Russian Foreign Intelligence Service (SVR)
Motivation: Espionage
Sophistication: Advanced

[Step 1: IOC Extraction]
Extracted IOCs:
  - Domains: 1 (avsvmcloud.com...)
  - IPs: 1 (13.59.205.66...)
  - Hashes: 1

Validation:
  - Matched 1/3 known domains
  - Matched 1/3 known IPs

[Step 2: ATT&CK Technique Detection]
Auto-detected 7 techniques:
  T1568.002, T1021.001, T1059.004, T1071.001, T1567.002, T1021.006, T1059.001

Validation:
  - Matched 4/29 known techniques
  - Coverage: 13.8%

[Step 3: Log Source Recommendations]
Generated recommendations for 7 techniques
  - Log sources: 25 unique sources
  - SIEM queries: 7 platforms

Sample log sources:
  - network: waf
  - network: ids_ips
  - aws: waf_logs

[Step 4: Detection Summary]
Tactic Coverage: 4/11 tactics
  Covered: execution, initial_access, command_and_control, credential_access
```

## Profile Structure

Each threat actor profile in `tests/threat_actor_profiles.py` contains:

```python
{
    "aliases": ["Cozy Bear", "The Dukes", ...],
    "attribution": "Russian Foreign Intelligence Service (SVR)",
    "first_seen": "2008",
    "targets": ["Government", "Think Tanks", ...],
    "geography": ["United States", "Europe", ...],
    "motivation": "Espionage",
    "sophistication": "Advanced",
    "ttps": {
        "initial_access": ["T1566.001", "T1566.002", ...],
        "execution": ["T1059.001", "T1059.003", ...],
        "persistence": ["T1547.001", "T1053.005", ...],
        # ... 11 tactic categories
    },
    "tools": ["SUNBURST", "TEARDROP", "Cobalt Strike", ...],
    "iocs": {
        "domains": ["avsvmcloud.com", ...],
        "ips": ["13.59.205.66", ...],
        "hashes": ["32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77"],
    },
    "sample_intel": """
    APT29 (Cozy Bear) conducted a sophisticated supply chain attack...
    """
}
```

## Test Categories

### 1. IOC Extraction Tests
Validate that the `extract_iocs` tool correctly identifies:
- Domains
- IP addresses
- File hashes
- Email addresses (if present)

### 2. Technique Detection Tests
Validate that the `intel_to_log_sources` tool correctly detects:
- ATT&CK technique IDs (e.g., T1059.001)
- Coverage percentage against known TTPs
- Key techniques for each actor

### 3. Log Source Recommendation Tests
Validate that the `recommend_log_sources` tool generates:
- Relevant log sources (Windows Event Logs, CloudTrail, etc.)
- SIEM-specific queries (Splunk, Sentinel, Elastic, etc.)
- Deployment checklists

### 4. Profile Completeness Tests
Validate that all profiles have:
- Required fields (aliases, attribution, TTPs, tools, IOCs)
- Valid TTP mappings to ATT&CK framework
- Sample intelligence containing the listed IOCs

### 5. Cross-Actor Comparison Tests
Validate behavioral patterns across actors:
- Russian actors share common tools (Mimikatz, Cobalt Strike)
- Chinese actors target technology sector
- North Korean actors have financial motivation
- All advanced actors use PowerShell

## Adding Custom Profiles

To add your own threat actor profiles:

1. **Edit `tests/threat_actor_profiles.py`**:

```python
THREAT_ACTOR_PROFILES["Your Actor Name"] = {
    "aliases": ["Alias1", "Alias2"],
    "attribution": "Attribution info",
    "first_seen": "2020",
    "targets": ["Industry1", "Industry2"],
    "geography": ["Region1", "Region2"],
    "motivation": "Espionage",
    "sophistication": "Advanced",
    "ttps": {
        "initial_access": ["T1566.001"],
        "execution": ["T1059.001"],
        # ... add more tactics
    },
    "tools": ["Tool1", "Tool2"],
    "iocs": {
        "domains": ["malicious.com"],
        "ips": ["1.2.3.4"],
        "hashes": ["abc123..."],
    },
    "sample_intel": """
    Your threat intelligence text here...
    Include IOCs and TTPs in natural language.
    """
}
```

2. **Run tests to validate**:

```bash
python -m pytest tests/test_threat_actor_scenarios.py::TestThreatActorProfiles -v
```

3. **Run demo to see analysis**:

```bash
python examples/demo_threat_actor_testing.py
```

## Use Cases

### 1. Validation Testing
Ensure your MCP tools correctly analyze threat intelligence from known actors:
```bash
pytest tests/test_threat_actor_scenarios.py -v
```

### 2. Detection Engineering
Generate detections for specific threat actors:
```python
from tests.threat_actor_profiles import get_threat_actor_profile
from threat_research_mcp.extensions.mitre_attack_integration import intel_to_log_sources

profile = get_threat_actor_profile("APT29")
result = intel_to_log_sources(
    intel_text=profile["sample_intel"],
    environment="aws",
    siem_platforms="splunk,sentinel"
)
```

### 3. Threat Hunting
Identify log sources needed to hunt for specific actors:
```python
from tests.threat_actor_profiles import get_threat_actor_profile
from threat_research_mcp.detection.log_source_mapper import get_log_sources_for_techniques

profile = get_threat_actor_profile("Lazarus Group")
techniques = [tech for tactic_techniques in profile["ttps"].values() for tech in tactic_techniques]
log_sources = get_log_sources_for_techniques(techniques[:10], environment="hybrid")
```

### 4. Red Team Emulation
Use profiles to plan red team exercises:
```python
from tests.threat_actor_profiles import get_threat_actor_profile

profile = get_threat_actor_profile("APT28")
print(f"Emulate: {profile['aliases'][0]}")
print(f"TTPs: {profile['ttps']['initial_access']}")
print(f"Tools: {profile['tools']}")
```

## Comparison Report

The demo generates a comparison report across all actors:

```
THREAT ACTOR COMPARISON REPORT
================================================================================

Actor                    IOCs   Techniques   Coverage  Tactics  Queries
--------------------------------------------------------------------------------
APT29                  2/3     4/7         13.8%          4        7
APT28                  2/3     7/8         25.9%          6        8
APT41                  2/3     4/6         13.8%          4        6
UNC2452                2/3     2/3          8.0%          2        3
UNC3890                2/3     4/7         16.0%          4        7
Lazarus Group          2/3     4/6         13.8%          4        6
--------------------------------------------------------------------------------
AVERAGE                  2.0         4.2      15.2%

KEY FINDINGS
================================================================================

[+] Best Technique Coverage: APT28 (25.9%)
[+] Most Techniques Detected: APT28 (8 techniques)
[+] Most IOCs Extracted: APT29 (3 IOCs)

[i] Average technique detection coverage: 15.2%
[i] Total threat actors analyzed: 6
[i] All actors successfully processed with log source recommendations
```

## Limitations

### Keyword-Based Detection
The current technique detection is keyword-based and may not detect:
- Supply chain attacks (T1195.002) without explicit "supply chain" keywords
- Data destruction (T1485) without explicit "wiper" or "destruction" keywords
- Advanced techniques requiring contextual understanding

**Workaround**: Use `manual_techniques` parameter to supplement auto-detection:
```python
intel_to_log_sources(
    intel_text=intel,
    manual_techniques="T1195.002,T1485"
)
```

### Coverage Percentage
Coverage percentages (13-26%) reflect the keyword-based detection limitations. In production, you would:
1. Use `mitre-attack-mcp` for authoritative technique lookups
2. Supplement with manual technique IDs
3. Use behavioral hunting (`threat-hunting-mcp`) for TTPs

## Next Steps

1. **Run Tests**: Validate your installation with `pytest tests/test_threat_actor_scenarios.py -v`
2. **Run Demo**: See detailed analysis with `python examples/demo_threat_actor_testing.py`
3. **Add Profiles**: Add your own threat actor profiles to `tests/threat_actor_profiles.py`
4. **Integrate**: Use profiles in your detection engineering workflows
5. **Extend**: Add more actors from public threat intelligence sources

## References

- **APT29**: [CISA Alert AA20-352A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a)
- **APT28**: [CISA Alert AA22-110A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-110a)
- **APT41**: [DOJ Indictment](https://www.justice.gov/opa/pr/seven-international-cyber-defendants-including-apt41-actors-charged-connection-computer)
- **UNC2452**: [Microsoft NOBELIUM Resource Center](https://www.microsoft.com/en-us/security/blog/2021/03/04/goldmax-goldfinder-sibot-analyzing-nobelium-malware/)
- **Lazarus Group**: [CISA Alert AA20-239A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-239a)
- **MITRE ATT&CK**: [https://attack.mitre.org/](https://attack.mitre.org/)
