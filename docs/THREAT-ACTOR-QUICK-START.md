# Threat Actor Testing - Quick Start Guide

## What This Is

A comprehensive testing framework that validates `threat-research-mcp` tools against realistic threat intelligence from 6 major APT/UNC groups.

## Quick Commands

### Run All Tests (29 tests)
```bash
cd threat-research-mcp
python -m pytest tests/test_threat_actor_scenarios.py -v
```

### Run Interactive Demo
```bash
python examples/demo_threat_actor_testing.py
```

### Run Detection Engineering Workflows
```bash
python examples/detection_engineering_workflow.py
```

## The 6 Threat Actors

| Actor | Attribution | Key Campaign | Tools |
|-------|-------------|--------------|-------|
| **APT29** | Russian SVR | SolarWinds | SUNBURST, Cobalt Strike |
| **APT28** | Russian GRU | Spearphishing | X-Agent, Mimikatz |
| **APT41** | Chinese State | Healthcare/Telecom | Winnti, MESSAGETAP |
| **UNC2452** | Russian SVR | Supply Chain | TEARDROP, RAINDROP |
| **UNC3890** | Chinese Nexus | ProxyShell | China Chopper, Python tools |
| **Lazarus** | North Korean | Cryptocurrency | HOPLIGHT, Wipers |

## Use Case #1: Validate Your Setup

**Goal**: Ensure MCP tools work correctly

```bash
# Run tests
pytest tests/test_threat_actor_scenarios.py -v

# Expected: 29 passed in <1s
```

**What It Tests**:
- IOC extraction (domains, IPs, hashes)
- ATT&CK technique detection
- Log source recommendations
- Profile data quality

## Use Case #2: Build Actor-Specific Detections

**Goal**: Create detections for a specific threat actor

```python
from tests.threat_actor_profiles import get_threat_actor_profile
from threat_research_mcp.extensions.mitre_attack_integration import intel_to_log_sources

# Load APT29 profile
profile = get_threat_actor_profile("APT29")

# Generate detections
result = intel_to_log_sources(
    intel_text=profile["sample_intel"],
    environment="aws",  # or "azure", "gcp", "hybrid"
    siem_platforms="splunk,sentinel"
)

print(result)  # JSON with techniques, log sources, queries
```

**Output**:
- Auto-detected ATT&CK techniques
- 25+ log sources (Windows, CloudTrail, Azure, etc.)
- Ready-to-run SIEM queries (Splunk, Sentinel, Elastic)
- Deployment checklist

## Use Case #3: Multi-Actor Coverage

**Goal**: Find common techniques across multiple actors

```python
from tests.threat_actor_profiles import get_threat_actor_profile

# Load Russian actors
actors = ["APT28", "APT29", "UNC2452"]
profiles = {actor: get_threat_actor_profile(actor) for actor in actors}

# Find common techniques
common_techniques = set()
for profile in profiles.values():
    for tactic, techniques in profile["ttps"].items():
        common_techniques.update(techniques)

print(f"Total unique techniques: {len(common_techniques)}")
# Build detections for these common techniques
```

**Benefit**: One detection rule covers multiple threat actors

## Use Case #4: IOC-Based Detections

**Goal**: Block known threat actor infrastructure

```python
from tests.threat_actor_profiles import get_threat_actor_profile

profile = get_threat_actor_profile("Lazarus Group")

# Extract IOCs
domains = profile["iocs"]["domains"]
ips = profile["iocs"]["ips"]
hashes = profile["iocs"]["hashes"]

# Generate firewall rules
for ip in ips:
    print(f"deny ip any any {ip} any")

# Generate DNS blocklist
for domain in domains:
    print(f'zone "{domain}" {{ type master; file "/etc/bind/db.sinkhole"; }};')

# Generate EDR hash blocks
for hash_val in hashes:
    print(f"{hash_val},Lazarus Group malware")
```

## Use Case #5: Threat Hunting

**Goal**: Hunt for specific threat actor activity

```python
from tests.threat_actor_profiles import get_threat_actor_profile

profile = get_threat_actor_profile("APT41")

# Build hunt hypotheses
print("Hunt Hypothesis 1: APT41 exploited public-facing applications")
print(f"Techniques: {profile['ttps']['initial_access']}")
print(f"Tools: {profile['tools']}")

# Generate hunt queries
from threat_research_mcp.detection.query_generator import generate_hunt_queries

queries = generate_hunt_queries(
    profile["ttps"]["initial_access"][:5],
    siem_platforms=["splunk"]
)

print(queries["splunk"]["ready_to_run"])
```

## Adding Your Own Actors

### Step 1: Find Public Intelligence

Sources:
- [CISA Advisories](https://www.cisa.gov/news-events/cybersecurity-advisories)
- [MITRE ATT&CK Groups](https://attack.mitre.org/groups/)
- [Mandiant Threat Intelligence](https://www.mandiant.com/resources/blog)

### Step 2: Create Profile

Edit `tests/threat_actor_profiles.py`:

```python
"Your Actor": {
    "aliases": ["Alias1", "Alias2"],
    "attribution": "Nation-state or criminal group",
    "first_seen": "2020",
    "targets": ["Industry1", "Industry2"],
    "geography": ["Region1", "Region2"],
    "motivation": "Espionage/Financial/Disruption",
    "sophistication": "Advanced",
    "ttps": {
        "initial_access": ["T1566.001"],
        "execution": ["T1059.001"],
        # ... map to MITRE ATT&CK
    },
    "tools": ["Tool1", "Tool2"],
    "iocs": {
        "domains": ["malicious.com"],
        "ips": ["1.2.3.4"],
        "hashes": ["abc123..."],
    },
    "sample_intel": """
    [Paste threat intelligence report here]
    Include IOCs and describe TTPs in natural language.
    
    IOCs:
    - Domain: malicious.com
    - IP: 1.2.3.4
    """,
}
```

### Step 3: Validate

```bash
pytest tests/test_threat_actor_scenarios.py::TestThreatActorProfiles -v
```

### Step 4: Test

```bash
python examples/demo_threat_actor_testing.py
```

## Detection Engineering Workflows

Run the full workflow demo:

```bash
python examples/detection_engineering_workflow.py
```

**Includes**:
1. **Actor-Specific Detections**: Build detections for APT29
2. **Multi-Actor Coverage**: Find common techniques across Russian APTs
3. **IOC-Based Detections**: Deploy firewall/DNS/EDR blocks for Lazarus
4. **Threat Hunting**: Hunt for APT41 activity

## File Structure

```
threat-research-mcp/
├── tests/
│   ├── threat_actor_profiles.py          # 6 actor profiles
│   └── test_threat_actor_scenarios.py    # 29 tests
├── examples/
│   ├── demo_threat_actor_testing.py      # Interactive demo
│   └── detection_engineering_workflow.py # 4 workflows
└── docs/
    ├── THREAT-ACTOR-TESTING.md           # Full documentation
    ├── ADDING-THREAT-ACTORS.md           # How to add actors
    └── THREAT-ACTOR-QUICK-START.md       # This file
```

## Common Questions

### Q: How accurate is technique detection?

**A**: Keyword-based detection achieves 13-26% coverage. For production:
- Use `manual_techniques` parameter to supplement
- Integrate with `mitre-attack-mcp` for authoritative lookups
- Use behavioral hunting (`threat-hunting-mcp`) for TTPs

### Q: Can I use this for red team exercises?

**A**: Yes! Profiles include:
- TTPs to emulate
- Tools to use
- IOCs to plant (for blue team detection)

### Q: How do I keep profiles up to date?

**A**: 
1. Subscribe to CISA advisories
2. Monitor vendor threat intelligence blogs
3. Update profiles quarterly with new TTPs/IOCs

### Q: Can I share my custom profiles?

**A**: Yes! Contribute via pull request to the repository.

## Next Steps

1. ✅ Run tests: `pytest tests/test_threat_actor_scenarios.py -v`
2. ✅ Run demo: `python examples/demo_threat_actor_testing.py`
3. ✅ Try workflows: `python examples/detection_engineering_workflow.py`
4. ✅ Add your own actor: See `docs/ADDING-THREAT-ACTORS.md`
5. ✅ Build detections: Use profiles in your SIEM

## Resources

- **Full Documentation**: `docs/THREAT-ACTOR-TESTING.md`
- **Adding Actors**: `docs/ADDING-THREAT-ACTORS.md`
- **Detection Workflows**: `examples/detection_engineering_workflow.py`
- **MITRE ATT&CK**: https://attack.mitre.org/
- **CISA Advisories**: https://www.cisa.gov/news-events/cybersecurity-advisories
