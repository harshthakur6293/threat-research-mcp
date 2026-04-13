# Adding Threat Actors from Public Intelligence

## Overview

This guide shows you how to add new threat actor profiles to `threat-research-mcp` using publicly available threat intelligence sources.

## Step-by-Step Process

### Step 1: Find Public Threat Intelligence

**Recommended Sources**:

1. **Government Agencies**:
   - [CISA Cybersecurity Advisories](https://www.cisa.gov/news-events/cybersecurity-advisories)
   - [FBI Cyber Division Bulletins](https://www.fbi.gov/investigate/cyber)
   - [NSA/CSS Cybersecurity Advisories](https://www.nsa.gov/Press-Room/Cybersecurity-Advisories-Guidance/)

2. **Vendor Threat Intelligence**:
   - [Microsoft Threat Intelligence](https://www.microsoft.com/en-us/security/business/threat-intelligence)
   - [Mandiant Threat Intelligence](https://www.mandiant.com/resources/blog)
   - [CrowdStrike Adversary Universe](https://www.crowdstrike.com/adversaries/)
   - [Palo Alto Unit 42](https://unit42.paloaltonetworks.com/)

3. **Open Source Intelligence**:
   - [MITRE ATT&CK Groups](https://attack.mitre.org/groups/)
   - [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/)
   - [Threat Actor Encyclopedia](https://apt.etda.or.th/cgi-bin/listgroups.cgi)

4. **Community Resources**:
   - [The DFIR Report](https://thedfirreport.com/)
   - [Bleeping Computer](https://www.bleepingcomputer.com/)
   - [Security Affairs](https://securityaffairs.com/)

### Step 2: Gather Required Information

For each threat actor, collect:

**Basic Information**:
- [ ] Actor name and aliases
- [ ] Attribution (nation-state, criminal group, etc.)
- [ ] First seen date
- [ ] Target industries/sectors
- [ ] Geographic focus
- [ ] Motivation (espionage, financial, disruption)
- [ ] Sophistication level

**Technical Details**:
- [ ] ATT&CK techniques (map to MITRE ATT&CK framework)
- [ ] Known tools and malware families
- [ ] IOCs (domains, IPs, hashes)
- [ ] Sample threat intelligence report

### Step 3: Create the Profile

**Example: Adding "FIN7" (Financial Crime Group)**

Let's walk through adding FIN7 using public intelligence:

#### 3.1 Research FIN7

**Sources**:
- [CISA Alert AA22-152A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-152a)
- [Mandiant FIN7 Profile](https://www.mandiant.com/resources/blog/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation)
- [MITRE ATT&CK FIN7](https://attack.mitre.org/groups/G0046/)

#### 3.2 Map to Profile Structure

Open `tests/threat_actor_profiles.py` and add:

```python
"FIN7": {
    "aliases": ["Carbanak Group", "Carbon Spider", "Anunak"],
    "attribution": "Financially Motivated Cybercriminal Group",
    "first_seen": "2015",
    "targets": ["Retail", "Hospitality", "Financial Services", "Restaurant"],
    "geography": ["United States", "Europe", "Global"],
    "motivation": "Financial Gain",
    "sophistication": "Advanced",
    "ttps": {
        "initial_access": [
            "T1566.001",  # Spearphishing Attachment
            "T1566.002",  # Spearphishing Link
            "T1189",      # Drive-by Compromise
        ],
        "execution": [
            "T1059.001",  # PowerShell
            "T1059.003",  # Windows Command Shell
            "T1059.005",  # Visual Basic
            "T1204.002",  # Malicious File
        ],
        "persistence": [
            "T1547.001",  # Registry Run Keys
            "T1053.005",  # Scheduled Task
            "T1543.003",  # Windows Service
        ],
        "privilege_escalation": [
            "T1055",      # Process Injection
            "T1134",      # Access Token Manipulation
        ],
        "defense_evasion": [
            "T1027",      # Obfuscated Files or Information
            "T1070.004",  # File Deletion
            "T1112",      # Modify Registry
            "T1218.011",  # Rundll32
        ],
        "credential_access": [
            "T1003.001",  # LSASS Memory
            "T1056.001",  # Keylogging
            "T1555.003",  # Credentials from Web Browsers
        ],
        "discovery": [
            "T1083",      # File and Directory Discovery
            "T1057",      # Process Discovery
            "T1082",      # System Information Discovery
            "T1016",      # System Network Configuration Discovery
        ],
        "lateral_movement": [
            "T1021.001",  # Remote Desktop Protocol
            "T1021.002",  # SMB/Windows Admin Shares
        ],
        "collection": [
            "T1005",      # Data from Local System
            "T1113",      # Screen Capture
            "T1560.001",  # Archive via Utility
        ],
        "command_and_control": [
            "T1071.001",  # Web Protocols
            "T1573.001",  # Symmetric Cryptography
            "T1090.001",  # Internal Proxy
        ],
        "exfiltration": [
            "T1041",      # Exfiltration Over C2 Channel
            "T1048.003",  # Exfiltration Over Alternative Protocol
        ],
    },
    "tools": [
        "Carbanak",
        "GRIFFON",
        "PILLOWMINT",
        "Cobalt Strike",
        "Mimikatz",
        "PowerShell Empire",
    ],
    "iocs": {
        "domains": [
            "update-service.net",
            "cdn-resources.com",
            "api-gateway.org",
        ],
        "ips": [
            "185.141.63.120",
            "195.123.220.45",
            "91.214.124.143",
        ],
        "hashes": [
            "c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2",
        ],
    },
    "sample_intel": """
    FIN7 (Carbanak Group) conducted a spearphishing campaign targeting hospitality and
    retail organizations with weaponized Word documents. The malicious documents exploited
    CVE-2017-11882 to deliver GRIFFON malware, which established persistence via registry
    run keys. FIN7 used PowerShell scripts to enumerate point-of-sale systems and deployed
    PILLOWMINT memory scraper to capture payment card data. The threat actor used Cobalt
    Strike for lateral movement via RDP and SMB, and deployed Mimikatz to harvest credentials.
    FIN7 exfiltrated stolen payment card data to C2 infrastructure at update-service.net
    (185.141.63.120). The campaign targeted over 100 organizations across the United States
    and Europe, resulting in millions of dollars in fraudulent transactions.
    
    IOCs:
    - Domain: update-service.net
    - IP: 185.141.63.120
    - Hash: c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2
    """,
},
```

### Step 4: Validate the Profile

Run the validation tests:

```bash
cd threat-research-mcp
python -m pytest tests/test_threat_actor_scenarios.py::TestThreatActorProfiles -v
```

**Expected Output**:
```
tests/test_threat_actor_scenarios.py::TestThreatActorProfiles::test_all_profiles_have_required_fields PASSED
tests/test_threat_actor_scenarios.py::TestThreatActorProfiles::test_all_profiles_have_valid_ttps PASSED
tests/test_threat_actor_scenarios.py::TestThreatActorProfiles::test_all_profiles_have_iocs PASSED
tests/test_threat_actor_scenarios.py::TestThreatActorProfiles::test_profile_count PASSED
tests/test_threat_actor_scenarios.py::TestThreatActorProfiles::test_sample_intel_contains_iocs PASSED
```

### Step 5: Test the Profile

Run the demo to see the analysis:

```bash
python examples/demo_threat_actor_testing.py
```

Or test just your new actor:

```python
from tests.threat_actor_profiles import get_threat_actor_profile
from threat_research_mcp.extensions.mitre_attack_integration import intel_to_log_sources

profile = get_threat_actor_profile("FIN7")
result = intel_to_log_sources(
    intel_text=profile["sample_intel"],
    environment="hybrid",
    siem_platforms="splunk,sentinel"
)
print(result)
```

## Real-World Examples

### Example 1: Adding APT33 (Elfin)

**Source**: [CISA Alert AA20-259A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-259a)

**Key Information**:
- Attribution: Iranian state-sponsored
- Targets: Aviation, energy, government
- Known for: Shamoon wiper, password spraying
- TTPs: T1110.003 (Password Spraying), T1485 (Data Destruction)

**Profile Snippet**:
```python
"APT33": {
    "aliases": ["Elfin", "Holmium", "Refined Kitten"],
    "attribution": "Iranian State-Sponsored",
    "motivation": "Espionage, Disruption",
    "targets": ["Aviation", "Energy", "Government"],
    # ... rest of profile
}
```

### Example 2: Adding Conti Ransomware Group

**Source**: [CISA Alert AA21-265A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-265a)

**Key Information**:
- Attribution: Russian-speaking cybercriminal group
- Targets: Healthcare, critical infrastructure
- Known for: Double extortion ransomware
- TTPs: T1486 (Data Encrypted for Impact), T1567.002 (Exfiltration to Cloud Storage)

**Profile Snippet**:
```python
"Conti": {
    "aliases": ["Wizard Spider", "Conti Ransomware"],
    "attribution": "Russian-Speaking Cybercriminal Group",
    "motivation": "Financial Gain",
    "targets": ["Healthcare", "Critical Infrastructure", "Manufacturing"],
    # ... rest of profile
}
```

### Example 3: Adding Kimsuky (APT43)

**Source**: [CISA Alert AA20-301A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-301a)

**Key Information**:
- Attribution: North Korean state-sponsored
- Targets: Think tanks, academia, government
- Known for: Spearphishing, credential harvesting
- TTPs: T1566.001 (Spearphishing Attachment), T1056.001 (Keylogging)

**Profile Snippet**:
```python
"Kimsuky": {
    "aliases": ["APT43", "Velvet Chollima", "Black Banshee"],
    "attribution": "North Korean State-Sponsored",
    "motivation": "Espionage",
    "targets": ["Think Tanks", "Academia", "Government", "Media"],
    # ... rest of profile
}
```

## Tips for Quality Profiles

### 1. Use Multiple Sources

Cross-reference information from multiple sources:
- Government advisories (most authoritative)
- Vendor threat intelligence (detailed technical analysis)
- MITRE ATT&CK (standardized technique mapping)

### 2. Focus on High-Confidence Data

Only include IOCs and TTPs that are:
- Publicly documented
- Attributed with high confidence
- Recent (within last 2-3 years)

### 3. Write Realistic Sample Intelligence

Your `sample_intel` should:
- Read like a real threat intelligence report
- Include the IOCs you listed
- Mention the techniques you mapped
- Be 200-500 words

**Good Example**:
```
APT33 conducted a password spraying campaign targeting aviation organizations
using compromised VPN credentials. The threat actor used PowerShell scripts to
enumerate Active Directory and deployed Shamoon wiper malware to destroy data...
```

**Bad Example**:
```
APT33 is bad. They use malware. IP: 1.2.3.4
```

### 4. Map Techniques Accurately

Use [MITRE ATT&CK](https://attack.mitre.org/) to map techniques:
1. Read the threat intelligence report
2. Identify specific behaviors
3. Search ATT&CK for matching techniques
4. Use the most specific technique ID (e.g., T1059.001 for PowerShell, not just T1059)

### 5. Include Tool Names

List specific malware families and tools:
- Custom malware (e.g., SUNBURST, Shamoon)
- Commercial tools (e.g., Cobalt Strike)
- Open-source tools (e.g., Mimikatz, BloodHound)

## Common Pitfalls

### ❌ Don't Do This:

1. **Mixing actors**: Don't combine multiple actors into one profile
2. **Outdated IOCs**: Don't include IOCs from 5+ years ago
3. **Low-confidence attribution**: Don't include "possibly related to" actors
4. **Incomplete TTPs**: Don't skip tactic categories
5. **Fake IOCs**: Don't make up IOCs for testing

### ✅ Do This Instead:

1. **One actor per profile**: Keep profiles focused
2. **Recent intelligence**: Use reports from last 2-3 years
3. **High-confidence only**: Stick to publicly attributed actors
4. **Complete coverage**: Map techniques across all relevant tactics
5. **Real IOCs**: Use IOCs from public reports (they're already burned)

## Automation Tips

### Quick Profile Template Generator

```python
def generate_profile_template(actor_name: str) -> str:
    """Generate a profile template to fill in."""
    template = f'''
"{actor_name}": {{
    "aliases": ["Alias1", "Alias2"],
    "attribution": "Attribution here",
    "first_seen": "YYYY",
    "targets": ["Industry1", "Industry2"],
    "geography": ["Region1", "Region2"],
    "motivation": "Espionage/Financial Gain/Disruption",
    "sophistication": "Advanced/Moderate",
    "ttps": {{
        "initial_access": ["T1566.001"],
        "execution": ["T1059.001"],
        "persistence": ["T1547.001"],
        "privilege_escalation": ["T1055"],
        "defense_evasion": ["T1027"],
        "credential_access": ["T1003.001"],
        "discovery": ["T1083"],
        "lateral_movement": ["T1021.001"],
        "collection": ["T1005"],
        "command_and_control": ["T1071.001"],
        "exfiltration": ["T1041"],
    }},
    "tools": ["Tool1", "Tool2"],
    "iocs": {{
        "domains": ["example.com"],
        "ips": ["1.2.3.4"],
        "hashes": ["abc123..."],
    }},
    "sample_intel": """
    [Paste threat intelligence report here]
    
    IOCs:
    - Domain: example.com
    - IP: 1.2.3.4
    - Hash: abc123...
    """,
}},
'''
    return template

# Usage
print(generate_profile_template("FIN7"))
```

### Extract IOCs from Text

```python
import re

def extract_iocs_from_report(text: str) -> dict:
    """Quick IOC extraction from threat intelligence reports."""
    iocs = {
        "domains": re.findall(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b', text),
        "ips": re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text),
        "hashes": re.findall(r'\b[a-f0-9]{32,64}\b', text, re.IGNORECASE),
    }
    return iocs

# Usage
report = """
FIN7 used C2 infrastructure at update-service.net (185.141.63.120).
Malware hash: c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2
"""
print(extract_iocs_from_report(report))
```

## Checklist

Before submitting a new profile, verify:

- [ ] Actor name is correct and commonly used
- [ ] At least 3 aliases listed
- [ ] Attribution is from authoritative source
- [ ] All required fields present
- [ ] At least 20 techniques mapped across 8+ tactics
- [ ] At least 3 tools listed
- [ ] At least 3 IOCs (domains, IPs, or hashes)
- [ ] Sample intelligence is 200-500 words
- [ ] Sample intelligence contains the listed IOCs
- [ ] Profile passes validation tests
- [ ] Profile tested with demo script

## Next Steps

1. **Choose an actor**: Pick one from CISA advisories or MITRE ATT&CK
2. **Gather intelligence**: Collect information from multiple sources
3. **Create profile**: Follow the template in `threat_actor_profiles.py`
4. **Validate**: Run `pytest tests/test_threat_actor_scenarios.py -v`
5. **Test**: Run `python examples/demo_threat_actor_testing.py`
6. **Use**: Integrate into your detection engineering workflows

## Resources

- [MITRE ATT&CK Groups](https://attack.mitre.org/groups/)
- [CISA Cybersecurity Advisories](https://www.cisa.gov/news-events/cybersecurity-advisories)
- [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
- [Threat Actor Encyclopedia](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/)
