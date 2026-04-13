# Automatic ATT&CK Technique Detection

## Overview

The **`intel_to_log_sources`** tool provides a fully automated pipeline from raw threat intelligence to actionable log source recommendations:

```
Threat Intel → Auto-Detect Techniques → Log Sources → SIEM Queries → Deployment Checklist
```

Instead of manually mapping threat intelligence to ATT&CK techniques, the system automatically analyzes the intel text and identifies relevant techniques based on keywords, TTPs, and behavioral patterns.

## Quick Start

### Using the MCP Tool

```python
# In your MCP client (Cursor, VS Code + Cline, etc.)
intel_to_log_sources(
    intel_text="ICP Canister C2 using blockchain for censorship-resistant command and control",
    environment="hybrid",
    siem_platforms="splunk,sentinel,elastic"
)
```

### Example Output

```json
{
  "intel_summary": "ICP Canister C2 using blockchain for censorship-resistant...",
  "detected_techniques": ["T1071.001", "T1090", "T1573.002"],
  "all_techniques": ["T1071.001", "T1090", "T1573.002"],
  "log_sources": {
    "network": {
      "proxy": {
        "priority": "high",
        "description": "Web proxy logs for C2 communication"
      }
    }
  },
  "hunt_queries": {...},
  "deployment_checklist": [...]
}
```

## How It Works

### 1. Keyword-Based Pattern Matching

The system analyzes threat intelligence text for specific keywords and patterns:

| Pattern | Detected Techniques | Example Keywords |
|---------|-------------------|------------------|
| **C2 Infrastructure** | T1071.001 (Web Protocols) | "c2", "command and control", "callback", "beacon" |
| **Proxy Behavior** | T1090 (Proxy) | "proxy", "proxying", "proxy server" |
| **Encryption** | T1573.002 (Encrypted Channel) | "encrypted c2", "tls", "ssl" |
| **Web3/Blockchain** | T1071.001, T1090 | "blockchain", "web3", "smart contract", "canister" |
| **PowerShell** | T1059.001 | "powershell", "pwsh", "invoke-expression" |
| **Phishing** | T1566.001 | "phishing", "spearphishing", "malicious attachment" |
| **Ransomware** | T1486 | "ransomware", "encrypted files", "ransom note" |
| **Credential Dumping** | T1003.001 | "lsass", "credential dump", "mimikatz" |

### 2. Contextual Analysis

The system considers context and combinations:

- **"Blockchain C2"** → Detects both T1071.001 (Web Protocols) and T1090 (Proxy)
- **"Encrypted communication"** → Adds T1573.002 (Encrypted Channel)
- **"Persistence via scheduled task"** → Detects T1053.005 (Scheduled Task)

### 3. Manual Override

You can supplement auto-detection with manual techniques:

```python
intel_to_log_sources(
    intel_text="Custom malware with unusual behavior",
    manual_techniques="T1055,T1027"  # Process Injection, Obfuscation
)
```

## Supported Detection Patterns

### Command & Control
- **T1071.001** - Application Layer Protocol: Web Protocols
  - Keywords: `c2`, `command and control`, `callback`, `beacon`, `http`, `https`
- **T1090** - Proxy
  - Keywords: `proxy`, `proxying`, `proxy server`, `socks`
- **T1573.002** - Encrypted Channel
  - Keywords: `encrypted c2`, `tls`, `ssl`, `encrypted communication`
- **T1568.002** - Dynamic Resolution: DGA
  - Keywords: `domain generation`, `dga`, `dynamic dns`, `fast flux`

### Execution
- **T1059.001** - PowerShell
  - Keywords: `powershell`, `pwsh`, `ps1`, `invoke-expression`, `iex`
- **T1059.004** - Unix Shell
  - Keywords: `bash`, `shell script`, `sh`, `/bin/bash`

### Persistence
- **T1053.005** - Scheduled Task/Job
  - Keywords: `scheduled task`, `cron`, `at job`, `task scheduler`
- **T1547.001** - Registry Run Keys
  - Keywords: `registry`, `run key`, `autorun`
- **T1543.003** - Windows Service
  - Keywords: `service`, `systemd`, `windows service`

### Credential Access
- **T1003.001** - LSASS Memory Dumping
  - Keywords: `lsass`, `credential dump`, `mimikatz`
- **T1110.003** - Password Spraying
  - Keywords: `password spray`, `brute force`, `credential stuffing`

### Defense Evasion
- **T1070.001** - Clear Event Logs
  - Keywords: `clear log`, `event log`, `wevtutil`, `clear-eventlog`
- **T1562.001** - Impair Defenses
  - Keywords: `disable defender`, `disable antivirus`, `tamper protection`

### Lateral Movement
- **T1021.001** - RDP
  - Keywords: `rdp`, `remote desktop`, `terminal services`
- **T1021.006** - Windows Remote Management
  - Keywords: `psexec`, `wmi`, `windows management`

### Initial Access
- **T1566.001** - Phishing
  - Keywords: `phishing`, `spearphishing`, `malicious attachment`, `email`
- **T1190** - Exploit Public-Facing Application
  - Keywords: `exploit`, `vulnerability`, `cve`, `public-facing`

### Exfiltration & Impact
- **T1567.002** - Exfiltration to Cloud Storage
  - Keywords: `exfiltration`, `data theft`, `cloud storage`, `s3`, `blob storage`
- **T1486** - Ransomware
  - Keywords: `ransomware`, `encrypted files`, `ransom note`, `crypto locker`

### Account Manipulation
- **T1136.001** - Create Local Account
  - Keywords: `create account`, `new user`, `useradd`, `net user`
- **T1078** - Valid Accounts
  - Keywords: `privilege escalation`, `admin rights`, `elevate privileges`

## Real-World Examples

### Example 1: ICP Canister C2 (Your Case)

**Input:**
```
ICP Canister ID: tdtqy-oyaaa-aaaae-af2dq-cai

Decentralized C2 using Internet Computer Protocol for censorship-resistant 
command and control. Threat actor leveraging Web3/blockchain infrastructure.
Encrypted communication channels. Proxy-like behavior through decentralized nodes.
```

**Auto-Detected Techniques:**
- T1071.001 (Web Protocols) - from "c2", "command and control"
- T1090 (Proxy) - from "proxy-like behavior", "blockchain"
- T1573.002 (Encrypted Channel) - from "encrypted communication"
- T1059.004 (Unix Shell) - from "blockchain" context

**Result:**
- 8 log sources identified
- 2 high-priority actions
- Network proxy and firewall logs prioritized
- Custom ICP-specific recommendations

### Example 2: Phishing with PowerShell

**Input:**
```
Phishing email delivered malicious zip attachment. User extracted and executed
JavaScript file which launched PowerShell with encoded command. PowerShell 
downloaded second-stage payload from attacker-controlled server.
```

**Auto-Detected Techniques:**
- T1566.001 (Phishing) - from "phishing email", "malicious attachment"
- T1059.001 (PowerShell) - from "powershell", "encoded command"
- T1105 (Ingress Tool Transfer) - from "downloaded" (if pattern added)

**Result:**
- Email gateway logs (critical)
- PowerShell script block logging (critical)
- Network proxy logs (high)
- Ready-to-run Splunk/Sentinel queries

### Example 3: Ransomware Attack

**Input:**
```
Ransomware deployed after initial compromise. Attacker cleared Windows event logs,
disabled Windows Defender, and encrypted files across network shares. Ransom note
left on desktop.
```

**Auto-Detected Techniques:**
- T1486 (Ransomware) - from "ransomware", "encrypted files", "ransom note"
- T1070.001 (Clear Event Logs) - from "cleared windows event logs"
- T1562.001 (Impair Defenses) - from "disabled windows defender"

**Result:**
- Sysmon file creation/deletion (critical)
- Security Event ID 1102 (critical)
- EDR alerts for mass file modifications
- Defender tampering detection

## Integration with mitre-attack-mcp (Future)

The current implementation uses keyword-based heuristics. In future versions, we plan to integrate with the **mitre-attack-mcp** server for authoritative technique mapping:

```python
# Future implementation
def extract_techniques_from_intel(intel_text: str) -> List[str]:
    # Call mitre-attack-mcp's search_techniques tool
    result = call_mitre_attack_mcp(
        query=intel_text,
        tool_name="search_techniques"
    )
    return result["technique_ids"]
```

This will provide:
- **More accurate** technique detection
- **Confidence scores** for each technique
- **Tactic mapping** (Initial Access, Execution, etc.)
- **Threat actor profiles** (APT groups using these techniques)
- **Mitigation recommendations** from ATT&CK

## API Reference

### `intel_to_log_sources(intel_text, environment, siem_platforms, auto_detect_techniques, manual_techniques)`

**Parameters:**
- `intel_text` (str): Threat intelligence text to analyze
- `environment` (str, optional): Target environment - "hybrid" (default), "aws", "azure", "gcp", "on-prem"
- `siem_platforms` (str, optional): Comma-separated SIEM platforms - "splunk,sentinel,elastic" (default)
- `auto_detect_techniques` (bool, optional): Enable auto-detection (default: True)
- `manual_techniques` (List[str], optional): Additional techniques to include

**Returns:**
Dictionary with:
- `intel_summary`: Brief summary of the intel
- `detected_techniques`: Auto-detected technique IDs
- `manual_techniques`: User-provided technique IDs
- `all_techniques`: Combined list
- `log_sources`: Detailed log sources by platform
- `priority_summary`: Critical/high/medium priority sources
- `hunt_queries`: SIEM-specific queries
- `deployment_checklist`: Prioritized deployment tasks
- `blind_spots`: Techniques without mappings

### MCP Tool: `intel_to_log_sources`

```python
intel_to_log_sources(
    intel_text: str,
    environment: str = "hybrid",
    siem_platforms: str = "splunk,sentinel,elastic",
    manual_techniques: str = ""
) -> str  # Returns JSON
```

## Best Practices

### 1. Provide Detailed Intel

**Good:**
```
Threat actor using PowerShell to download and execute Cobalt Strike beacon.
C2 communication over HTTPS to attacker-controlled domain. Persistence via
scheduled task running every 5 minutes.
```

**Bad:**
```
Malware detected
```

### 2. Include TTPs and Behavior

Focus on:
- **Actions taken** (downloaded, executed, created, modified)
- **Tools used** (PowerShell, Mimikatz, PsExec)
- **Infrastructure** (domains, IPs, C2 channels)
- **Persistence mechanisms** (scheduled tasks, services, registry)

### 3. Supplement with Manual Techniques

If you know specific techniques that might not be detected:

```python
intel_to_log_sources(
    intel_text="Custom malware with process hollowing",
    manual_techniques="T1055.012"  # Process Hollowing
)
```

### 4. Review and Validate

Auto-detection is a starting point:
1. **Review detected techniques** - Are they accurate?
2. **Check for missing techniques** - Did it miss anything obvious?
3. **Validate log sources** - Do you have these logs available?
4. **Customize queries** - Adjust for your environment

### 5. Combine with Other Tools

Chain with specialist MCPs:

```
1. intel_to_log_sources → Auto-detect techniques
2. mitre-attack-mcp → Get detailed technique info
3. Security-Detections-MCP → Find existing detections
4. fastmcp-threatintel → Enrich IOCs
```

## Limitations

### Current Limitations

1. **Keyword-Based**: Uses heuristics, not ML or authoritative ATT&CK data
2. **English Only**: Works best with English threat intelligence
3. **No Confidence Scores**: All detected techniques are treated equally
4. **Limited Context**: Doesn't understand complex relationships or attack chains
5. **No Tactic Mapping**: Doesn't organize techniques by tactic

### Planned Improvements

1. **mitre-attack-mcp Integration**: Use authoritative ATT&CK data
2. **Confidence Scoring**: Rank techniques by detection confidence
3. **Attack Chain Analysis**: Understand technique sequences
4. **Multi-Language Support**: Support non-English intel
5. **ML-Based Detection**: Use NLP models for better accuracy

## Troubleshooting

### "No ATT&CK techniques detected"

**Cause**: Intel text doesn't contain recognizable keywords

**Solution**:
1. Provide more detailed intel with specific actions and tools
2. Use `manual_techniques` parameter
3. Check the keyword patterns in `mitre_attack_integration.py`

### "Detected wrong techniques"

**Cause**: Keyword overlap or ambiguous language

**Solution**:
1. Review detected techniques and remove false positives
2. Use `manual_techniques` to override
3. Provide more specific intel text

### "Missing obvious techniques"

**Cause**: Keywords not in detection patterns

**Solution**:
1. Use `manual_techniques` to supplement
2. Submit a feature request to add the pattern
3. Contribute to `mitre_attack_integration.py`

## Contributing

To improve auto-detection:

1. **Add new patterns** in `src/threat_research_mcp/extensions/mitre_attack_integration.py`
2. **Test with real intel** from your incident response cases
3. **Submit feedback** on detection accuracy
4. **Contribute keyword patterns** for your domain

Example contribution:

```python
# Add detection for T1218.011 (Rundll32)
if any(kw in intel_lower for kw in ["rundll32", "rundll32.exe"]):
    techniques.append("T1218.011")
```

## References

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [mitre-attack-mcp](https://github.com/MHaggis/mitre-attack-mcp)
- [Log Source Recommendations](log-source-recommendations.md)
- [Three-MCP Workflow](three-mcp-workflow.md)
