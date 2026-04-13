# Log Source Recommendations (v0.3)

## Overview

The Log Source Recommendation feature helps security engineers and threat hunters identify **exactly which logs to collect** and **how to query them** based on detected ATT&CK techniques. Instead of generic "Process Creation" guidance, you get specific event IDs, cloud service logs, and ready-to-run SIEM queries.

## Why This Matters

When you detect techniques like `T1059.001` (PowerShell), you need to know:

1. **Which Windows Event Logs** to enable (Event IDs 4104, 4103, 4688)
2. **Which AWS CloudTrail events** to monitor (SSM SendCommand, Lambda Invoke)
3. **Which Azure Activity Logs** to collect (RunCommand, Automation jobs)
4. **Which GCP Cloud Logging** to configure (VM metadata changes)
5. **Ready-to-run queries** for Splunk, Sentinel, Elastic, Athena, and Chronicle

This feature bridges the gap between ATT&CK mapping and operational security.

## Quick Start

### Using the MCP Tool

```python
# In your MCP client (Cursor, VS Code + Cline, etc.)
recommend_log_sources(
    technique_ids="T1059.001,T1566.001,T1003.001",
    environment="hybrid",  # aws, azure, gcp, on-prem, or hybrid
    siem_platforms="splunk,sentinel,elastic"
)
```

### Example Output

```json
{
  "techniques": ["T1059.001", "T1566.001", "T1003.001"],
  "environment": "hybrid",
  "priority_summary": {
    "critical": [
      {
        "platform": "windows",
        "source": "event_logs",
        "techniques": ["T1059.001", "T1003.001"]
      },
      {
        "platform": "email_gateway",
        "source": "log_types",
        "techniques": ["T1566.001"]
      }
    ],
    "high": [...],
    "medium": [...]
  },
  "log_sources": {
    "windows": {
      "event_logs": {
        "techniques": ["T1059.001"],
        "details": {
          "channel": "Microsoft-Windows-PowerShell/Operational",
          "event_ids": [4104, 4103, 4105, 4106],
          "priority": "critical",
          "description": "PowerShell script block and module logging",
          "configuration": "Enable via GPO: Administrative Templates → Windows PowerShell → Turn on Script Block Logging"
        }
      }
    },
    "aws": {
      "cloudtrail": {
        "techniques": ["T1059.001"],
        "details": {
          "services": ["SSM", "Lambda"],
          "events": ["SendCommand", "StartSession", "Invoke"],
          "priority": "high",
          "description": "PowerShell execution via Systems Manager or Lambda"
        }
      }
    }
  },
  "hunt_queries": {
    "T1059.001": {
      "splunk": {
        "query": "index=windows (source=\"WinEventLog:Microsoft-Windows-PowerShell/Operational\" EventCode IN (4104, 4103))...",
        "description": "Splunk query for detecting T1059.001",
        "ready_to_run": true
      },
      "sentinel": {
        "query": "SecurityEvent | where EventID == 4688 | where Process has_any (\"powershell.exe\", \"pwsh.exe\")...",
        "description": "Sentinel query for detecting T1059.001",
        "ready_to_run": true
      }
    }
  },
  "deployment_checklist": [
    {
      "platform": "windows",
      "source": "event_logs",
      "priority": "critical",
      "action": "PowerShell script block and module logging",
      "configuration_steps": "Enable via GPO: Administrative Templates → Windows PowerShell → Turn on Script Block Logging",
      "event_ids": "4104, 4103, 4105, 4106"
    }
  ],
  "blind_spots": []
}
```

## Supported Techniques (v0.3)

The current prototype supports **20 common ATT&CK techniques** with comprehensive log source mappings:

### Initial Access & Execution
- **T1566.001** - Phishing: Spearphishing Attachment
- **T1190** - Exploit Public-Facing Application
- **T1059.001** - PowerShell

### Persistence & Privilege Escalation
- **T1053.005** - Scheduled Task/Job: Scheduled Task
- **T1547.001** - Boot or Logon Autostart Execution: Registry Run Keys
- **T1543.003** - Create or Modify System Process: Windows Service

### Defense Evasion
- **T1070.001** - Indicator Removal: Clear Windows Event Logs
- **T1562.001** - Impair Defenses: Disable or Modify Tools

### Credential Access
- **T1003.001** - OS Credential Dumping: LSASS Memory
- **T1110.003** - Brute Force: Password Spraying

### Discovery & Lateral Movement
- **T1078** - Valid Accounts
- **T1021.001** - Remote Services: Remote Desktop Protocol

### Command and Control
- **T1071.001** - Application Layer Protocol: Web Protocols
- **T1105** - Ingress Tool Transfer

### Exfiltration & Impact
- **T1567.002** - Exfiltration Over Web Service: Exfiltration to Cloud Storage
- **T1486** - Data Encrypted for Impact (Ransomware)

### Account & Service Manipulation
- **T1136.001** - Create Account: Local Account
- **T1098** - Account Manipulation
- **T1569.002** - System Services: Service Execution

## Platform Coverage

### Windows
- **Event Logs**: Security, System, PowerShell/Operational, TaskScheduler/Operational, TerminalServices
- **Sysmon**: Process creation, network connections, file operations, registry modifications
- **EDR**: CrowdStrike, Microsoft Defender, Carbon Black, SentinelOne

### AWS
- **CloudTrail**: IAM, SSM, Lambda, S3, GuardDuty, Config
- **VPC Flow Logs**: Network traffic analysis
- **CloudWatch Logs**: Lambda execution, SSM sessions
- **ALB/CloudFront Logs**: Web application traffic
- **WAF Logs**: Web application firewall events

### Azure
- **Activity Logs**: Resource management operations
- **Sign-in Logs**: Azure AD authentication
- **Diagnostic Logs**: Service-specific logs
- **NSG Flow Logs**: Network Security Group traffic
- **Application Gateway/Front Door Logs**: Web traffic

### GCP
- **Cloud Logging**: Audit logs, activity logs
- **VPC Flow Logs**: Network traffic
- **Cloud Scheduler**: Scheduled job execution
- **Cloud Armor**: Security policy logs
- **Load Balancer Logs**: HTTP(S) traffic

### Network & Email
- **Firewall Logs**: Connection logs, URL filtering
- **Proxy Logs**: HTTP/HTTPS traffic
- **IDS/IPS**: Snort, Suricata, Zeek
- **Email Gateway**: Proofpoint, Mimecast, Microsoft Defender for Office 365
- **Office 365/Google Workspace**: Email flow, attachment analysis

## SIEM Query Support

The feature generates ready-to-run queries for:

### Splunk
- Index-based searches with proper sourcetype filtering
- Statistical aggregations for anomaly detection
- Time-based windowing for correlation

### Microsoft Sentinel (KQL)
- SecurityEvent, SigninLogs, DeviceEvents tables
- Advanced hunting queries
- Azure-specific log sources

### Elastic (EQL/JSON)
- JSON query DSL format
- Aggregations and filtering
- ECS (Elastic Common Schema) field mappings

### AWS Athena (SQL)
- CloudTrail, VPC Flow Logs, ALB logs queries
- S3-based log analysis
- Time-partitioned queries

### Chronicle (YARA-L)
- UDM (Unified Data Model) field mappings
- Event correlation rules
- Multi-event detection logic

## Integration with Workflows

### Automatic Integration

When you use the `analysis_product` or `intel_to_analysis_product` tools, log source guidance is **automatically generated** if ATT&CK techniques are detected:

```python
# This automatically includes log source guidance
analysis_product(text="Incident report with PowerShell and phishing...")
```

The `AnalysisProduct` JSON will include a `detection_delivery.log_source_guidance` section with:
- Prioritized log sources
- SIEM-specific queries
- Deployment checklist

### Manual Usage

For targeted log source recommendations without full analysis:

```python
recommend_log_sources(
    technique_ids="T1059.001,T1003.001",
    environment="aws",  # Focus on AWS-specific logs
    siem_platforms="splunk,athena"
)
```

## Deployment Checklist

The `deployment_checklist` provides a prioritized action plan:

```json
[
  {
    "platform": "windows",
    "source": "event_logs",
    "priority": "critical",
    "action": "PowerShell script block and module logging",
    "configuration_steps": "Enable via GPO: Administrative Templates → Windows PowerShell → Turn on Script Block Logging",
    "event_ids": "4104, 4103, 4105, 4106"
  },
  {
    "platform": "windows",
    "source": "sysmon",
    "priority": "high",
    "action": "Process creation with full command line and hashes"
  }
]
```

**Priority Levels:**
- **Critical**: Must-have for detection; high confidence indicators
- **High**: Strong detection value; recommended for comprehensive coverage
- **Medium**: Supplementary logs; useful for context and correlation

## Environment Filtering

Use the `environment` parameter to focus on relevant platforms:

### `hybrid` (default)
Returns log sources for all platforms (Windows, AWS, Azure, GCP, network, email)

### `aws`
Focuses on AWS-specific logs (CloudTrail, VPC Flow, CloudWatch) plus network and EDR

### `azure`
Focuses on Azure-specific logs (Activity, Sign-in, NSG Flow) plus network and EDR

### `gcp`
Focuses on GCP-specific logs (Cloud Logging, VPC Flow) plus network and EDR

### `on-prem`
Focuses on Windows, Linux, network, and email logs (excludes cloud providers)

## Best Practices

### 1. Start with Critical Priority
Focus on deploying critical-priority log sources first:
```python
result = recommend_log_sources(technique_ids="T1059.001,T1003.001")
critical_sources = result["priority_summary"]["critical"]
```

### 2. Validate Queries in Your Environment
The queries are templates - adjust index names, table names, and field names to match your environment:
```spl
# Template
index=windows source="WinEventLog:Microsoft-Windows-PowerShell/Operational"

# Your environment might use
index=wineventlog sourcetype=XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
```

### 3. Test Before Production
- Run queries in a test environment first
- Verify log sources are actually generating data
- Adjust thresholds and filters based on your baseline

### 4. Chain with Specialist MCPs
Combine with other MCP servers for comprehensive coverage:
```
1. threat-research-mcp → Extract techniques
2. recommend_log_sources → Get log guidance
3. fastmcp-threatintel → Enrich IOCs
4. Security-Detections-MCP → Find existing detections
```

### 5. Document Your Environment
Create an `environment.yaml` (future feature) to define:
- Available log sources
- SIEM platform(s)
- Cloud providers in use
- EDR/email gateway vendors

## Roadmap

### v0.4 (Planned)
- **Environment Profiler**: Define your environment once, get tailored recommendations
- **Coverage Gap Detection**: Identify missing logs based on your environment
- **SIEM-Specific Tuning**: Platform-specific query optimizations
- **Expanded Technique Coverage**: 100+ techniques with mappings

### v0.5+ (Future)
- **Custom Log Source Registry**: Add your own log sources
- **Query Testing Framework**: Validate queries against sample data
- **Detection Engineering Workflow**: From technique → log source → query → alert
- **Integration with SOAR**: Automated log source deployment

## Troubleshooting

### "No specific log source mappings available"
This means the technique isn't yet in the v0.3 mapping database. Check `blind_spots` in the output.

**Workaround**: Use the generic `map_data_sources` tool for MITRE data source categories.

### "No [SIEM] template for [technique]"
Query templates are being added incrementally. The technique has log source mappings but no SIEM-specific query yet.

**Workaround**: Use the log source details to write your own query.

### Queries Don't Match My Environment
This is expected! The queries are **templates** that need customization:
- Index/table names
- Field names (especially custom fields)
- Thresholds and baselines
- Time windows

## Examples

### Example 1: Phishing Incident Response

```python
# Detect phishing techniques
result = recommend_log_sources(
    technique_ids="T1566.001,T1059.001,T1105",
    environment="hybrid",
    siem_platforms="sentinel,splunk"
)

# Priority actions:
# 1. Enable Office 365 EmailEvents logging
# 2. Enable PowerShell script block logging (Event ID 4104)
# 3. Configure proxy logs for file downloads
# 4. Deploy Sysmon for network connections (Event ID 3)
```

### Example 2: Ransomware Detection

```python
result = recommend_log_sources(
    technique_ids="T1486,T1070.001,T1562.001",
    environment="on-prem",
    siem_platforms="splunk,elastic"
)

# Priority actions:
# 1. Enable Sysmon file creation/deletion (Event IDs 11, 23)
# 2. Monitor Security Event ID 1102 (audit log cleared)
# 3. EDR alerts for mass file modifications
# 4. Monitor security tool process termination
```

### Example 3: Cloud Account Compromise

```python
result = recommend_log_sources(
    technique_ids="T1078,T1098,T1136.001",
    environment="aws",
    siem_platforms="athena,sentinel"
)

# Priority actions:
# 1. Enable CloudTrail for IAM events (CreateUser, AttachUserPolicy)
# 2. Monitor AssumeRole and GetSessionToken
# 3. Alert on IAM policy changes
# 4. Track first-time logins from new IPs
```

## API Reference

### `recommend_log_sources(technique_ids, environment, siem_platforms)`

**Parameters:**
- `technique_ids` (str): Comma-separated ATT&CK technique IDs (e.g., "T1059.001,T1566.001")
- `environment` (str, optional): Target environment - "hybrid" (default), "aws", "azure", "gcp", "on-prem"
- `siem_platforms` (str, optional): Comma-separated SIEM platforms - "splunk,sentinel,elastic" (default), also supports "athena", "chronicle"

**Returns:**
JSON string with:
- `techniques`: List of input technique IDs
- `environment`: Target environment
- `log_sources`: Detailed log sources by platform
- `priority_summary`: Critical/high/medium priority sources
- `hunt_queries`: SIEM-specific queries by technique
- `deployment_checklist`: Prioritized deployment tasks
- `blind_spots`: Techniques without mappings

## Contributing

To add new techniques or improve existing mappings:

1. **Add technique mappings** in `src/threat_research_mcp/detection/log_source_mapper.py`
2. **Add SIEM queries** in `src/threat_research_mcp/detection/query_generator.py`
3. **Add tests** in `tests/test_log_source_mapper.py`
4. **Update this documentation** with the new technique

See `CONTRIBUTING.md` for detailed guidelines.

## References

- [MITRE ATT&CK Data Sources](https://attack.mitre.org/datasources/)
- [Windows Event Log Reference](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-policy-recommendations)
- [AWS CloudTrail Event Reference](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference.html)
- [Azure Monitor Logs Reference](https://docs.microsoft.com/en-us/azure/azure-monitor/reference/)
- [GCP Cloud Logging Documentation](https://cloud.google.com/logging/docs)
