"""Generate SIEM-specific hunt queries for ATT&CK techniques.

This module provides ready-to-run queries for Splunk, Microsoft Sentinel, Elastic, and Chronicle/Athena.
"""

from __future__ import annotations

from typing import Any, Dict, List

# Query templates by SIEM platform
QUERY_TEMPLATES: Dict[str, Dict[str, str]] = {
    "T1059.001": {  # PowerShell
        "splunk": """index=windows (source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode IN (4104, 4103))
| eval script_block=ScriptBlockText
| search script_block IN ("*Invoke-Expression*", "*IEX*", "*DownloadString*", "*WebClient*", "*Net.WebClient*", "*-EncodedCommand*", "*-enc*", "*bypass*", "*hidden*")
| stats count by ComputerName, User, script_block
| where count > 5""",
        "sentinel": """SecurityEvent
| where EventID == 4688
| where Process has_any ("powershell.exe", "pwsh.exe")
| where CommandLine has_any ("Invoke-Expression", "IEX", "DownloadString", "-EncodedCommand", "-enc", "bypass", "hidden")
| project TimeGenerated, Computer, Account, CommandLine, ParentProcessName
| summarize count() by Computer, Account, CommandLine""",
        "elastic": """{
  "query": {
    "bool": {
      "must": [
        {"term": {"event.code": "4104"}},
        {"wildcard": {"powershell.script_block.text": "*Invoke-Expression*"}}
      ],
      "filter": [
        {"range": {"@timestamp": {"gte": "now-24h"}}}
      ]
    }
  }
}""",
        "athena": """SELECT
  eventtime,
  useridentity.principalid,
  requestparameters
FROM cloudtrail_logs
WHERE eventsource = 'ssm.amazonaws.com'
  AND eventname IN ('SendCommand', 'StartSession')
  AND requestparameters LIKE '%powershell%'""",
        "chronicle": """metadata.event_type = "PROCESS_LAUNCH"
AND target.process.command_line = /powershell.*(-enc|-EncodedCommand|IEX|Invoke-Expression|DownloadString)/nocase""",
    },
    "T1566.001": {  # Phishing: Spearphishing Attachment
        "splunk": """index=email
| search (attachment_name="*.exe" OR attachment_name="*.zip" OR attachment_name="*.doc*" OR attachment_name="*.xls*")
| eval suspicious_sender=if(match(sender_domain, "(?i)(temp|disposable|mailinator)"), 1, 0)
| where suspicious_sender=1 OR attachment_count > 3
| stats count by recipient, sender, subject, attachment_name""",
        "sentinel": """EmailEvents
| where AttachmentCount > 0
| where FileName has_any (".exe", ".zip", ".docm", ".xlsm", ".js", ".hta")
| join kind=inner (
    EmailAttachmentInfo
    | where FileType in ("exe", "zip", "docm", "xlsm")
) on NetworkMessageId
| project TimeGenerated, RecipientEmailAddress, SenderFromAddress, Subject, FileName, ThreatTypes""",
        "elastic": """{
  "query": {
    "bool": {
      "must": [
        {"exists": {"field": "email.attachments"}},
        {"terms": {"email.attachments.file.extension": ["exe", "zip", "docm", "xlsm"]}}
      ]
    }
  }
}""",
        "athena": """-- For AWS WorkMail logs (if available)
SELECT
  eventtime,
  recipientemailaddress,
  senderemailaddress,
  subject
FROM workmail_logs
WHERE attachmentcount > 0""",
        "chronicle": """metadata.event_type = "EMAIL_TRANSACTION"
AND network.email.attachment.file_extension = /exe|zip|docm|xlsm|js|hta/nocase""",
    },
    "T1053.005": {  # Scheduled Task
        "splunk": """index=windows source="WinEventLog:Microsoft-Windows-TaskScheduler/Operational" (EventCode=106 OR EventCode=140 OR EventCode=200)
| rex field=Message "Task Name: (?<task_name>.*)"
| rex field=Message "User: (?<task_user>.*)"
| where NOT match(task_name, "^\\\\Microsoft\\\\")
| stats count by ComputerName, task_name, task_user, EventCode""",
        "sentinel": """SecurityEvent
| where EventID in (4698, 4702)
| extend TaskName = extract(@"Task Name:\\s+(.+)", 1, EventData)
| where TaskName !startswith @"\\Microsoft\\"
| project TimeGenerated, Computer, Account, TaskName, EventID""",
        "elastic": """{
  "query": {
    "bool": {
      "must": [
        {"terms": {"event.code": ["106", "140", "200"]}},
        {"match": {"winlog.channel": "Microsoft-Windows-TaskScheduler/Operational"}}
      ],
      "must_not": [
        {"prefix": {"winlog.event_data.TaskName": "\\\\Microsoft\\\\"}}
      ]
    }
  }
}""",
        "athena": """SELECT
  eventtime,
  eventname,
  useridentity.principalid,
  requestparameters
FROM cloudtrail_logs
WHERE eventsource = 'events.amazonaws.com'
  AND eventname IN ('PutRule', 'PutTargets')""",
        "chronicle": """metadata.event_type = "SCHEDULED_TASK_CREATION"
OR (metadata.event_type = "REGISTRY_MODIFICATION"
    AND target.registry.registry_key = /.*\\\\Schedule\\\\TaskCache\\\\Tasks.*/nocase)""",
    },
    "T1003.001": {  # LSASS Memory Dumping
        "splunk": """index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10
| eval TargetImage=lower(TargetImage)
| where match(TargetImage, "lsass\\.exe$")
| where GrantedAccess IN ("0x1010", "0x1410", "0x1438", "0x143a", "0x1fffff")
| stats count by ComputerName, SourceImage, TargetImage, GrantedAccess, SourceUser""",
        "sentinel": """DeviceEvents
| where ActionType == "ProcessAccess"
| where FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in ("svchost.exe", "wininit.exe", "csrss.exe")
| project TimeGenerated, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName""",
        "elastic": """{
  "query": {
    "bool": {
      "must": [
        {"term": {"event.code": "10"}},
        {"wildcard": {"winlog.event_data.TargetImage": "*lsass.exe"}},
        {"terms": {"winlog.event_data.GrantedAccess": ["0x1010", "0x1410", "0x1438"]}}
      ]
    }
  }
}""",
        "athena": """-- Not directly applicable to cloud; use EDR logs if shipped to S3
SELECT * FROM edr_logs
WHERE event_type = 'process_access'
  AND target_process LIKE '%lsass.exe'""",
        "chronicle": """metadata.event_type = "PROCESS_OPEN"
AND target.process.file.full_path = /.*lsass\\.exe$/nocase
AND principal.process.file.full_path != /.*\\\\(svchost|wininit|csrss)\\.exe$/nocase""",
    },
    "T1078": {  # Valid Accounts
        "splunk": """index=aws sourcetype=aws:cloudtrail eventName=ConsoleLogin
| iplocation sourceIPAddress
| eval is_anomalous=if(Country!="US" OR City!="Expected_City", 1, 0)
| where is_anomalous=1
| stats count by userIdentity.userName, sourceIPAddress, Country, City""",
        "sentinel": """SigninLogs
| where ResultType == "0"
| extend Country = LocationDetails.countryOrRegion
| where Country !in ("US", "CA")
| project TimeGenerated, UserPrincipalName, IPAddress, Country, AppDisplayName""",
        "elastic": """{
  "query": {
    "bool": {
      "must": [
        {"term": {"event.action": "ConsoleLogin"}},
        {"term": {"event.outcome": "success"}}
      ],
      "must_not": [
        {"terms": {"source.geo.country_iso_code": ["US", "CA"]}}
      ]
    }
  }
}""",
        "athena": """SELECT
  eventtime,
  useridentity.principalid,
  sourceipaddress,
  eventname
FROM cloudtrail_logs
WHERE eventname IN ('ConsoleLogin', 'AssumeRole', 'GetSessionToken')
  AND errorcode IS NULL
  AND sourceipaddress NOT IN ('10.0.0.0/8', '172.16.0.0/12')""",
        "chronicle": """metadata.event_type = "USER_LOGIN"
AND security_result.action = "ALLOW"
AND principal.ip NOT IN ("10.0.0.0/8", "172.16.0.0/12")""",
    },
    "T1021.001": {  # RDP
        "splunk": """index=windows EventCode=4624 Logon_Type=10
| eval src_ip=if(isnull(Source_Network_Address) OR Source_Network_Address="-", "localhost", Source_Network_Address)
| where src_ip!="localhost" AND src_ip!="127.0.0.1"
| stats count by ComputerName, Account_Name, src_ip, Logon_Type""",
        "sentinel": """SecurityEvent
| where EventID == 4624
| where LogonType == 10
| where IpAddress !in ("127.0.0.1", "::1", "-")
| project TimeGenerated, Computer, Account, IpAddress, LogonType""",
        "elastic": """{
  "query": {
    "bool": {
      "must": [
        {"term": {"event.code": "4624"}},
        {"term": {"winlog.event_data.LogonType": "10"}}
      ],
      "must_not": [
        {"terms": {"source.ip": ["127.0.0.1", "::1"]}}
      ]
    }
  }
}""",
        "athena": """SELECT
  eventtime,
  sourceipaddress,
  useridentity.principalid
FROM vpc_flow_logs
WHERE dstport = 3389
  AND action = 'ACCEPT'
GROUP BY eventtime, sourceipaddress, useridentity.principalid
HAVING count(*) > 10""",
        "chronicle": """metadata.event_type = "USER_LOGIN"
AND network.application_protocol = "RDP"
AND security_result.action = "ALLOW" """,
    },
    "T1070.001": {  # Clear Windows Event Logs
        "splunk": """index=windows (EventCode=1102 OR EventCode=104)
| stats count by ComputerName, User, EventCode, Channel
| eval severity="CRITICAL"
| table _time, ComputerName, User, Channel, severity""",
        "sentinel": """SecurityEvent
| where EventID in (1102, 104)
| project TimeGenerated, Computer, Account, EventID, Activity
| extend Severity = "Critical" """,
        "elastic": """{
  "query": {
    "terms": {
      "event.code": ["1102", "104"]
    }
  }
}""",
        "athena": """SELECT
  eventtime,
  eventname,
  useridentity.principalid
FROM cloudtrail_logs
WHERE eventname IN ('StopLogging', 'DeleteTrail', 'UpdateTrail')
  AND requestparameters LIKE '%IsLogging=false%'""",
        "chronicle": """metadata.event_type = "SERVICE_MODIFICATION"
AND (metadata.product_event_type = "1102" OR metadata.product_event_type = "104")""",
    },
    "T1136.001": {  # Create Account: Local Account
        "splunk": """index=windows EventCode=4720
| stats count by ComputerName, TargetUserName, SubjectUserName
| where count > 0""",
        "sentinel": """SecurityEvent
| where EventID == 4720
| project TimeGenerated, Computer, TargetAccount, SubjectAccount
| extend AccountCreatedBy = SubjectAccount""",
        "elastic": """{
  "query": {
    "term": {
      "event.code": "4720"
    }
  }
}""",
        "athena": """SELECT
  eventtime,
  eventname,
  useridentity.principalid,
  requestparameters
FROM cloudtrail_logs
WHERE eventname IN ('CreateUser', 'CreateAccessKey')
  AND errorcode IS NULL""",
        "chronicle": """metadata.event_type = "USER_CREATION"
OR (metadata.event_type = "RESOURCE_CREATION"
    AND target.resource.resource_type = "USER")""",
    },
    "T1486": {  # Data Encrypted for Impact (Ransomware)
        "splunk": """index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11
| stats count by ComputerName, Image, TargetFilename
| where count > 100
| eval file_ext=lower(mvindex(split(TargetFilename, "."), -1))
| where match(file_ext, "^(encrypted|locked|crypto|crypt|cerber|locky|wannacry)$")""",
        "sentinel": """DeviceFileEvents
| where ActionType in ("FileCreated", "FileRenamed")
| where FileName matches regex @"\\.(encrypted|locked|crypto|crypt)$"
| summarize FileCount=count() by DeviceName, InitiatingProcessFileName, bin(TimeGenerated, 1m)
| where FileCount > 50""",
        "elastic": """{
  "query": {
    "bool": {
      "must": [
        {"term": {"event.code": "11"}},
        {"wildcard": {"file.extension": "*encrypted*"}}
      ]
    }
  },
  "aggs": {
    "file_count": {
      "terms": {"field": "host.name"},
      "aggs": {"count": {"value_count": {"field": "file.path"}}}
    }
  }
}""",
        "athena": """SELECT
  eventtime,
  eventname,
  requestparameters
FROM cloudtrail_logs
WHERE eventsource = 's3.amazonaws.com'
  AND eventname = 'DeleteObject'
GROUP BY DATE_TRUNC('minute', eventtime), useridentity.principalid
HAVING count(*) > 100""",
        "chronicle": """metadata.event_type = "FILE_CREATION"
AND target.file.full_path = /.*\\.(encrypted|locked|crypto|crypt)$/nocase
| aggregate count() by principal.hostname, 1m
| filter count > 50""",
    },
    "T1110.003": {  # Password Spraying
        "splunk": """index=windows EventCode=4625
| stats dc(TargetUserName) as unique_users, count by Source_Network_Address
| where unique_users > 10 AND count > 20""",
        "sentinel": """SigninLogs
| where ResultType != "0"
| summarize FailedAttempts=count(), UniqueUsers=dcount(UserPrincipalName) by IPAddress, bin(TimeGenerated, 5m)
| where UniqueUsers > 10 and FailedAttempts > 20""",
        "elastic": """{
  "query": {
    "bool": {
      "must": [
        {"term": {"event.code": "4625"}},
        {"range": {"@timestamp": {"gte": "now-1h"}}}
      ]
    }
  },
  "aggs": {
    "by_ip": {
      "terms": {"field": "source.ip"},
      "aggs": {
        "unique_users": {"cardinality": {"field": "user.name"}}
      }
    }
  }
}""",
        "athena": """SELECT
  sourceipaddress,
  COUNT(DISTINCT useridentity.principalid) as unique_users,
  COUNT(*) as attempts
FROM cloudtrail_logs
WHERE eventname = 'ConsoleLogin'
  AND errorcode IS NOT NULL
GROUP BY sourceipaddress
HAVING unique_users > 10 AND attempts > 20""",
        "chronicle": """metadata.event_type = "USER_LOGIN"
AND security_result.action = "BLOCK"
| aggregate count(), count_distinct(target.user.userid) by principal.ip, 5m
| filter count_distinct > 10 and count > 20""",
    },
    "T1567.002": {  # Exfiltration to Cloud Storage
        "splunk": """index=proxy
| search (url="*s3.amazonaws.com*" OR url="*blob.core.windows.net*" OR url="*storage.googleapis.com*")
| where http_method="PUT" OR http_method="POST"
| stats sum(bytes_out) as total_bytes by src_ip, url
| where total_bytes > 104857600""",
        "sentinel": """CommonSecurityLog
| where RequestURL has_any ("s3.amazonaws.com", "blob.core.windows.net", "storage.googleapis.com")
| where RequestMethod in ("PUT", "POST")
| summarize TotalBytes=sum(SentBytes) by SourceIP, RequestURL
| where TotalBytes > 104857600""",
        "elastic": """{
  "query": {
    "bool": {
      "must": [
        {"terms": {"http.request.method": ["PUT", "POST"]}},
        {"wildcard": {"url.full": "*s3.amazonaws.com*"}}
      ]
    }
  },
  "aggs": {
    "total_bytes": {
      "sum": {"field": "http.request.bytes"}
    }
  }
}""",
        "athena": """SELECT
  eventtime,
  sourceipaddress,
  requestparameters,
  SUM(CAST(JSON_EXTRACT(requestparameters, '$.contentLength') AS BIGINT)) as total_bytes
FROM cloudtrail_logs
WHERE eventsource = 's3.amazonaws.com'
  AND eventname IN ('PutObject', 'CompleteMultipartUpload')
GROUP BY sourceipaddress, DATE_TRUNC('hour', eventtime)
HAVING total_bytes > 104857600""",
        "chronicle": """metadata.event_type = "NETWORK_HTTP"
AND network.http.method IN ("PUT", "POST")
AND target.url = /.*s3\\.amazonaws\\.com.*/nocase
| aggregate sum(network.sent_bytes) by principal.ip, 1h
| filter sum > 104857600""",
    },
}


def generate_hunt_queries(
    technique_ids: List[str], siem_platforms: List[str] = None
) -> Dict[str, Any]:
    """
    Generate ready-to-run hunt queries for given techniques.

    Args:
        technique_ids: List of ATT&CK technique IDs
        siem_platforms: Target SIEM platforms (splunk, sentinel, elastic, athena, chronicle)
                       If None, generates for all platforms

    Returns:
        Dictionary with queries organized by technique and SIEM platform
    """
    if siem_platforms is None:
        siem_platforms = ["splunk", "sentinel", "elastic", "athena", "chronicle"]

    results: Dict[str, Any] = {"techniques": technique_ids, "queries": {}}

    for tid in technique_ids:
        tid_clean = tid.strip().upper()
        if tid_clean not in QUERY_TEMPLATES:
            results["queries"][tid_clean] = {
                "status": "no_template",
                "message": f"No query templates available for {tid_clean}",
            }
            continue

        technique_queries = {}
        for platform in siem_platforms:
            if platform in QUERY_TEMPLATES[tid_clean]:
                technique_queries[platform] = {
                    "query": QUERY_TEMPLATES[tid_clean][platform],
                    "description": f"{platform.title()} query for detecting {tid_clean}",
                    "ready_to_run": True,
                }
            else:
                technique_queries[platform] = {
                    "status": "not_available",
                    "message": f"No {platform} template for {tid_clean}",
                }

        results["queries"][tid_clean] = technique_queries

    return results


def generate_deployment_checklist(log_sources: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    Generate a deployment checklist based on required log sources.

    Args:
        log_sources: Output from log_source_mapper.get_log_sources_for_techniques()

    Returns:
        List of deployment tasks with platform, action, and priority
    """
    checklist: List[Dict[str, str]] = []

    platforms = log_sources.get("log_sources", {})

    for platform, sources in platforms.items():
        for source_name, source_info in sources.items():
            details = source_info.get("details", {})

            if isinstance(details, dict):
                priority = details.get("priority", "medium")
                description = details.get("description", "")
                config = details.get("configuration", "")

                task = {
                    "platform": platform,
                    "source": source_name,
                    "priority": priority,
                    "action": description,
                }

                if config:
                    task["configuration_steps"] = config

                # Add specific event IDs for Windows
                if platform == "windows" and "event_logs" in details:
                    event_ids = []
                    for log in details["event_logs"]:
                        if isinstance(log, dict) and "event_ids" in log:
                            event_ids.extend(log["event_ids"])
                    if event_ids:
                        task["event_ids"] = ", ".join(map(str, set(event_ids)))

                checklist.append(task)

    # Sort by priority
    priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    checklist.sort(key=lambda x: priority_order.get(x["priority"], 3))

    return checklist
