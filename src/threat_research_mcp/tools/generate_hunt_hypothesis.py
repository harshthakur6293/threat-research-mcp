"""Hunt hypothesis engine — technique + available log sources → actionable hunt hypotheses.

Given one or more ATT&CK technique IDs and the log sources available in the analyst's
environment, this module generates specific, actionable hunt hypotheses and ready-to-run
queries for Splunk (SPL), Microsoft Sentinel (KQL), and Elastic (EQL/Lucene).

Design: fully offline, deterministic, no LLM required.
mitre-attack-mcp can be called by the orchestrating Claude session for richer
technique context; this engine provides the query playbook.
"""

from __future__ import annotations

import json
from typing import Any

# ── Hunt Playbook ─────────────────────────────────────────────────────────────
# Structure: technique_id → { name, tactic, log_sources: { source_key → entry } }
# Each entry: { name, hypothesis, queries: { splunk, kql, elastic, sigma_logsource } }

_PLAYBOOK: dict[str, dict[str, Any]] = {
    "T1059.001": {
        "name": "PowerShell Execution",
        "tactic": "execution",
        "log_sources": {
            "script_block_logging": {
                "name": "Windows PowerShell Script Block Logging (Event ID 4104)",
                "hypothesis": "Adversary executing encoded or obfuscated PowerShell payloads via script block logging.",
                "splunk": 'index=wineventlog EventCode=4104 | search ScriptBlockText="*encodedcommand*" OR ScriptBlockText="*iex(*" OR ScriptBlockText="*downloadstring*" | table _time, ComputerName, ScriptBlockText',
                "kql": 'Event | where EventID == 4104 | where EventData has_any ("encodedcommand", "iex(", "downloadstring") | project TimeGenerated, Computer, EventData',
                "elastic": "event.code:4104 AND winlog.event_data.ScriptBlockText:(*encodedcommand* OR *iex(* OR *downloadstring*)",
                "sigma_logsource": "windows/powershell/powershell_script",
            },
            "sysmon_process": {
                "name": "Sysmon Process Creation (Event ID 1)",
                "hypothesis": "PowerShell launched with suspicious flags (-enc, -w hidden, -nop) from unusual parent processes.",
                "splunk": 'index=sysmon EventCode=1 Image="*\\powershell.exe" | search CommandLine="-enc*" OR CommandLine="-w hidden*" OR CommandLine="-nop*" OR ParentImage="*\\winword.exe" OR ParentImage="*\\excel.exe" | table _time, ComputerName, ParentImage, CommandLine',
                "kql": 'SecurityEvent | where EventID == 4688 | where NewProcessName endswith "\\powershell.exe" | where CommandLine has_any ("-enc", "-w hidden", "-nop") or ParentProcessName has_any ("winword", "excel", "outlook")',
                "elastic": "process.name:powershell.exe AND (process.command_line:*-enc* OR process.command_line:*-w hidden* OR process.parent.name:(winword.exe OR excel.exe))",
                "sigma_logsource": "windows/process_creation",
            },
        },
    },
    "T1059.003": {
        "name": "Windows Command Shell",
        "tactic": "execution",
        "log_sources": {
            "sysmon_process": {
                "name": "Sysmon Process Creation (Event ID 1)",
                "hypothesis": "cmd.exe spawned from unexpected parents or executing suspicious payloads via /c flag.",
                "splunk": 'index=sysmon EventCode=1 Image="*\\cmd.exe" | search CommandLine="*/c *" ParentImage!="*\\explorer.exe" | table _time, ComputerName, ParentImage, CommandLine',
                "kql": 'SecurityEvent | where EventID == 4688 | where NewProcessName endswith "\\cmd.exe" | where CommandLine has "/c" and not ParentProcessName endswith "explorer.exe"',
                "elastic": "process.name:cmd.exe AND process.command_line:*/c* AND NOT process.parent.name:explorer.exe",
                "sigma_logsource": "windows/process_creation",
            },
        },
    },
    "T1003.001": {
        "name": "LSASS Memory Dumping",
        "tactic": "credential-access",
        "log_sources": {
            "sysmon_process_access": {
                "name": "Sysmon Process Access (Event ID 10)",
                "hypothesis": "Non-system processes accessing lsass.exe memory with credential-dump access rights.",
                "splunk": 'index=sysmon EventCode=10 TargetImage="*\\lsass.exe" | where GrantedAccess IN ("0x1010","0x1410","0x1438","0x143a","0x1418","0x1f1fff") | where NOT (SourceImage="*\\svchost.exe" OR SourceImage="*\\wininit.exe") | table _time, ComputerName, SourceImage, GrantedAccess',
                "kql": 'SecurityEvent | where EventID == 10 | where TargetImage endswith "\\lsass.exe" | where GrantedAccess in ("0x1010","0x1410","0x1438") | where not SourceImage has_any ("svchost","wininit","csrss")',
                "elastic": "event.code:10 AND winlog.event_data.TargetImage:*lsass.exe AND NOT winlog.event_data.SourceImage:(svchost.exe OR wininit.exe)",
                "sigma_logsource": "windows/process_access",
            },
            "windows_defender": {
                "name": "Microsoft Defender / EDR Alerts",
                "hypothesis": "Credential dumping tool (mimikatz, procdump, comsvcs) detected by endpoint protection.",
                "splunk": 'index=defender (FileName="mimikatz*" OR FileName="procdump*" OR CommandLine="*comsvcs*MiniDump*") | table _time, ComputerName, FileName, CommandLine',
                "kql": 'DeviceProcessEvents | where FileName in~ ("mimikatz.exe","procdump.exe","procdump64.exe") or ProcessCommandLine has_all ("comsvcs","MiniDump")',
                "elastic": "process.name:(mimikatz.exe OR procdump.exe) OR process.command_line:(*comsvcs* AND *MiniDump*)",
                "sigma_logsource": "windows/process_creation",
            },
        },
    },
    "T1071.001": {
        "name": "C2 over HTTP/HTTPS",
        "tactic": "command-and-control",
        "log_sources": {
            "proxy_logs": {
                "name": "Web Proxy / Firewall HTTP Logs",
                "hypothesis": "Beaconing pattern — periodic HTTP/S requests to uncommon domains at regular intervals.",
                "splunk": "index=proxy | stats count, dc(url) as unique_urls, range(_time) as duration by src_ip, dest_host | where count > 20 AND unique_urls < 3 AND duration > 3600 | sort -count",
                "kql": 'CommonSecurityLog | where DeviceVendor == "Zscaler" or DeviceVendor == "Palo Alto Networks" | summarize RequestCount=count(), UniqueURLs=dcount(RequestURL), Duration=datetime_diff("second", max(TimeGenerated), min(TimeGenerated)) by SourceIP, DestinationHostName | where RequestCount > 20 and UniqueURLs < 3 and Duration > 3600',
                "elastic": "network.protocol:http AND destination.port:(80 OR 443)",
                "sigma_logsource": "proxy",
            },
            "dns_logs": {
                "name": "DNS Query Logs",
                "hypothesis": "High-volume DNS queries to newly registered or low-reputation domains from workstations.",
                "splunk": 'index=dns query_type=A | stats count by src_ip, query | where count > 50 | lookup threat_intel_domains query OUTPUT reputation | where reputation="malicious"',
                "kql": 'DnsEvents | where QueryType == "A" | summarize count() by ClientIP, Name | where count_ > 50',
                "elastic": "dns.question.type:A AND source.ip:*",
                "sigma_logsource": "dns",
            },
        },
    },
    "T1071.004": {
        "name": "C2 over DNS",
        "tactic": "command-and-control",
        "log_sources": {
            "dns_logs": {
                "name": "DNS Query Logs",
                "hypothesis": "DNS tunneling — unusually long subdomain strings used to exfiltrate data or receive commands.",
                "splunk": 'index=dns | eval subdomain_len=len(replace(query,"[^.]+\\.","")) | where subdomain_len > 50 | stats count by src_ip, query | sort -count',
                "kql": "DnsEvents | extend SubdomainLen=strlen(Name) | where SubdomainLen > 50 | summarize count() by ClientIP, Name | order by count_ desc",
                "elastic": "dns.question.name:* AND NOT dns.question.name:*.microsoft.com",
                "sigma_logsource": "dns",
            },
        },
    },
    "T1053.005": {
        "name": "Scheduled Task Persistence",
        "tactic": "persistence",
        "log_sources": {
            "windows_event_4698": {
                "name": "Windows Security Event ID 4698 (Scheduled Task Created)",
                "hypothesis": "New scheduled task created pointing to suspicious binary locations or using encoded commands.",
                "splunk": 'index=wineventlog EventCode=4698 | rex field=TaskContent "<Command>(?P<cmd>[^<]+)" | where match(cmd, "(?i)(temp|appdata|public|downloads|powershell.*-enc)") | table _time, ComputerName, TaskName, cmd',
                "kql": 'SecurityEvent | where EventID == 4698 | where EventData has_any ("\\Temp\\","\\AppData\\","encodedcommand") | project TimeGenerated, Computer, EventData',
                "elastic": "event.code:4698 AND winlog.event_data.TaskContent:(*Temp* OR *AppData* OR *encodedcommand*)",
                "sigma_logsource": "windows/security",
            },
            "sysmon_process": {
                "name": "Sysmon Process Creation (Event ID 1)",
                "hypothesis": "schtasks.exe or at.exe used to create tasks pointing to suspicious paths.",
                "splunk": 'index=sysmon EventCode=1 (Image="*\\schtasks.exe" OR Image="*\\at.exe") CommandLine="*/create*" | table _time, ComputerName, CommandLine',
                "kql": 'SecurityEvent | where EventID == 4688 | where NewProcessName has_any ("schtasks","at.exe") | where CommandLine has "/create"',
                "elastic": "process.name:(schtasks.exe OR at.exe) AND process.command_line:*/create*",
                "sigma_logsource": "windows/process_creation",
            },
        },
    },
    "T1547.001": {
        "name": "Registry Run Key Persistence",
        "tactic": "persistence",
        "log_sources": {
            "sysmon_registry": {
                "name": "Sysmon Registry Event (Event ID 13)",
                "hypothesis": "New value written to HKCU/HKLM Run keys pointing to non-standard binary paths.",
                "splunk": 'index=sysmon EventCode=13 (TargetObject="*\\CurrentVersion\\Run*" OR TargetObject="*\\CurrentVersion\\RunOnce*") | where NOT match(Details, "(?i)(program files|windows|microsoft)") | table _time, ComputerName, TargetObject, Details',
                "kql": 'Event | where EventID == 13 | where EventData has_any ("CurrentVersion\\Run","CurrentVersion\\RunOnce") | where not EventData has_any ("Program Files","Windows","Microsoft")',
                "elastic": "event.code:13 AND registry.path:*CurrentVersion\\Run* AND NOT registry.data.strings:*Program Files*",
                "sigma_logsource": "windows/registry/registry_set",
            },
        },
    },
    "T1543.003": {
        "name": "Windows Service Creation",
        "tactic": "persistence",
        "log_sources": {
            "windows_event_7045": {
                "name": "Windows System Event ID 7045 (New Service Installed)",
                "hypothesis": "New service pointing to suspicious binary path or using cmd/powershell as service binary.",
                "splunk": 'index=wineventlog EventCode=7045 | where match(ServiceFileName, "(?i)(temp|appdata|public|powershell|cmd)") | table _time, ComputerName, ServiceName, ServiceFileName',
                "kql": 'Event | where EventID == 7045 | where EventData has_any ("\\Temp\\","powershell","cmd.exe","\\AppData\\") | project TimeGenerated, Computer, EventData',
                "elastic": "event.code:7045 AND (winlog.event_data.ImagePath:*Temp* OR winlog.event_data.ImagePath:*powershell* OR winlog.event_data.ImagePath:*AppData*)",
                "sigma_logsource": "windows/system",
            },
        },
    },
    "T1505.003": {
        "name": "Web Shell",
        "tactic": "persistence",
        "log_sources": {
            "web_server_logs": {
                "name": "IIS / Apache / Nginx Access Logs",
                "hypothesis": "POST requests to .aspx/.php/.jsp files not in known-good application paths, especially with cmd/exec parameters.",
                "splunk": 'index=iis cs_method=POST (cs_uri_stem="*.aspx" OR cs_uri_stem="*.php" OR cs_uri_stem="*.jsp") | where NOT match(cs_uri_stem, "(?i)(login|search|api)") | stats count by c_ip, cs_uri_stem | where count > 5',
                "kql": 'W3CIISLog | where csMethod == "POST" and (csUriStem endswith ".aspx" or csUriStem endswith ".php") | summarize count() by cIP, csUriStem',
                "elastic": r"http.request.method:POST AND url.path:(*\.aspx OR *\.php OR *\.jsp) AND NOT url.path:*(login|api)*",
                "sigma_logsource": "webserver",
            },
        },
    },
    "T1566.001": {
        "name": "Spearphishing Attachment",
        "tactic": "initial-access",
        "log_sources": {
            "email_gateway": {
                "name": "Email Gateway / Exchange Logs",
                "hypothesis": "Emails with macro-enabled Office documents or password-protected archives delivered to high-value targets.",
                "splunk": 'index=email (attachment_extension=".xlsm" OR attachment_extension=".docm" OR attachment_extension=".zip") | stats count by sender, recipient, subject | where count=1 | sort -_time',
                "kql": 'EmailAttachmentInfo | where FileType has_any (".xlsm",".docm",".xls",".zip") | join EmailEvents on NetworkMessageId | project TimeGenerated, SenderFromAddress, RecipientEmailAddress, FileName, Subject',
                "elastic": "email.attachments.file.extension:(xlsm OR docm OR zip) AND email.from.address:*",
                "sigma_logsource": "application/email",
            },
            "sysmon_process": {
                "name": "Sysmon Process Creation (Event ID 1)",
                "hypothesis": "Office application (winword, excel) spawning child processes — classic macro execution chain.",
                "splunk": 'index=sysmon EventCode=1 (ParentImage="*\\winword.exe" OR ParentImage="*\\excel.exe" OR ParentImage="*\\outlook.exe") NOT (Image="*\\splwow64.exe") | table _time, ComputerName, ParentImage, Image, CommandLine',
                "kql": 'SecurityEvent | where EventID == 4688 | where ParentProcessName has_any ("winword","excel","outlook","powerpnt") | where not NewProcessName has "splwow64"',
                "elastic": "process.parent.name:(WINWORD.EXE OR EXCEL.EXE OR OUTLOOK.EXE) AND NOT process.name:splwow64.exe",
                "sigma_logsource": "windows/process_creation",
            },
        },
    },
    "T1021.001": {
        "name": "Remote Desktop Protocol (RDP)",
        "tactic": "lateral-movement",
        "log_sources": {
            "windows_event_4624": {
                "name": "Windows Security Event ID 4624 (Logon) / 4625 (Failed Logon)",
                "hypothesis": "Successful RDP logons (LogonType=10) from unusual source IPs or at unusual hours.",
                "splunk": "index=wineventlog EventCode=4624 Logon_Type=10 | stats count by src_ip, Account_Name, ComputerName | where count > 1 | sort -count",
                "kql": "SecurityEvent | where EventID == 4624 | where LogonType == 10 | summarize count() by IpAddress, Account, Computer | where count_ > 1",
                "elastic": "event.code:4624 AND winlog.event_data.LogonType:10",
                "sigma_logsource": "windows/security",
            },
        },
    },
    "T1021.002": {
        "name": "SMB / Lateral Movement",
        "tactic": "lateral-movement",
        "log_sources": {
            "windows_event_4624": {
                "name": "Windows Security Event ID 4624 (Network Logon)",
                "hypothesis": "Network logons (LogonType=3) spreading across multiple hosts from a single source — potential lateral movement.",
                "splunk": 'index=wineventlog EventCode=4624 Logon_Type=3 NOT Account_Name="*$" | stats dc(ComputerName) as hosts by Account_Name, src_ip | where hosts > 3 | sort -hosts',
                "kql": 'SecurityEvent | where EventID == 4624 | where LogonType == 3 | where Account !endswith "$" | summarize HostCount=dcount(Computer) by Account, IpAddress | where HostCount > 3',
                "elastic": "event.code:4624 AND winlog.event_data.LogonType:3 AND NOT winlog.event_data.SubjectUserName:*$",
                "sigma_logsource": "windows/security",
            },
        },
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "initial-access",
        "log_sources": {
            "windows_event_4624": {
                "name": "Windows Security / Azure AD Sign-in Logs",
                "hypothesis": "Logon from account outside normal working hours, from new geo-location, or after password spray.",
                "splunk": 'index=wineventlog EventCode=4624 | eval hour=strftime(_time,"%H") | where hour < 7 OR hour > 20 | stats count by Account_Name, src_ip, ComputerName | sort -count',
                "kql": "SigninLogs | where ResultType == 0 | where dayofweek(TimeGenerated) in (0,6) or hourofday(TimeGenerated) !between (7 .. 20) | project TimeGenerated, UserPrincipalName, IPAddress, Location",
                "elastic": 'event.code:4624 AND NOT winlog.event_data.IpAddress:("::1" OR "127.0.0.1")',
                "sigma_logsource": "windows/security",
            },
        },
    },
    "T1110.003": {
        "name": "Password Spraying",
        "tactic": "credential-access",
        "log_sources": {
            "windows_event_4625": {
                "name": "Windows Security Event ID 4625 (Failed Logon)",
                "hypothesis": "Single source IP failing authentication against many different accounts — spray pattern.",
                "splunk": "index=wineventlog EventCode=4625 | stats dc(Account_Name) as distinct_users, count by src_ip | where distinct_users > 10 | sort -distinct_users",
                "kql": "SecurityEvent | where EventID == 4625 | summarize DistinctUsers=dcount(Account), FailCount=count() by IpAddress | where DistinctUsers > 10 | order by DistinctUsers desc",
                "elastic": "event.code:4625 | stats count by source.ip, user.name",
                "sigma_logsource": "windows/security",
            },
        },
    },
    "T1055": {
        "name": "Process Injection",
        "tactic": "defense-evasion",
        "log_sources": {
            "sysmon_create_remote_thread": {
                "name": "Sysmon CreateRemoteThread (Event ID 8)",
                "hypothesis": "Process creating a remote thread in a high-value process (lsass, explorer, svchost) — classic injection.",
                "splunk": 'index=sysmon EventCode=8 TargetImage IN ("*\\lsass.exe","*\\explorer.exe","*\\svchost.exe") | where NOT SourceImage IN ("*\\svchost.exe","*\\csrss.exe") | table _time, ComputerName, SourceImage, TargetImage',
                "kql": 'Event | where EventID == 8 | where EventData has_any ("lsass.exe","explorer.exe","svchost.exe") | where not EventData has_any ("svchost.exe","csrss.exe") as SourceImage',
                "elastic": "event.code:8 AND winlog.event_data.TargetImage:(lsass.exe OR explorer.exe OR svchost.exe)",
                "sigma_logsource": "windows/sysmon/sysmon",
            },
        },
    },
    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "tactic": "exfiltration",
        "log_sources": {
            "proxy_logs": {
                "name": "Web Proxy / DLP Logs",
                "hypothesis": "Large outbound HTTP POST to external IP or newly registered domain — potential data exfil.",
                "splunk": "index=proxy cs_method=POST | eval mb=bytes/1024/1024 | where mb > 10 | stats sum(mb) as total_mb by src_ip, dest_host | sort -total_mb",
                "kql": 'CommonSecurityLog | where RequestMethod == "POST" and SentBytes > 10000000 | summarize TotalMB=sum(SentBytes)/1024/1024 by SourceIP, DestinationHostName | order by TotalMB desc',
                "elastic": "network.protocol:http AND http.request.method:POST AND destination.bytes:>10000000",
                "sigma_logsource": "proxy",
            },
        },
    },
    "T1027": {
        "name": "Obfuscated Files or Information",
        "tactic": "defense-evasion",
        "log_sources": {
            "script_block_logging": {
                "name": "PowerShell Script Block Logging (Event ID 4104)",
                "hypothesis": "High entropy strings or known obfuscation patterns in PowerShell script blocks.",
                "splunk": 'index=wineventlog EventCode=4104 | eval entropy=len(replace(ScriptBlockText,"[a-zA-Z0-9]",""))/len(ScriptBlockText) | where entropy > 0.3 | table _time, ComputerName, ScriptBlockText',
                "kql": 'Event | where EventID == 4104 | where EventData has_any ("char(","concat(","[convert]::","-bxor")',
                "elastic": "event.code:4104 AND winlog.event_data.ScriptBlockText:(*char(* OR *-bxor* OR *[convert]*)",
                "sigma_logsource": "windows/powershell/powershell_script",
            },
        },
    },
    "T1046": {
        "name": "Network Service Discovery / Port Scanning",
        "tactic": "discovery",
        "log_sources": {
            "firewall_logs": {
                "name": "Firewall / Network Flow Logs",
                "hypothesis": "Single internal host making connection attempts to many ports on many hosts — internal scanning.",
                "splunk": "index=firewall action=deny | stats dc(dest_port) as ports, dc(dest_ip) as hosts by src_ip | where ports > 20 OR hosts > 20 | sort -ports",
                "kql": 'AzureNetworkAnalytics_CL | where FlowStatus_s == "D" | summarize DistinctPorts=dcount(DestPort_d), DistinctHosts=dcount(DestIP_s) by SrcIP_s | where DistinctPorts > 20 or DistinctHosts > 20',
                "elastic": "network.direction:egress AND event.outcome:failure",
                "sigma_logsource": "firewall",
            },
        },
    },
    "T1486": {
        "name": "Data Encrypted for Impact (Ransomware)",
        "tactic": "impact",
        "log_sources": {
            "sysmon_file": {
                "name": "Sysmon File Creation (Event ID 11)",
                "hypothesis": "Mass file renaming or creation of ransom note files across network shares.",
                "splunk": 'index=sysmon EventCode=11 | eval ext=mvindex(split(TargetFilename,"."), -1) | where ext IN ("encrypted","locked","crypt","ryk","maze") OR match(TargetFilename, "(?i)(readme|decrypt|recover|ransom)") | stats count by ComputerName, ext | sort -count',
                "kql": 'DeviceFileEvents | where FileName endswith_cs ".encrypted" or FileName endswith_cs ".locked" or FileName has_any ("README","DECRYPT","RECOVER") | summarize count() by DeviceName, FileName | order by count_ desc',
                "elastic": "event.code:11 AND (file.name:*decrypt* OR file.name:*ransom* OR file.extension:(encrypted OR locked OR crypt))",
                "sigma_logsource": "windows/sysmon/sysmon",
            },
        },
    },
    "T1558.003": {
        "name": "Kerberoasting",
        "tactic": "credential-access",
        "log_sources": {
            "windows_event_4769": {
                "name": "Windows Security Event ID 4769 (Kerberos Service Ticket Request)",
                "hypothesis": "Service ticket requests using RC4 encryption (0x17) for service accounts — kerberoasting indicator.",
                "splunk": 'index=wineventlog EventCode=4769 Ticket_Encryption_Type=0x17 NOT Account_Name="*$" | stats count by Account_Name, Service_Name, Client_Address | sort -count',
                "kql": 'SecurityEvent | where EventID == 4769 | where TicketEncryptionType == "0x17" | where not AccountName endswith "$" | summarize count() by AccountName, ServiceName, IpAddress',
                "elastic": "event.code:4769 AND winlog.event_data.TicketEncryptionType:0x17 AND NOT winlog.event_data.ServiceName:*$",
                "sigma_logsource": "windows/security",
            },
        },
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "initial-access",
        "log_sources": {
            "web_server_logs": {
                "name": "Web Application / WAF Logs",
                "hypothesis": "SQL injection, path traversal, or command injection patterns in HTTP request parameters.",
                "splunk": 'index=web_logs | search (cs_uri_query="*\'*" OR cs_uri_query="*select *" OR cs_uri_query="*../../../*" OR cs_uri_query="*cmd=*" OR cs_uri_query="*exec(*") | table _time, c_ip, cs_uri_stem, cs_uri_query',
                "kql": 'W3CIISLog | where csUriQuery has_any ("select ","union ","../",";cmd","exec(") | project TimeGenerated, cIP, csUriStem, csUriQuery',
                "elastic": "url.query:(*select* OR *union* OR *../* OR *exec(*)",
                "sigma_logsource": "webserver",
            },
        },
    },
    # ── Supply Chain / CI-CD ──────────────────────────────────────────────────
    "T1195.001": {
        "name": "Compromise Software Supply Chain",
        "tactic": "initial-access",
        "log_sources": {
            "github_actions_audit": {
                "name": "GitHub Actions Audit Log / OIDC Token Events",
                "hypothesis": "Malicious package published to PyPI/npm from a compromised CI account, or unexpected workflow triggered on push to main.",
                "splunk": 'index=github_audit action=package.publish OR action=workflows.completed | where outcome="success" AND actor_ip!="" | stats count by actor, repo, package_name, actor_ip | where count=1',
                "kql": 'GitHubAuditData_CL | where action_s in ("package.publish","workflows.completed") | where outcome_s == "success" | project TimeGenerated, actor_s, repo_s, package_s, actorIp_s',
                "elastic": "github.audit.action:(package.publish OR workflows.completed) AND github.audit.outcome:success",
                "sigma_logsource": "application/github",
            },
            "aws_cloudtrail": {
                "name": "AWS CloudTrail — CodeBuild / CodePipeline Events",
                "hypothesis": "Unexpected CodeBuild project start or artifact upload from an unusual IAM principal.",
                "splunk": "index=aws_cloudtrail eventSource=codebuild.amazonaws.com eventName=StartBuild | stats count by userIdentity.arn, projectName, sourceVersion | where count=1",
                "kql": 'AWSCloudTrail | where EventSource == "codebuild.amazonaws.com" and EventName == "StartBuild" | project TimeGenerated, UserIdentityArn, RequestParameters',
                "elastic": "aws.cloudtrail.event_source:codebuild.amazonaws.com AND aws.cloudtrail.event_name:StartBuild",
                "sigma_logsource": "cloud/aws/cloudtrail",
            },
        },
    },
    "T1195.002": {
        "name": "Compromise Software Dependencies",
        "tactic": "initial-access",
        "log_sources": {
            "github_actions_audit": {
                "name": "GitHub Actions Audit Log",
                "hypothesis": "Workflow file modified in a public repo to exfiltrate secrets or introduce a backdoored dependency.",
                "splunk": 'index=github_audit action=workflows.run_attempt | rex field=head_branch "(?P<branch>.+)" | where branch="main" OR branch="master" | stats count by actor, repo, workflow | where count < 3',
                "kql": 'GitHubAuditData_CL | where action_s == "workflows.run_attempt" | where headBranch_s in ("main","master") | summarize count() by actor_s, repo_s, workflow_s',
                "elastic": "github.audit.action:workflows.run_attempt AND github.audit.head_branch:(main OR master)",
                "sigma_logsource": "application/github",
            },
        },
    },
    # ── Cloud ─────────────────────────────────────────────────────────────────
    "T1552.005": {
        "name": "Cloud Instance Metadata API (IMDS)",
        "tactic": "credential-access",
        "log_sources": {
            "aws_cloudtrail": {
                "name": "AWS CloudTrail — IMDSv1 GetSessionToken / AssumeRole",
                "hypothesis": "EC2 metadata service queried for IAM credentials by a non-standard process or from an unusual user agent.",
                "splunk": 'index=aws_cloudtrail eventName=GetSessionToken userIdentity.type=AssumedRole | stats count by userIdentity.arn, sourceIPAddress, userAgent | where match(userAgent,"(?i)(curl|wget|python|ruby|powershell)")',
                "kql": 'AWSCloudTrail | where EventName == "GetSessionToken" and UserIdentityType == "AssumedRole" | project TimeGenerated, UserIdentityArn, SourceIpAddress, UserAgent | where UserAgent has_any ("curl","wget","python","powershell")',
                "elastic": "aws.cloudtrail.event_name:GetSessionToken AND aws.cloudtrail.user_identity.type:AssumedRole AND aws.cloudtrail.user_agent:(curl OR wget OR python)",
                "sigma_logsource": "cloud/aws/cloudtrail",
            },
            "gcp_cloud_logging": {
                "name": "GCP Cloud Logging — Compute Metadata Server",
                "hypothesis": "GCE instance queried the metadata server for service account tokens from a process not in the expected baseline.",
                "splunk": 'index=gcp_logs resource.type=gce_instance protoPayload.requestUrl="*computeMetadata*" | stats count by resource.labels.instance_id, protoPayload.authenticationInfo.principalEmail | where count > 100',
                "kql": 'GCPCloudAudit | where ResourceType == "gce_instance" and RequestUrl has "computeMetadata" | summarize count() by InstanceId, PrincipalEmail',
                "elastic": "gcp.audit.resource.type:gce_instance AND url.original:*computeMetadata*",
                "sigma_logsource": "cloud/gcp",
            },
            "azure_activity_logs": {
                "name": "Azure Monitor — IMDS / Managed Identity Token Requests",
                "hypothesis": "Azure VM queried IMDS for a managed identity token; unusual caller or spike in token requests.",
                "splunk": 'index=azure_monitor Category=AzureActivity operationName="MICROSOFT.COMPUTE/VIRTUALMACHINES/RETRIEVE TOKEN" | stats count by caller, resourceId | where count > 50',
                "kql": 'AzureActivity | where OperationNameValue =~ "MICROSOFT.COMPUTE/VIRTUALMACHINES/RETRIEVE TOKEN" | summarize count() by Caller, ResourceId | where count_ > 50',
                "elastic": "azure.activitylogs.operation_name:MICROSOFT.COMPUTE/VIRTUALMACHINES/RETRIEVE*TOKEN",
                "sigma_logsource": "cloud/azure/activitylogs",
            },
        },
    },
    "T1078.004": {
        "name": "Cloud Accounts",
        "tactic": "initial-access",
        "log_sources": {
            "aws_cloudtrail": {
                "name": "AWS CloudTrail — AssumeRole / ConsoleLogin",
                "hypothesis": "IAM role assumed from an unexpected source IP or region; console login without MFA for privileged account.",
                "splunk": 'index=aws_cloudtrail eventName=AssumeRole OR eventName=ConsoleLogin | where errorCode="" | stats count by userIdentity.arn, sourceIPAddress, awsRegion | where NOT match(sourceIPAddress,"^10\\.|^172\\.(1[6-9]|2[0-9]|3[01])\\.|^192\\.168\\.")',
                "kql": 'AWSCloudTrail | where EventName in ("AssumeRole","ConsoleLogin") and isempty(ErrorCode) | where not SourceIpAddress matches regex @"^(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.)" | project TimeGenerated, UserIdentityArn, SourceIpAddress, AWSRegion',
                "elastic": "aws.cloudtrail.event_name:(AssumeRole OR ConsoleLogin) AND NOT aws.cloudtrail.error_code:*",
                "sigma_logsource": "cloud/aws/cloudtrail",
            },
            "azure_activity_logs": {
                "name": "Azure AD Sign-In Logs — Service Principal",
                "hypothesis": "Service principal sign-in from an IP outside the expected corporate range or with unusual application ID.",
                "splunk": 'index=azure_aad Category=ServicePrincipalSignInLogs resultType=0 | stats count by servicePrincipalName, ipAddress, location | where NOT match(ipAddress,"^10\\.|^192\\.168\\.")',
                "kql": 'AADServicePrincipalSignInLogs | where ResultType == 0 | where not IPAddress matches regex @"^(10\\.|192\\.168\\.)" | project TimeGenerated, ServicePrincipalName, IPAddress, Location',
                "elastic": "azure.signinlogs.properties.service_principal_name:* AND NOT azure.signinlogs.properties.ip_address:10.*",
                "sigma_logsource": "cloud/azure/azure.aad",
            },
            "gcp_cloud_logging": {
                "name": "GCP Cloud Logging — Service Account Key Usage",
                "hypothesis": "Service account key used from outside GCP (external IP) — potential exfiltrated credential use.",
                "splunk": 'index=gcp_logs protoPayload.authenticationInfo.serviceAccountKeyName=* | where NOT match(protoPayload.requestMetadata.callerIp,"^(10\\.|35\\.|34\\.)")',
                "kql": 'GCPCloudAudit | where isnotempty(ServiceAccountKeyName) | where not CallerIp matches regex @"^(10\\.|35\\.|34\\.)" | project TimeGenerated, ServiceAccountKeyName, CallerIp',
                "elastic": "gcp.audit.authentication_info.service_account_key_name:* AND NOT source.ip:10.*",
                "sigma_logsource": "cloud/gcp",
            },
        },
    },
    "T1530": {
        "name": "Data from Cloud Storage",
        "tactic": "collection",
        "log_sources": {
            "aws_cloudtrail": {
                "name": "AWS CloudTrail — S3 Data Events",
                "hypothesis": "Bulk GetObject requests on sensitive S3 buckets from an IAM principal that does not normally access them.",
                "splunk": "index=aws_cloudtrail eventSource=s3.amazonaws.com eventName=GetObject | stats count, dc(requestParameters.key) as objects by userIdentity.arn, requestParameters.bucketName | where count > 100 | sort -count",
                "kql": 'AWSCloudTrail | where EventSource == "s3.amazonaws.com" and EventName == "GetObject" | summarize ObjectCount=dcount(tostring(RequestParameters)), Requests=count() by UserIdentityArn, BucketName | where Requests > 100 | order by Requests desc',
                "elastic": "aws.cloudtrail.event_source:s3.amazonaws.com AND aws.cloudtrail.event_name:GetObject",
                "sigma_logsource": "cloud/aws/cloudtrail",
            },
            "gcp_cloud_logging": {
                "name": "GCP Cloud Logging — GCS Data Access",
                "hypothesis": "Mass object downloads from GCS buckets tagged as sensitive by an unexpected service account.",
                "splunk": "index=gcp_logs resource.type=gcs_bucket protoPayload.methodName=storage.objects.get | stats count by protoPayload.authenticationInfo.principalEmail, resource.labels.bucket_name | where count > 100",
                "kql": 'GCPCloudAudit | where ResourceType == "gcs_bucket" and MethodName == "storage.objects.get" | summarize count() by PrincipalEmail, BucketName | where count_ > 100',
                "elastic": "gcp.audit.resource.type:gcs_bucket AND gcp.audit.method_name:storage.objects.get",
                "sigma_logsource": "cloud/gcp",
            },
            "azure_activity_logs": {
                "name": "Azure Monitor — Storage Blob Access Logs",
                "hypothesis": "Unusual volume of blob downloads from Azure Storage accounts by a service principal or from external IPs.",
                "splunk": "index=azure_storage category=StorageRead operationType=GetBlob | stats count, dc(uri) as blobs by callerIpAddress, accountName | where count > 200",
                "kql": 'StorageBlobLogs | where OperationName == "GetBlob" | summarize Requests=count(), UniqueBlobs=dcount(Uri) by CallerIpAddress, AccountName | where Requests > 200',
                "elastic": "azure.storage.operation_name:GetBlob AND NOT azure.storage.caller_ip_address:10.*",
                "sigma_logsource": "cloud/azure/activitylogs",
            },
        },
    },
    "T1609": {
        "name": "Container Administration Command",
        "tactic": "execution",
        "log_sources": {
            "k8s_audit": {
                "name": "Kubernetes API Server Audit Log",
                "hypothesis": "kubectl exec or attach into a running pod — especially into privileged or system-namespace pods.",
                "splunk": 'index=k8s_audit verb=create resource=pods subresource IN (exec,attach) | stats count by user.username, objectRef.namespace, objectRef.name | where NOT match(user.username,"system:serviceaccount:kube-system")',
                "kql": 'KubeAudit_CL | where verb_s == "create" and resource_s == "pods" and subresource_s in ("exec","attach") | project TimeGenerated, user_username_s, namespace_s, podName_s',
                "elastic": "kubernetes.audit.verb:create AND kubernetes.audit.object_ref.resource:pods AND kubernetes.audit.object_ref.subresource:(exec OR attach)",
                "sigma_logsource": "cloud/kubernetes/audit",
            },
            "docker_daemon": {
                "name": "Docker Daemon / Containerd Logs",
                "hypothesis": "docker exec into a running container — especially combined with elevated capabilities or root shell.",
                "splunk": 'index=docker_events Type=exec_create | rex field=Status "exec_create: (?P<cmd>.+)" | where match(cmd,"(?i)(sh|bash|cmd|powershell|/bin/)") | table _time, host, container_id, cmd',
                "kql": 'ContainerLog | where LogEntry has "exec_create" | where LogEntry has_any ("sh","bash","/bin/") | project TimeGenerated, Computer, ContainerID, LogEntry',
                "elastic": "event.action:exec_create AND container.runtime:docker",
                "sigma_logsource": "cloud/container/docker",
            },
        },
    },
    "T1610": {
        "name": "Deploy Container",
        "tactic": "defense-evasion",
        "log_sources": {
            "k8s_audit": {
                "name": "Kubernetes API Server Audit Log",
                "hypothesis": "New DaemonSet or privileged Pod created — potential persistence via node-level container deployment.",
                "splunk": 'index=k8s_audit verb=create resource IN (pods,daemonsets,deployments) | where match(requestObject.spec.containers{}.securityContext.privileged,"true") OR match(requestObject.spec.hostPID,"true") | stats count by user.username, objectRef.namespace, requestObject.metadata.name',
                "kql": 'KubeAudit_CL | where verb_s == "create" and resource_s in ("pods","daemonsets","deployments") | where requestObject_s has "privileged" or requestObject_s has "hostPID" | project TimeGenerated, user_username_s, namespace_s, name_s',
                "elastic": "kubernetes.audit.verb:create AND kubernetes.audit.object_ref.resource:(pods OR daemonsets) AND kubernetes.audit.request_object:*privileged*",
                "sigma_logsource": "cloud/kubernetes/audit",
            },
            "aws_cloudtrail": {
                "name": "AWS CloudTrail — ECS / EKS Task Launch",
                "hypothesis": "New ECS task definition registered with privileged settings or unexpected image pulled from external registry.",
                "splunk": 'index=aws_cloudtrail eventSource=ecs.amazonaws.com eventName IN (RegisterTaskDefinition,RunTask) | rex field=requestParameters "image":"(?P<image>[^"]+)" | where NOT match(image,"(?i)(your-account-id\\.dkr\\.ecr|public\\.ecr\\.aws)") | table _time, userIdentity.arn, image',
                "kql": 'AWSCloudTrail | where EventSource == "ecs.amazonaws.com" and EventName in ("RegisterTaskDefinition","RunTask") | project TimeGenerated, UserIdentityArn, RequestParameters',
                "elastic": "aws.cloudtrail.event_source:ecs.amazonaws.com AND aws.cloudtrail.event_name:(RegisterTaskDefinition OR RunTask)",
                "sigma_logsource": "cloud/aws/cloudtrail",
            },
            "docker_daemon": {
                "name": "Docker Daemon Logs",
                "hypothesis": "Container started with --privileged or --pid=host flags, or with a mounted host filesystem.",
                "splunk": 'index=docker_events Type=container Action=start | where match(Actor.Attributes.image,"(?i)(alpine|busybox|kalilinux)") OR match(HostConfig.Privileged,"true") | table _time, host, container_id, Actor.Attributes.image',
                "kql": 'ContainerLog | where LogEntry has "container start" and (LogEntry has "privileged" or LogEntry has "hostPID") | project TimeGenerated, Computer, ContainerID, LogEntry',
                "elastic": "event.action:container_start AND container.runtime:docker AND NOT container.image.name:*internal-registry*",
                "sigma_logsource": "cloud/container/docker",
            },
        },
    },
    "T1613": {
        "name": "Container and Resource Discovery",
        "tactic": "discovery",
        "log_sources": {
            "k8s_audit": {
                "name": "Kubernetes API Server Audit Log",
                "hypothesis": "Unusual burst of LIST or WATCH calls against pods, secrets, or cluster roles — automated discovery.",
                "splunk": "index=k8s_audit verb IN (list,watch) resource IN (pods,secrets,clusterroles,nodes) | stats count by user.username, resource, objectRef.namespace | where count > 50 | sort -count",
                "kql": 'KubeAudit_CL | where verb_s in ("list","watch") and resource_s in ("pods","secrets","clusterroles","nodes") | summarize count() by user_username_s, resource_s, namespace_s | where count_ > 50',
                "elastic": "kubernetes.audit.verb:(list OR watch) AND kubernetes.audit.object_ref.resource:(pods OR secrets OR clusterroles)",
                "sigma_logsource": "cloud/kubernetes/audit",
            },
            "docker_daemon": {
                "name": "Docker API / Daemon Logs",
                "hypothesis": "docker ps, inspect, or API GET /containers/json called from a non-admin account or from a container itself.",
                "splunk": "index=docker_events Type=container Action IN (list,inspect) | stats count by host, remoteAddr | where count > 20",
                "kql": 'ContainerLog | where LogEntry has_any ("GET /containers/json","docker ps","docker inspect") | summarize count() by Computer, ContainerID | where count_ > 20',
                "elastic": "event.action:(container_list OR container_inspect) AND container.runtime:docker",
                "sigma_logsource": "cloud/container/docker",
            },
        },
    },
    # ── macOS ─────────────────────────────────────────────────────────────────
    "T1059.002": {
        "name": "AppleScript / osascript Execution",
        "tactic": "execution",
        "log_sources": {
            "macos_unified_log": {
                "name": "macOS Unified Log",
                "hypothesis": "osascript invoked with -e flag or reading from stdin — common pattern for in-memory AppleScript execution.",
                "splunk": 'index=macos_edr process_name=osascript | search cmdline="-e *" OR cmdline="*curl*" OR cmdline="*http*" | table _time, host, user, cmdline, parent_process',
                "kql": 'DeviceProcessEvents | where DeviceName has "macOS" or OSPlatform == "macOS" | where FileName == "osascript" | where ProcessCommandLine has_any ("-e","curl","http","downloadString") | project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName',
                "elastic": "process.name:osascript AND (process.command_line:*-e* OR process.command_line:*curl* OR process.command_line:*http*)",
                "sigma_logsource": "macos/process_creation",
            },
            "edr_macos": {
                "name": "EDR on macOS — Process Events",
                "hypothesis": "Script Editor or osascript spawning curl, python, or bash — multi-stage download chain.",
                "splunk": 'index=macos_edr (parent_process_name="Script Editor" OR parent_process_name="osascript") child_process_name IN ("curl","python","python3","bash","sh") | table _time, host, user, parent_process_name, cmdline',
                "kql": 'DeviceProcessEvents | where OSPlatform == "macOS" | where InitiatingProcessFileName in~ ("osascript","Script Editor") | where FileName in~ ("curl","python","python3","bash","sh") | project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine',
                "elastic": "process.parent.name:(osascript OR Script Editor) AND process.name:(curl OR python OR python3 OR bash OR sh)",
                "sigma_logsource": "macos/process_creation",
            },
        },
    },
    "T1543.001": {
        "name": "Launch Agent / Launch Daemon Persistence",
        "tactic": "persistence",
        "log_sources": {
            "macos_unified_log": {
                "name": "macOS Unified Log — launchd",
                "hypothesis": "New .plist file written to /Library/LaunchDaemons/ or ~/Library/LaunchAgents/ pointing to a non-Apple binary.",
                "splunk": 'index=macos_edr event_type=file_create target_path IN ("/Library/LaunchDaemons/*","/Library/LaunchAgents/*","*/Library/LaunchAgents/*") | where NOT match(target_path,"(?i)(apple|microsoft|google/chrome|dropbox)") | table _time, host, user, target_path, process_name',
                "kql": 'DeviceFileEvents | where OSPlatform == "macOS" | where FolderPath has_any ("/Library/LaunchDaemons/","/Library/LaunchAgents/") | where not FolderPath has_any ("Apple","Microsoft","Dropbox","Google/Chrome") | project TimeGenerated, DeviceName, AccountName, FolderPath, FileName, InitiatingProcessFileName',
                "elastic": "file.path:(*LaunchDaemons* OR *LaunchAgents*) AND NOT file.path:(*Apple* OR *Microsoft*) AND event.action:creation",
                "sigma_logsource": "macos/file_event",
            },
            "edr_macos": {
                "name": "EDR on macOS — launchctl load",
                "hypothesis": "launchctl used to load a new daemon from an unusual path — persistence installation.",
                "splunk": 'index=macos_edr process_name=launchctl cmdline="*load*" | where NOT match(cmdline,"(?i)(apple|system/library|/usr/libexec)") | table _time, host, user, cmdline, parent_process',
                "kql": 'DeviceProcessEvents | where OSPlatform == "macOS" | where FileName == "launchctl" | where ProcessCommandLine has "load" | where not ProcessCommandLine has_any ("/System/Library","/usr/libexec","Apple") | project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName',
                "elastic": "process.name:launchctl AND process.command_line:*load* AND NOT process.command_line:*/System/Library/*",
                "sigma_logsource": "macos/process_creation",
            },
        },
    },
    "T1548.006": {
        "name": "TCC Database Manipulation",
        "tactic": "defense-evasion",
        "log_sources": {
            "macos_unified_log": {
                "name": "macOS Unified Log — TCC / sqlite3",
                "hypothesis": "sqlite3 writing to TCC.db to grant permissions — bypasses macOS privacy controls without user prompt.",
                "splunk": 'index=macos_edr process_name=sqlite3 target_path="*TCC.db*" | table _time, host, user, cmdline, parent_process',
                "kql": 'DeviceFileEvents | where OSPlatform == "macOS" | where FileName == "TCC.db" | where InitiatingProcessFileName == "sqlite3" | project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine',
                "elastic": "process.name:sqlite3 AND file.path:*TCC.db*",
                "sigma_logsource": "macos/file_event",
            },
            "edr_macos": {
                "name": "EDR on macOS — TCC parent-child chain",
                "hypothesis": "Finder or SystemUIServer directed by an untrusted process to rename or move the com.apple.TCC directory.",
                "splunk": 'index=macos_edr process_name IN ("Finder","SystemUIServer") | where NOT match(parent_process_name,"(?i)(loginwindow|launchd)") | table _time, host, user, parent_process_name, cmdline',
                "kql": 'DeviceProcessEvents | where OSPlatform == "macOS" | where FileName in~ ("Finder","SystemUIServer") | where not InitiatingProcessFileName in~ ("loginwindow","launchd") | project TimeGenerated, DeviceName, AccountName, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine',
                "elastic": "process.name:(Finder OR SystemUIServer) AND NOT process.parent.name:(loginwindow OR launchd)",
                "sigma_logsource": "macos/process_creation",
            },
        },
    },
    "T1555.003": {
        "name": "Credentials from Keychain / Web Browsers",
        "tactic": "credential-access",
        "log_sources": {
            "macos_unified_log": {
                "name": "macOS Unified Log — security CLI",
                "hypothesis": "security find-generic-password or find-internet-password invoked by a non-browser, non-Apple process.",
                "splunk": 'index=macos_edr process_name=security cmdline IN ("*find-generic-password*","*find-internet-password*") | where NOT match(parent_process_name,"(?i)(Safari|Chrome|Firefox|1Password|Keychain)") | table _time, host, user, cmdline',
                "kql": 'DeviceProcessEvents | where OSPlatform == "macOS" | where FileName == "security" | where ProcessCommandLine has_any ("find-generic-password","find-internet-password") | where not InitiatingProcessFileName has_any ("Safari","Chrome","Firefox","1Password") | project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName',
                "elastic": "process.name:security AND process.command_line:(find-generic-password OR find-internet-password) AND NOT process.parent.name:(Safari OR Chrome OR Firefox)",
                "sigma_logsource": "macos/process_creation",
            },
            "edr_macos": {
                "name": "EDR on macOS — browser profile exfil",
                "hypothesis": "ZIP archive created from ~/Library/Application Support/<browser>/Default containing cookies, login data, or keychain files.",
                "splunk": 'index=macos_edr process_name IN ("zip","tar","python3") cmdline="*Library/Application Support*" cmdline IN ("*Cookies*","*Login Data*","*keychain*") | table _time, host, user, cmdline',
                "kql": 'DeviceProcessEvents | where OSPlatform == "macOS" | where FileName in~ ("zip","tar","python3") | where ProcessCommandLine has "Library/Application Support" | where ProcessCommandLine has_any ("Cookies","Login Data","keychain") | project TimeGenerated, DeviceName, AccountName, ProcessCommandLine',
                "elastic": "process.name:(zip OR tar OR python3) AND process.command_line:*Application Support* AND process.command_line:(*Cookies* OR *Login Data* OR *keychain*)",
                "sigma_logsource": "macos/process_creation",
            },
        },
    },
    "T1539": {
        "name": "Steal Web Session Cookie",
        "tactic": "credential-access",
        "log_sources": {
            "edr_macos": {
                "name": "EDR on macOS — Telegram / app session theft",
                "hypothesis": "Access to Telegram tdata or session db files by a process other than Telegram itself — session hijacking.",
                "splunk": 'index=macos_edr target_path IN ("*Telegram*","*tdata*","*leveldb*") | where NOT match(process_name,"(?i)(Telegram|Electron)") | table _time, host, user, process_name, target_path',
                "kql": 'DeviceFileEvents | where OSPlatform == "macOS" | where FolderPath has_any ("Telegram","tdata") | where not InitiatingProcessFileName has_any ("Telegram","Electron") | project TimeGenerated, DeviceName, AccountName, FolderPath, FileName, InitiatingProcessFileName',
                "elastic": "file.path:(*Telegram* OR *tdata*) AND NOT process.name:(Telegram OR Electron) AND event.action:open",
                "sigma_logsource": "macos/file_event",
            },
        },
    },
    "T1567.002": {
        "name": "Exfiltration via Web Service (Telegram Bot API)",
        "tactic": "exfiltration",
        "log_sources": {
            "proxy_logs": {
                "name": "Web Proxy / Network Flow Logs",
                "hypothesis": "Large HTTPS POST to api.telegram.org from a non-Telegram process — Telegram Bot API used as exfil channel.",
                "splunk": 'index=proxy dest_host="api.telegram.org" cs_method=POST | where bytes_out > 50000 | stats sum(bytes_out) as total_bytes, count by src_ip, user_agent | where NOT match(user_agent,"(?i)(TelegramDesktop|Telegram for)")',
                "kql": 'CommonSecurityLog | where DestinationHostName =~ "api.telegram.org" and RequestMethod == "POST" and SentBytes > 50000 | where not UserAgent has_any ("TelegramDesktop","Telegram for") | summarize TotalBytes=sum(SentBytes), Requests=count() by SourceIP, UserAgent',
                "elastic": "destination.domain:api.telegram.org AND http.request.method:POST AND NOT http.request.headers.user_agent:*Telegram*",
                "sigma_logsource": "proxy",
            },
            "edr_macos": {
                "name": "EDR on macOS — curl to Telegram",
                "hypothesis": "curl or python making POST requests to api.telegram.org with sendDocument or sendMessage endpoints — data exfil via bot.",
                "splunk": 'index=macos_edr process_name IN ("curl","python3","python") cmdline IN ("*api.telegram.org*","*sendDocument*","*sendMessage*") | table _time, host, user, cmdline',
                "kql": 'DeviceProcessEvents | where OSPlatform == "macOS" | where FileName in~ ("curl","python3","python") | where ProcessCommandLine has "api.telegram.org" | project TimeGenerated, DeviceName, AccountName, ProcessCommandLine',
                "elastic": "process.name:(curl OR python3 OR python) AND process.command_line:*api.telegram.org*",
                "sigma_logsource": "macos/process_creation",
            },
        },
    },
    "T1204.002": {
        "name": "User Execution: Malicious File",
        "tactic": "execution",
        "log_sources": {
            "edr_macos": {
                "name": "EDR on macOS — Script Editor / user-opened file",
                "hypothesis": "Script Editor opening an .scpt file with a large blank-line offset hiding malicious code — user-initiated execution.",
                "splunk": 'index=macos_edr process_name="Script Editor" | where file_path="*.scpt" | where NOT match(file_path,"(?i)(/Applications/|/System/)") | table _time, host, user, file_path, cmdline',
                "kql": 'DeviceProcessEvents | where OSPlatform == "macOS" | where InitiatingProcessFileName == "Script Editor" | where ProcessCommandLine has ".scpt" | where not ProcessCommandLine has_any ("/Applications/","/System/") | project TimeGenerated, DeviceName, AccountName, ProcessCommandLine',
                "elastic": "process.parent.name:Script Editor AND process.command_line:*.scpt AND NOT process.command_line:*/Applications/*",
                "sigma_logsource": "macos/process_creation",
            },
        },
    },
    "T1560.001": {
        "name": "Archive Collected Data: Archive via Utility",
        "tactic": "collection",
        "log_sources": {
            "edr_macos": {
                "name": "EDR on macOS — zip / tar before exfil",
                "hypothesis": "zip or tar archiving user data directories (Documents, Downloads, SSH keys, browser profiles) shortly before a network connection.",
                "splunk": 'index=macos_edr process_name IN ("zip","tar","ditto") cmdline IN ("*Documents*","*Downloads*","*.ssh*","*Library/Application Support*") | table _time, host, user, cmdline, parent_process',
                "kql": 'DeviceProcessEvents | where OSPlatform == "macOS" | where FileName in~ ("zip","tar","ditto") | where ProcessCommandLine has_any ("Documents","Downloads",".ssh","Application Support") | project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName',
                "elastic": "process.name:(zip OR tar OR ditto) AND process.command_line:(*Documents* OR *Downloads* OR *.ssh* OR *Application Support*)",
                "sigma_logsource": "macos/process_creation",
            },
        },
    },
}

# ── SQL queries (security data lake — Snowflake / BigQuery / AWS Athena / Databricks)
# Keyed by (technique_id, log_source_key). Standard tables assumed:
#   process_events(event_time, hostname, username, process_name, cmdline, parent_name)
#   auth_events(event_time, hostname, username, src_ip, logon_type, event_code, result)
#   network_events(event_time, src_ip, dst_ip, dst_port, method, host, bytes_out, action)
#   dns_events(event_time, src_ip, query, query_type)
#   file_events(event_time, hostname, process_name, file_path, file_name, file_ext)
#   registry_events(event_time, hostname, process_name, reg_path, reg_value)
#   script_block(event_time, hostname, username, script_text)
#   web_logs(event_time, src_ip, method, uri_stem, uri_query, status_code)
#   email_events(event_time, sender, recipient, subject, attachment_ext)
#   cloud_trail(event_time, principal_arn, action, resource, src_ip, region, user_agent, error_code)
#   k8s_audit(event_time, username, verb, resource, namespace, name, subresource)
#   container_events(event_time, host, container_id, image, action, cmdline)
_SQL_QUERIES: dict[tuple[str, str], str] = {
    ("T1059.001", "script_block_logging"): (
        "SELECT event_time, hostname, username, script_text\n"
        "FROM script_block\n"
        "WHERE (LOWER(script_text) LIKE '%encodedcommand%'\n"
        "   OR  LOWER(script_text) LIKE '%iex(%'\n"
        "   OR  LOWER(script_text) LIKE '%downloadstring%')\n"
        "ORDER BY event_time DESC LIMIT 200"
    ),
    ("T1059.001", "sysmon_process"): (
        "SELECT event_time, hostname, parent_name, cmdline\n"
        "FROM process_events\n"
        "WHERE LOWER(process_name) = 'powershell.exe'\n"
        "  AND (LOWER(cmdline) LIKE '%-enc%'\n"
        "   OR  LOWER(cmdline) LIKE '%-w hidden%'\n"
        "   OR  LOWER(cmdline) LIKE '%-nop%'\n"
        "   OR  LOWER(parent_name) IN ('winword.exe','excel.exe','outlook.exe'))\n"
        "ORDER BY event_time DESC LIMIT 200"
    ),
    ("T1059.003", "sysmon_process"): (
        "SELECT event_time, hostname, parent_name, cmdline\n"
        "FROM process_events\n"
        "WHERE LOWER(process_name) = 'cmd.exe'\n"
        "  AND LOWER(cmdline) LIKE '%/c%'\n"
        "  AND LOWER(parent_name) NOT LIKE '%explorer.exe%'\n"
        "ORDER BY event_time DESC LIMIT 200"
    ),
    ("T1003.001", "sysmon_process_access"): (
        "SELECT event_time, hostname, process_name, cmdline\n"
        "FROM process_events\n"
        "WHERE LOWER(cmdline) LIKE '%lsass%'\n"
        "  AND LOWER(process_name) NOT IN ('svchost.exe','wininit.exe','csrss.exe')\n"
        "ORDER BY event_time DESC LIMIT 200"
    ),
    ("T1003.001", "windows_defender"): (
        "SELECT event_time, hostname, process_name, cmdline\n"
        "FROM process_events\n"
        "WHERE LOWER(process_name) IN ('mimikatz.exe','procdump.exe','procdump64.exe')\n"
        "   OR (LOWER(cmdline) LIKE '%comsvcs%' AND LOWER(cmdline) LIKE '%minidump%')\n"
        "ORDER BY event_time DESC LIMIT 200"
    ),
    ("T1071.001", "proxy_logs"): (
        "SELECT src_ip, host, COUNT(*) AS requests,\n"
        "       COUNT(DISTINCT method) AS unique_methods,\n"
        "       MAX(event_time) - MIN(event_time) AS duration_secs\n"
        "FROM network_events\n"
        "WHERE method IN ('GET','POST') AND dst_port IN (80, 443)\n"
        "GROUP BY src_ip, host\n"
        "HAVING requests > 20 AND unique_methods < 3\n"
        "   AND DATEDIFF('second', MIN(event_time), MAX(event_time)) > 3600\n"
        "ORDER BY requests DESC LIMIT 100"
    ),
    ("T1071.001", "dns_logs"): (
        "SELECT src_ip, query, COUNT(*) AS hits\n"
        "FROM dns_events\n"
        "WHERE query_type = 'A'\n"
        "GROUP BY src_ip, query\n"
        "HAVING hits > 50\n"
        "ORDER BY hits DESC LIMIT 200"
    ),
    ("T1071.004", "dns_logs"): (
        "SELECT src_ip, query, LENGTH(query) AS qlen\n"
        "FROM dns_events\n"
        "WHERE LENGTH(query) > 50\n"
        "ORDER BY qlen DESC LIMIT 200"
    ),
    ("T1053.005", "windows_event_4698"): (
        "SELECT event_time, hostname, username, cmdline\n"
        "FROM process_events\n"
        "WHERE event_code = '4698'\n"
        "  AND (LOWER(cmdline) LIKE '%temp%' OR LOWER(cmdline) LIKE '%appdata%'\n"
        "   OR  LOWER(cmdline) LIKE '%encodedcommand%')\n"
        "ORDER BY event_time DESC LIMIT 200"
    ),
    ("T1053.005", "sysmon_process"): (
        "SELECT event_time, hostname, cmdline\n"
        "FROM process_events\n"
        "WHERE LOWER(process_name) IN ('schtasks.exe','at.exe')\n"
        "  AND LOWER(cmdline) LIKE '%/create%'\n"
        "ORDER BY event_time DESC LIMIT 200"
    ),
    ("T1547.001", "sysmon_registry"): (
        "SELECT event_time, hostname, process_name, reg_path, reg_value\n"
        "FROM registry_events\n"
        "WHERE LOWER(reg_path) LIKE '%currentversion\\\\run%'\n"
        "  AND LOWER(reg_value) NOT LIKE '%program files%'\n"
        "  AND LOWER(reg_value) NOT LIKE '%windows%'\n"
        "ORDER BY event_time DESC LIMIT 200"
    ),
    ("T1543.003", "windows_event_7045"): (
        "SELECT event_time, hostname, username, cmdline\n"
        "FROM process_events\n"
        "WHERE event_code = '7045'\n"
        "  AND (LOWER(cmdline) LIKE '%temp%' OR LOWER(cmdline) LIKE '%appdata%'\n"
        "   OR  LOWER(cmdline) LIKE '%powershell%' OR LOWER(cmdline) LIKE '%cmd.exe%')\n"
        "ORDER BY event_time DESC LIMIT 200"
    ),
    ("T1505.003", "web_server_logs"): (
        "SELECT src_ip, uri_stem, COUNT(*) AS posts\n"
        "FROM web_logs\n"
        "WHERE LOWER(method) = 'post'\n"
        "  AND (LOWER(uri_stem) LIKE '%.aspx' OR LOWER(uri_stem) LIKE '%.php'\n"
        "   OR  LOWER(uri_stem) LIKE '%.jsp')\n"
        "  AND LOWER(uri_stem) NOT LIKE '%login%' AND LOWER(uri_stem) NOT LIKE '%api%'\n"
        "GROUP BY src_ip, uri_stem HAVING posts > 5\n"
        "ORDER BY posts DESC LIMIT 100"
    ),
    ("T1566.001", "email_gateway"): (
        "SELECT sender, recipient, subject, COUNT(*) AS emails\n"
        "FROM email_events\n"
        "WHERE LOWER(attachment_ext) IN ('.xlsm','.docm','.zip','.7z','.xls')\n"
        "GROUP BY sender, recipient, subject\n"
        "HAVING emails = 1\n"
        "ORDER BY MAX(event_time) DESC LIMIT 200"
    ),
    ("T1566.001", "sysmon_process"): (
        "SELECT event_time, hostname, parent_name, process_name, cmdline\n"
        "FROM process_events\n"
        "WHERE LOWER(parent_name) IN ('winword.exe','excel.exe','outlook.exe','powerpnt.exe')\n"
        "  AND LOWER(process_name) NOT IN ('splwow64.exe','werfault.exe')\n"
        "ORDER BY event_time DESC LIMIT 200"
    ),
    ("T1021.001", "windows_event_4624"): (
        "SELECT src_ip, username, hostname, COUNT(*) AS sessions\n"
        "FROM auth_events\n"
        "WHERE event_code = '4624' AND logon_type = '10'\n"
        "GROUP BY src_ip, username, hostname\n"
        "HAVING sessions > 1\n"
        "ORDER BY sessions DESC LIMIT 200"
    ),
    ("T1021.002", "windows_event_4624"): (
        "SELECT username, src_ip, COUNT(DISTINCT hostname) AS host_count\n"
        "FROM auth_events\n"
        "WHERE event_code = '4624' AND logon_type = '3'\n"
        "  AND username NOT LIKE '%$'\n"
        "GROUP BY username, src_ip\n"
        "HAVING host_count > 3\n"
        "ORDER BY host_count DESC LIMIT 200"
    ),
    ("T1078", "windows_event_4624"): (
        "SELECT username, src_ip, hostname,\n"
        "       EXTRACT(HOUR FROM event_time) AS login_hour\n"
        "FROM auth_events\n"
        "WHERE event_code = '4624'\n"
        "  AND (EXTRACT(HOUR FROM event_time) < 7\n"
        "   OR  EXTRACT(HOUR FROM event_time) > 20)\n"
        "ORDER BY event_time DESC LIMIT 200"
    ),
    ("T1110.003", "windows_event_4625"): (
        "SELECT src_ip, COUNT(DISTINCT username) AS distinct_users,\n"
        "       COUNT(*) AS failures\n"
        "FROM auth_events\n"
        "WHERE event_code = '4625'\n"
        "GROUP BY src_ip\n"
        "HAVING distinct_users > 10\n"
        "ORDER BY distinct_users DESC LIMIT 100"
    ),
    ("T1055", "sysmon_create_remote_thread"): (
        "SELECT event_time, hostname, process_name, cmdline\n"
        "FROM process_events\n"
        "WHERE LOWER(cmdline) LIKE '%createremotethread%'\n"
        "   OR LOWER(cmdline) LIKE '%virtualallocex%'\n"
        "ORDER BY event_time DESC LIMIT 200"
    ),
    ("T1041", "proxy_logs"): (
        "SELECT src_ip, host,\n"
        "       ROUND(SUM(bytes_out) / 1024.0 / 1024.0, 2) AS total_mb\n"
        "FROM network_events\n"
        "WHERE LOWER(method) = 'post'\n"
        "GROUP BY src_ip, host\n"
        "HAVING SUM(bytes_out) > 10000000\n"
        "ORDER BY total_mb DESC LIMIT 100"
    ),
    ("T1027", "script_block_logging"): (
        "SELECT event_time, hostname, username, script_text\n"
        "FROM script_block\n"
        "WHERE LOWER(script_text) LIKE '%char(%'\n"
        "   OR LOWER(script_text) LIKE '%-bxor%'\n"
        "   OR LOWER(script_text) LIKE '%[convert]%'\n"
        "   OR LOWER(script_text) LIKE '%concat(%'\n"
        "ORDER BY event_time DESC LIMIT 200"
    ),
    ("T1046", "firewall_logs"): (
        "SELECT src_ip,\n"
        "       COUNT(DISTINCT dst_port) AS distinct_ports,\n"
        "       COUNT(DISTINCT dst_ip) AS distinct_hosts\n"
        "FROM network_events\n"
        "WHERE action = 'deny'\n"
        "GROUP BY src_ip\n"
        "HAVING distinct_ports > 20 OR distinct_hosts > 20\n"
        "ORDER BY distinct_ports DESC LIMIT 100"
    ),
    ("T1486", "sysmon_file"): (
        "SELECT hostname, file_ext, COUNT(*) AS file_count\n"
        "FROM file_events\n"
        "WHERE LOWER(file_ext) IN ('encrypted','locked','crypt','ryk','maze')\n"
        "   OR LOWER(file_name) LIKE '%readme%' OR LOWER(file_name) LIKE '%decrypt%'\n"
        "   OR LOWER(file_name) LIKE '%ransom%'\n"
        "GROUP BY hostname, file_ext\n"
        "HAVING file_count > 10\n"
        "ORDER BY file_count DESC LIMIT 100"
    ),
    ("T1558.003", "windows_event_4769"): (
        "SELECT username, src_ip, COUNT(*) AS ticket_requests\n"
        "FROM auth_events\n"
        "WHERE event_code = '4769'\n"
        "  AND LOWER(result) LIKE '%0x17%'\n"
        "  AND username NOT LIKE '%$'\n"
        "GROUP BY username, src_ip\n"
        "ORDER BY ticket_requests DESC LIMIT 200"
    ),
    ("T1190", "web_server_logs"): (
        "SELECT event_time, src_ip, uri_stem, uri_query\n"
        "FROM web_logs\n"
        "WHERE LOWER(uri_query) LIKE '%select %'\n"
        "   OR LOWER(uri_query) LIKE '%union %'\n"
        "   OR uri_query LIKE '%../%'\n"
        "   OR LOWER(uri_query) LIKE '%;cmd%'\n"
        "   OR LOWER(uri_query) LIKE '%exec(%'\n"
        "ORDER BY event_time DESC LIMIT 200"
    ),
    ("T1195.001", "github_actions_audit"): (
        "SELECT event_time, actor, resource AS repo, action\n"
        "FROM cloud_trail\n"
        "WHERE action IN ('package.publish','workflows.completed')\n"
        "  AND error_code IS NULL\n"
        "  AND src_ip IS NOT NULL\n"
        "ORDER BY event_time DESC LIMIT 200"
    ),
    ("T1195.001", "aws_cloudtrail"): (
        "SELECT event_time, principal_arn, action, resource, src_ip\n"
        "FROM cloud_trail\n"
        "WHERE action = 'StartBuild'\n"
        "  AND resource LIKE '%codebuild%'\n"
        "  AND error_code IS NULL\n"
        "ORDER BY event_time DESC LIMIT 200"
    ),
    ("T1195.002", "github_actions_audit"): (
        "SELECT event_time, actor, resource AS repo, action\n"
        "FROM cloud_trail\n"
        "WHERE action = 'workflows.run_attempt'\n"
        "  AND region IN ('main','master')\n"
        "ORDER BY event_time DESC LIMIT 200"
    ),
    ("T1552.005", "aws_cloudtrail"): (
        "SELECT event_time, principal_arn, src_ip, user_agent\n"
        "FROM cloud_trail\n"
        "WHERE action = 'GetSessionToken'\n"
        "  AND LOWER(user_agent) SIMILAR TO '%(curl|wget|python|ruby|powershell)%'\n"
        "ORDER BY event_time DESC LIMIT 200"
    ),
    ("T1552.005", "gcp_cloud_logging"): (
        "SELECT event_time, principal_arn AS principal, resource, src_ip\n"
        "FROM cloud_trail\n"
        "WHERE resource LIKE '%computeMetadata%'\n"
        "GROUP BY event_time, principal_arn, resource, src_ip\n"
        "HAVING COUNT(*) > 100\n"
        "ORDER BY event_time DESC LIMIT 200"
    ),
    ("T1552.005", "azure_activity_logs"): (
        "SELECT event_time, principal_arn AS principal, resource, COUNT(*) AS token_requests\n"
        "FROM cloud_trail\n"
        "WHERE LOWER(action) LIKE '%retrieve%token%'\n"
        "GROUP BY event_time, principal_arn, resource\n"
        "HAVING token_requests > 50\n"
        "ORDER BY token_requests DESC LIMIT 100"
    ),
    ("T1078.004", "aws_cloudtrail"): (
        "SELECT event_time, principal_arn, action, src_ip, region\n"
        "FROM cloud_trail\n"
        "WHERE action IN ('AssumeRole','ConsoleLogin') AND error_code IS NULL\n"
        "  AND src_ip NOT LIKE '10.%' AND src_ip NOT LIKE '172.1%'\n"
        "  AND src_ip NOT LIKE '192.168.%'\n"
        "ORDER BY event_time DESC LIMIT 200"
    ),
    ("T1078.004", "azure_activity_logs"): (
        "SELECT event_time, principal_arn AS principal, src_ip, region AS location\n"
        "FROM cloud_trail\n"
        "WHERE action LIKE '%ServicePrincipal%SignIn%'\n"
        "  AND error_code IS NULL\n"
        "  AND src_ip NOT LIKE '10.%' AND src_ip NOT LIKE '192.168.%'\n"
        "ORDER BY event_time DESC LIMIT 200"
    ),
    ("T1078.004", "gcp_cloud_logging"): (
        "SELECT event_time, principal_arn AS service_account, src_ip\n"
        "FROM cloud_trail\n"
        "WHERE principal_arn LIKE '%serviceAccountKey%'\n"
        "  AND src_ip NOT LIKE '10.%' AND src_ip NOT LIKE '35.%'\n"
        "  AND src_ip NOT LIKE '34.%'\n"
        "ORDER BY event_time DESC LIMIT 200"
    ),
    ("T1530", "aws_cloudtrail"): (
        "SELECT principal_arn, resource AS bucket,\n"
        "       COUNT(*) AS requests,\n"
        "       COUNT(DISTINCT resource) AS objects\n"
        "FROM cloud_trail\n"
        "WHERE action = 'GetObject' AND resource LIKE '%s3%'\n"
        "GROUP BY principal_arn, resource\n"
        "HAVING requests > 100\n"
        "ORDER BY requests DESC LIMIT 100"
    ),
    ("T1530", "gcp_cloud_logging"): (
        "SELECT principal_arn AS principal, resource AS bucket, COUNT(*) AS downloads\n"
        "FROM cloud_trail\n"
        "WHERE action = 'storage.objects.get'\n"
        "GROUP BY principal_arn, resource\n"
        "HAVING downloads > 100\n"
        "ORDER BY downloads DESC LIMIT 100"
    ),
    ("T1530", "azure_activity_logs"): (
        "SELECT src_ip, resource AS storage_account,\n"
        "       COUNT(*) AS blob_reads,\n"
        "       COUNT(DISTINCT resource) AS unique_blobs\n"
        "FROM cloud_trail\n"
        "WHERE action = 'GetBlob'\n"
        "GROUP BY src_ip, resource\n"
        "HAVING blob_reads > 200\n"
        "ORDER BY blob_reads DESC LIMIT 100"
    ),
    ("T1609", "k8s_audit"): (
        "SELECT event_time, username, namespace, name, subresource\n"
        "FROM k8s_audit\n"
        "WHERE verb = 'create' AND resource = 'pods'\n"
        "  AND subresource IN ('exec','attach')\n"
        "  AND username NOT LIKE 'system:serviceaccount:kube-system%'\n"
        "ORDER BY event_time DESC LIMIT 200"
    ),
    ("T1609", "docker_daemon"): (
        "SELECT event_time, host, container_id, cmdline\n"
        "FROM container_events\n"
        "WHERE action = 'exec_create'\n"
        "  AND (LOWER(cmdline) LIKE '%/bin/%' OR LOWER(cmdline) LIKE '%bash%'\n"
        "   OR  LOWER(cmdline) LIKE '%sh%' OR LOWER(cmdline) LIKE '%powershell%')\n"
        "ORDER BY event_time DESC LIMIT 200"
    ),
    ("T1610", "k8s_audit"): (
        "SELECT event_time, username, namespace, name\n"
        "FROM k8s_audit\n"
        "WHERE verb = 'create'\n"
        "  AND resource IN ('pods','daemonsets','deployments')\n"
        "  AND (name LIKE '%privileged%' OR name LIKE '%hostpid%')\n"
        "ORDER BY event_time DESC LIMIT 200"
    ),
    ("T1610", "aws_cloudtrail"): (
        "SELECT event_time, principal_arn, action, resource\n"
        "FROM cloud_trail\n"
        "WHERE action IN ('RegisterTaskDefinition','RunTask')\n"
        "  AND resource LIKE '%ecs%'\n"
        "ORDER BY event_time DESC LIMIT 200"
    ),
    ("T1610", "docker_daemon"): (
        "SELECT event_time, host, container_id, image, cmdline\n"
        "FROM container_events\n"
        "WHERE action = 'container_start'\n"
        "  AND (LOWER(cmdline) LIKE '%privileged%' OR LOWER(cmdline) LIKE '%hostpid%'\n"
        "   OR  LOWER(image) IN ('alpine','busybox','kalilinux'))\n"
        "ORDER BY event_time DESC LIMIT 200"
    ),
    ("T1613", "k8s_audit"): (
        "SELECT username, resource, namespace, COUNT(*) AS requests\n"
        "FROM k8s_audit\n"
        "WHERE verb IN ('list','watch')\n"
        "  AND resource IN ('pods','secrets','clusterroles','nodes')\n"
        "GROUP BY username, resource, namespace\n"
        "HAVING requests > 50\n"
        "ORDER BY requests DESC LIMIT 100"
    ),
    ("T1613", "docker_daemon"): (
        "SELECT host, container_id, COUNT(*) AS list_calls\n"
        "FROM container_events\n"
        "WHERE action IN ('container_list','container_inspect')\n"
        "GROUP BY host, container_id\n"
        "HAVING list_calls > 20\n"
        "ORDER BY list_calls DESC LIMIT 100"
    ),
    ("T1059.002", "macos_unified_log"): (
        "SELECT event_time, hostname, username, cmdline\n"
        "FROM process_events\n"
        "WHERE LOWER(process_name) = 'osascript'\n"
        "  AND (LOWER(cmdline) LIKE '%-e%' OR LOWER(cmdline) LIKE '%curl%'\n"
        "   OR  LOWER(cmdline) LIKE '%http%')\n"
        "ORDER BY event_time DESC LIMIT 200"
    ),
    ("T1059.002", "edr_macos"): (
        "SELECT event_time, hostname, process_name, parent_name, cmdline\n"
        "FROM process_events\n"
        "WHERE LOWER(parent_name) IN ('script editor','osascript')\n"
        "  AND LOWER(process_name) IN ('curl','python','python3','bash','sh')\n"
        "ORDER BY event_time DESC LIMIT 200"
    ),
    ("T1543.001", "macos_unified_log"): (
        "SELECT event_time, hostname, process_name, file_path\n"
        "FROM file_events\n"
        "WHERE (LOWER(file_path) LIKE '%/library/launchdaemons/%'\n"
        "   OR  LOWER(file_path) LIKE '%/library/launchagents/%')\n"
        "  AND LOWER(file_path) NOT LIKE '%apple%'\n"
        "  AND LOWER(file_path) NOT LIKE '%microsoft%'\n"
        "ORDER BY event_time DESC LIMIT 200"
    ),
    ("T1543.001", "edr_macos"): (
        "SELECT event_time, hostname, username, cmdline\n"
        "FROM process_events\n"
        "WHERE LOWER(process_name) = 'launchctl'\n"
        "  AND LOWER(cmdline) LIKE '%load%'\n"
        "  AND LOWER(cmdline) NOT LIKE '%/system/library/%'\n"
        "  AND LOWER(cmdline) NOT LIKE '%/usr/libexec/%'\n"
        "ORDER BY event_time DESC LIMIT 200"
    ),
    ("T1548.006", "macos_unified_log"): (
        "SELECT event_time, hostname, process_name, file_path\n"
        "FROM file_events\n"
        "WHERE LOWER(process_name) = 'sqlite3' AND LOWER(file_path) LIKE '%tcc.db%'\n"
        "ORDER BY event_time DESC LIMIT 200"
    ),
    ("T1548.006", "edr_macos"): (
        "SELECT event_time, hostname, process_name, parent_name, cmdline\n"
        "FROM process_events\n"
        "WHERE LOWER(process_name) IN ('finder','systemuiserver')\n"
        "  AND LOWER(parent_name) NOT IN ('loginwindow','launchd')\n"
        "ORDER BY event_time DESC LIMIT 200"
    ),
    ("T1555.003", "macos_unified_log"): (
        "SELECT event_time, hostname, username, parent_name, cmdline\n"
        "FROM process_events\n"
        "WHERE LOWER(process_name) = 'security'\n"
        "  AND (LOWER(cmdline) LIKE '%find-generic-password%'\n"
        "   OR  LOWER(cmdline) LIKE '%find-internet-password%')\n"
        "  AND LOWER(parent_name) NOT IN ('safari','chrome','firefox','1password')\n"
        "ORDER BY event_time DESC LIMIT 200"
    ),
    ("T1555.003", "edr_macos"): (
        "SELECT event_time, hostname, username, process_name, cmdline\n"
        "FROM process_events\n"
        "WHERE LOWER(process_name) IN ('zip','tar','python3')\n"
        "  AND LOWER(cmdline) LIKE '%application support%'\n"
        "  AND (LOWER(cmdline) LIKE '%cookies%' OR LOWER(cmdline) LIKE '%login data%'\n"
        "   OR  LOWER(cmdline) LIKE '%keychain%')\n"
        "ORDER BY event_time DESC LIMIT 200"
    ),
    ("T1539", "edr_macos"): (
        "SELECT event_time, hostname, username, process_name, file_path\n"
        "FROM file_events\n"
        "WHERE (LOWER(file_path) LIKE '%telegram%' OR LOWER(file_path) LIKE '%tdata%')\n"
        "  AND LOWER(process_name) NOT IN ('telegram','electron')\n"
        "ORDER BY event_time DESC LIMIT 200"
    ),
    ("T1567.002", "proxy_logs"): (
        "SELECT src_ip, user_agent,\n"
        "       ROUND(SUM(bytes_out) / 1024.0, 2) AS total_kb,\n"
        "       COUNT(*) AS requests\n"
        "FROM network_events\n"
        "WHERE LOWER(host) = 'api.telegram.org' AND LOWER(method) = 'post'\n"
        "  AND bytes_out > 50000\n"
        "  AND LOWER(user_agent) NOT LIKE '%telegramdesktop%'\n"
        "GROUP BY src_ip, user_agent\n"
        "ORDER BY total_kb DESC LIMIT 100"
    ),
    ("T1567.002", "edr_macos"): (
        "SELECT event_time, hostname, username, process_name, cmdline\n"
        "FROM process_events\n"
        "WHERE LOWER(process_name) IN ('curl','python3','python')\n"
        "  AND LOWER(cmdline) LIKE '%api.telegram.org%'\n"
        "ORDER BY event_time DESC LIMIT 200"
    ),
    ("T1204.002", "edr_macos"): (
        "SELECT event_time, hostname, username, parent_name, cmdline\n"
        "FROM process_events\n"
        "WHERE LOWER(parent_name) = 'script editor'\n"
        "  AND LOWER(cmdline) LIKE '%.scpt%'\n"
        "  AND LOWER(cmdline) NOT LIKE '%/applications/%'\n"
        "  AND LOWER(cmdline) NOT LIKE '%/system/%'\n"
        "ORDER BY event_time DESC LIMIT 200"
    ),
    ("T1560.001", "edr_macos"): (
        "SELECT event_time, hostname, username, process_name, cmdline\n"
        "FROM process_events\n"
        "WHERE LOWER(process_name) IN ('zip','tar','ditto')\n"
        "  AND (LOWER(cmdline) LIKE '%documents%' OR LOWER(cmdline) LIKE '%downloads%'\n"
        "   OR  LOWER(cmdline) LIKE '%.ssh%' OR LOWER(cmdline) LIKE '%application support%')\n"
        "ORDER BY event_time DESC LIMIT 200"
    ),
}


# Canonical log source tags → friendly names
_LOG_SOURCE_LABELS: dict[str, str] = {
    # Windows / Sysmon
    "sysmon_process": "Sysmon Process Creation (EID 1)",
    "sysmon_process_access": "Sysmon Process Access (EID 10)",
    "sysmon_registry": "Sysmon Registry Events (EID 13)",
    "sysmon_file": "Sysmon File Events (EID 11)",
    "sysmon_create_remote_thread": "Sysmon CreateRemoteThread (EID 8)",
    "script_block_logging": "PowerShell Script Block Logging (EID 4104)",
    "windows_event_4624": "Windows Security - Successful Logon (EID 4624)",
    "windows_event_4625": "Windows Security - Failed Logon (EID 4625)",
    "windows_event_4698": "Windows Security - Scheduled Task Created (EID 4698)",
    "windows_event_4769": "Windows Security - Kerberos Ticket (EID 4769)",
    "windows_event_7045": "Windows System - New Service (EID 7045)",
    "windows_defender": "Microsoft Defender / EDR",
    # Network
    "proxy_logs": "Web Proxy / Firewall HTTP Logs",
    "dns_logs": "DNS Query Logs",
    "email_gateway": "Email Gateway Logs",
    "web_server_logs": "Web Server / WAF Logs",
    "firewall_logs": "Firewall / Network Flow Logs",
    # macOS
    "macos_unified_log": "macOS Unified Log (log show / log stream)",
    "edr_macos": "EDR on macOS (Defender for Endpoint, CrowdStrike, SentinelOne)",
    # Cloud — AWS
    "aws_cloudtrail": "AWS CloudTrail",
    # Cloud — Azure
    "azure_activity_logs": "Azure Monitor / Activity Logs",
    # Cloud — GCP
    "gcp_cloud_logging": "GCP Cloud Logging / Audit Logs",
    # Container / Kubernetes
    "k8s_audit": "Kubernetes API Server Audit Log",
    "docker_daemon": "Docker Daemon / Containerd Logs",
    # CI / SCM
    "github_actions_audit": "GitHub Actions / Audit Log",
}


def generate_hunt_hypothesis(text: str) -> str:
    """Generate hunt hypotheses from free-form threat intel text.

    Calls map_attack internally to extract technique IDs, then returns
    hypotheses for all available log sources. Pass log_sources='sysmon,dns'
    to filter to specific sources only.
    """
    from threat_research_mcp.tools.map_attack import map_attack

    attack_result = json.loads(map_attack(text))
    technique_ids = [t["id"] for t in attack_result.get("techniques", [])]

    if not technique_ids:
        return json.dumps(
            {
                "hypotheses": [],
                "note": "No ATT&CK techniques detected in the provided text. Try including technique names, tool names, or TTP keywords.",
            },
            indent=2,
        )

    return generate_hunt_hypotheses_for_techniques(technique_ids)


def generate_hunt_hypotheses_for_techniques(
    technique_ids: list[str],
    log_source_filter: list[str] | None = None,
) -> str:
    """Generate hunt hypotheses for explicit ATT&CK technique IDs.

    Args:
        technique_ids: List of ATT&CK IDs e.g. ["T1059.001", "T1003.001"]
        log_source_filter: Optional list of log source keys to filter results.
                           If None, all available log sources are returned.
                           Example: ["sysmon_process", "dns_logs"]
    """
    hypotheses = []
    missing = []

    for tid in technique_ids:
        tid = tid.strip().upper()
        entry = _PLAYBOOK.get(tid)
        if not entry:
            missing.append(tid)
            continue

        for src_key, src in entry["log_sources"].items():
            if log_source_filter and src_key not in log_source_filter:
                continue

            hypotheses.append(
                {
                    "technique_id": tid,
                    "technique_name": entry["name"],
                    "tactic": entry["tactic"],
                    "log_source_key": src_key,
                    "log_source": src["name"],
                    "hypothesis": src["hypothesis"],
                    "queries": {
                        "splunk": src.get("splunk", ""),
                        "kql": src.get("kql", ""),
                        "elastic": src.get("elastic", ""),
                        "sql": _SQL_QUERIES.get((tid, src_key), ""),
                    },
                    "sigma_logsource": src.get("sigma_logsource", ""),
                }
            )

    return json.dumps(
        {
            "hypotheses": hypotheses,
            "count": len(hypotheses),
            "techniques_covered": list({h["technique_id"] for h in hypotheses}),
            "techniques_not_in_playbook": missing,
            "note": (
                "Techniques not in playbook can be enriched via mitre-attack-mcp "
                "(get_datacomponents_detecting_technique, get_procedure_examples_by_technique)."
                if missing
                else ""
            ),
        },
        indent=2,
    )
