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
                "kql":    'Event | where EventID == 4104 | where EventData has_any ("encodedcommand", "iex(", "downloadstring") | project TimeGenerated, Computer, EventData',
                "elastic": 'event.code:4104 AND winlog.event_data.ScriptBlockText:(*encodedcommand* OR *iex(* OR *downloadstring*)',
                "sigma_logsource": "windows/powershell/powershell_script",
            },
            "sysmon_process": {
                "name": "Sysmon Process Creation (Event ID 1)",
                "hypothesis": "PowerShell launched with suspicious flags (-enc, -w hidden, -nop) from unusual parent processes.",
                "splunk": 'index=sysmon EventCode=1 Image="*\\powershell.exe" | search CommandLine="-enc*" OR CommandLine="-w hidden*" OR CommandLine="-nop*" OR ParentImage="*\\winword.exe" OR ParentImage="*\\excel.exe" | table _time, ComputerName, ParentImage, CommandLine',
                "kql":    'SecurityEvent | where EventID == 4688 | where NewProcessName endswith "\\powershell.exe" | where CommandLine has_any ("-enc", "-w hidden", "-nop") or ParentProcessName has_any ("winword", "excel", "outlook")',
                "elastic": 'process.name:powershell.exe AND (process.command_line:*-enc* OR process.command_line:*-w hidden* OR process.parent.name:(winword.exe OR excel.exe))',
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
                "kql":    'SecurityEvent | where EventID == 4688 | where NewProcessName endswith "\\cmd.exe" | where CommandLine has "/c" and not ParentProcessName endswith "explorer.exe"',
                "elastic": 'process.name:cmd.exe AND process.command_line:*/c* AND NOT process.parent.name:explorer.exe',
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
                "kql":    'SecurityEvent | where EventID == 10 | where TargetImage endswith "\\lsass.exe" | where GrantedAccess in ("0x1010","0x1410","0x1438") | where not SourceImage has_any ("svchost","wininit","csrss")',
                "elastic": 'event.code:10 AND winlog.event_data.TargetImage:*lsass.exe AND NOT winlog.event_data.SourceImage:(svchost.exe OR wininit.exe)',
                "sigma_logsource": "windows/process_access",
            },
            "windows_defender": {
                "name": "Microsoft Defender / EDR Alerts",
                "hypothesis": "Credential dumping tool (mimikatz, procdump, comsvcs) detected by endpoint protection.",
                "splunk": 'index=defender (FileName="mimikatz*" OR FileName="procdump*" OR CommandLine="*comsvcs*MiniDump*") | table _time, ComputerName, FileName, CommandLine',
                "kql":    'DeviceProcessEvents | where FileName in~ ("mimikatz.exe","procdump.exe","procdump64.exe") or ProcessCommandLine has_all ("comsvcs","MiniDump")',
                "elastic": 'process.name:(mimikatz.exe OR procdump.exe) OR process.command_line:(*comsvcs* AND *MiniDump*)',
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
                "splunk": 'index=proxy | stats count, dc(url) as unique_urls, range(_time) as duration by src_ip, dest_host | where count > 20 AND unique_urls < 3 AND duration > 3600 | sort -count',
                "kql":    'CommonSecurityLog | where DeviceVendor == "Zscaler" or DeviceVendor == "Palo Alto Networks" | summarize RequestCount=count(), UniqueURLs=dcount(RequestURL), Duration=datetime_diff("second", max(TimeGenerated), min(TimeGenerated)) by SourceIP, DestinationHostName | where RequestCount > 20 and UniqueURLs < 3 and Duration > 3600',
                "elastic": 'network.protocol:http AND destination.port:(80 OR 443)',
                "sigma_logsource": "proxy",
            },
            "dns_logs": {
                "name": "DNS Query Logs",
                "hypothesis": "High-volume DNS queries to newly registered or low-reputation domains from workstations.",
                "splunk": 'index=dns query_type=A | stats count by src_ip, query | where count > 50 | lookup threat_intel_domains query OUTPUT reputation | where reputation="malicious"',
                "kql":    'DnsEvents | where QueryType == "A" | summarize count() by ClientIP, Name | where count_ > 50',
                "elastic": 'dns.question.type:A AND source.ip:*',
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
                "kql":    'DnsEvents | extend SubdomainLen=strlen(Name) | where SubdomainLen > 50 | summarize count() by ClientIP, Name | order by count_ desc',
                "elastic": 'dns.question.name:* AND NOT dns.question.name:*.microsoft.com',
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
                "kql":    'SecurityEvent | where EventID == 4698 | where EventData has_any ("\\Temp\\","\\AppData\\","encodedcommand") | project TimeGenerated, Computer, EventData',
                "elastic": 'event.code:4698 AND winlog.event_data.TaskContent:(*Temp* OR *AppData* OR *encodedcommand*)',
                "sigma_logsource": "windows/security",
            },
            "sysmon_process": {
                "name": "Sysmon Process Creation (Event ID 1)",
                "hypothesis": "schtasks.exe or at.exe used to create tasks pointing to suspicious paths.",
                "splunk": 'index=sysmon EventCode=1 (Image="*\\schtasks.exe" OR Image="*\\at.exe") CommandLine="*/create*" | table _time, ComputerName, CommandLine',
                "kql":    'SecurityEvent | where EventID == 4688 | where NewProcessName has_any ("schtasks","at.exe") | where CommandLine has "/create"',
                "elastic": 'process.name:(schtasks.exe OR at.exe) AND process.command_line:*/create*',
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
                "kql":    'Event | where EventID == 13 | where EventData has_any ("CurrentVersion\\Run","CurrentVersion\\RunOnce") | where not EventData has_any ("Program Files","Windows","Microsoft")',
                "elastic": 'event.code:13 AND registry.path:*CurrentVersion\\Run* AND NOT registry.data.strings:*Program Files*',
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
                "kql":    'Event | where EventID == 7045 | where EventData has_any ("\\Temp\\","powershell","cmd.exe","\\AppData\\") | project TimeGenerated, Computer, EventData',
                "elastic": 'event.code:7045 AND (winlog.event_data.ImagePath:*Temp* OR winlog.event_data.ImagePath:*powershell* OR winlog.event_data.ImagePath:*AppData*)',
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
                "kql":    'W3CIISLog | where csMethod == "POST" and (csUriStem endswith ".aspx" or csUriStem endswith ".php") | summarize count() by cIP, csUriStem',
                "elastic": r'http.request.method:POST AND url.path:(*\.aspx OR *\.php OR *\.jsp) AND NOT url.path:*(login|api)*',
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
                "kql":    'EmailAttachmentInfo | where FileType has_any (".xlsm",".docm",".xls",".zip") | join EmailEvents on NetworkMessageId | project TimeGenerated, SenderFromAddress, RecipientEmailAddress, FileName, Subject',
                "elastic": 'email.attachments.file.extension:(xlsm OR docm OR zip) AND email.from.address:*',
                "sigma_logsource": "application/email",
            },
            "sysmon_process": {
                "name": "Sysmon Process Creation (Event ID 1)",
                "hypothesis": "Office application (winword, excel) spawning child processes — classic macro execution chain.",
                "splunk": 'index=sysmon EventCode=1 (ParentImage="*\\winword.exe" OR ParentImage="*\\excel.exe" OR ParentImage="*\\outlook.exe") NOT (Image="*\\splwow64.exe") | table _time, ComputerName, ParentImage, Image, CommandLine',
                "kql":    'SecurityEvent | where EventID == 4688 | where ParentProcessName has_any ("winword","excel","outlook","powerpnt") | where not NewProcessName has "splwow64"',
                "elastic": 'process.parent.name:(WINWORD.EXE OR EXCEL.EXE OR OUTLOOK.EXE) AND NOT process.name:splwow64.exe',
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
                "splunk": 'index=wineventlog EventCode=4624 Logon_Type=10 | stats count by src_ip, Account_Name, ComputerName | where count > 1 | sort -count',
                "kql":    'SecurityEvent | where EventID == 4624 | where LogonType == 10 | summarize count() by IpAddress, Account, Computer | where count_ > 1',
                "elastic": 'event.code:4624 AND winlog.event_data.LogonType:10',
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
                "kql":    'SecurityEvent | where EventID == 4624 | where LogonType == 3 | where Account !endswith "$" | summarize HostCount=dcount(Computer) by Account, IpAddress | where HostCount > 3',
                "elastic": 'event.code:4624 AND winlog.event_data.LogonType:3 AND NOT winlog.event_data.SubjectUserName:*$',
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
                "kql":    'SigninLogs | where ResultType == 0 | where dayofweek(TimeGenerated) in (0,6) or hourofday(TimeGenerated) !between (7 .. 20) | project TimeGenerated, UserPrincipalName, IPAddress, Location',
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
                "splunk": 'index=wineventlog EventCode=4625 | stats dc(Account_Name) as distinct_users, count by src_ip | where distinct_users > 10 | sort -distinct_users',
                "kql":    'SecurityEvent | where EventID == 4625 | summarize DistinctUsers=dcount(Account), FailCount=count() by IpAddress | where DistinctUsers > 10 | order by DistinctUsers desc',
                "elastic": 'event.code:4625 | stats count by source.ip, user.name',
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
                "kql":    'Event | where EventID == 8 | where EventData has_any ("lsass.exe","explorer.exe","svchost.exe") | where not EventData has_any ("svchost.exe","csrss.exe") as SourceImage',
                "elastic": 'event.code:8 AND winlog.event_data.TargetImage:(lsass.exe OR explorer.exe OR svchost.exe)',
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
                "splunk": 'index=proxy cs_method=POST | eval mb=bytes/1024/1024 | where mb > 10 | stats sum(mb) as total_mb by src_ip, dest_host | sort -total_mb',
                "kql":    'CommonSecurityLog | where RequestMethod == "POST" and SentBytes > 10000000 | summarize TotalMB=sum(SentBytes)/1024/1024 by SourceIP, DestinationHostName | order by TotalMB desc',
                "elastic": 'network.protocol:http AND http.request.method:POST AND destination.bytes:>10000000',
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
                "kql":    'Event | where EventID == 4104 | where EventData has_any ("char(","concat(","[convert]::","-bxor")',
                "elastic": 'event.code:4104 AND winlog.event_data.ScriptBlockText:(*char(* OR *-bxor* OR *[convert]*)',
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
                "splunk": 'index=firewall action=deny | stats dc(dest_port) as ports, dc(dest_ip) as hosts by src_ip | where ports > 20 OR hosts > 20 | sort -ports',
                "kql":    'AzureNetworkAnalytics_CL | where FlowStatus_s == "D" | summarize DistinctPorts=dcount(DestPort_d), DistinctHosts=dcount(DestIP_s) by SrcIP_s | where DistinctPorts > 20 or DistinctHosts > 20',
                "elastic": 'network.direction:egress AND event.outcome:failure',
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
                "kql":    'DeviceFileEvents | where FileName endswith_cs ".encrypted" or FileName endswith_cs ".locked" or FileName has_any ("README","DECRYPT","RECOVER") | summarize count() by DeviceName, FileName | order by count_ desc',
                "elastic": 'event.code:11 AND (file.name:*decrypt* OR file.name:*ransom* OR file.extension:(encrypted OR locked OR crypt))',
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
                "kql":    'SecurityEvent | where EventID == 4769 | where TicketEncryptionType == "0x17" | where not AccountName endswith "$" | summarize count() by AccountName, ServiceName, IpAddress',
                "elastic": 'event.code:4769 AND winlog.event_data.TicketEncryptionType:0x17 AND NOT winlog.event_data.ServiceName:*$',
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
                "kql":    'W3CIISLog | where csUriQuery has_any ("select ","union ","../",";cmd","exec(") | project TimeGenerated, cIP, csUriStem, csUriQuery',
                "elastic": 'url.query:(*select* OR *union* OR *../* OR *exec(*)',
                "sigma_logsource": "webserver",
            },
        },
    },
}

# Canonical log source tags → friendly names
_LOG_SOURCE_LABELS: dict[str, str] = {
    "sysmon_process":          "Sysmon Process Creation (EID 1)",
    "sysmon_process_access":   "Sysmon Process Access (EID 10)",
    "sysmon_registry":         "Sysmon Registry Events (EID 13)",
    "sysmon_file":             "Sysmon File Events (EID 11)",
    "sysmon_create_remote_thread": "Sysmon CreateRemoteThread (EID 8)",
    "script_block_logging":    "PowerShell Script Block Logging (EID 4104)",
    "windows_event_4624":      "Windows Security - Successful Logon (EID 4624)",
    "windows_event_4625":      "Windows Security - Failed Logon (EID 4625)",
    "windows_event_4698":      "Windows Security - Scheduled Task Created (EID 4698)",
    "windows_event_4769":      "Windows Security - Kerberos Ticket (EID 4769)",
    "windows_event_7045":      "Windows System - New Service (EID 7045)",
    "windows_defender":        "Microsoft Defender / EDR",
    "proxy_logs":              "Web Proxy / Firewall HTTP Logs",
    "dns_logs":                "DNS Query Logs",
    "email_gateway":           "Email Gateway Logs",
    "web_server_logs":         "Web Server / WAF Logs",
    "firewall_logs":           "Firewall / Network Flow Logs",
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
        return json.dumps({
            "hypotheses": [],
            "note": "No ATT&CK techniques detected in the provided text. Try including technique names, tool names, or TTP keywords.",
        }, indent=2)

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

            hypotheses.append({
                "technique_id":   tid,
                "technique_name": entry["name"],
                "tactic":         entry["tactic"],
                "log_source_key": src_key,
                "log_source":     src["name"],
                "hypothesis":     src["hypothesis"],
                "queries": {
                    "splunk":  src.get("splunk", ""),
                    "kql":     src.get("kql", ""),
                    "elastic": src.get("elastic", ""),
                },
                "sigma_logsource": src.get("sigma_logsource", ""),
            })

    return json.dumps({
        "hypotheses": hypotheses,
        "count": len(hypotheses),
        "techniques_covered": list({h["technique_id"] for h in hypotheses}),
        "techniques_not_in_playbook": missing,
        "note": (
            "Techniques not in playbook can be enriched via mitre-attack-mcp "
            "(get_datacomponents_detecting_technique, get_procedure_examples_by_technique)."
            if missing else ""
        ),
    }, indent=2)
