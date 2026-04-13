"""Map ATT&CK techniques to specific log sources across cloud providers and platforms.

This module provides practical, actionable log source recommendations for threat hunting
and detection engineering based on ATT&CK techniques.
"""

from __future__ import annotations

from typing import Any, Dict, List

# Comprehensive technique → log source mappings
# Format: technique_id → platform → source → details
LOG_SOURCE_MAPPINGS: Dict[str, Dict[str, Any]] = {
    "T1059.001": {  # PowerShell
        "windows": {
            "event_logs": [
                {
                    "channel": "Microsoft-Windows-PowerShell/Operational",
                    "event_ids": [4104, 4103, 4105, 4106],
                    "priority": "critical",
                    "description": "PowerShell script block and module logging",
                    "configuration": "Enable via GPO: Administrative Templates → Windows PowerShell → Turn on Script Block Logging",
                },
                {
                    "channel": "Security",
                    "event_ids": [4688],
                    "priority": "critical",
                    "description": "Process creation with command line",
                    "configuration": "Enable command line logging in Audit Process Creation policy",
                },
            ],
            "sysmon": {
                "event_ids": [1],
                "priority": "high",
                "description": "Process creation with full command line and hashes",
            },
        },
        "aws": {
            "cloudtrail": {
                "services": ["SSM", "Lambda"],
                "events": ["SendCommand", "StartSession", "Invoke"],
                "priority": "high",
                "description": "PowerShell execution via Systems Manager or Lambda",
            },
            "cloudwatch_logs": {
                "log_groups": ["/aws/lambda/*", "/aws/ssm/*"],
                "priority": "medium",
                "description": "Function execution logs may contain PowerShell output",
            },
        },
        "azure": {
            "activity_logs": {
                "operations": [
                    "Microsoft.Compute/virtualMachines/runCommand/action",
                    "Microsoft.Automation/automationAccounts/jobs/write",
                ],
                "priority": "high",
                "description": "Azure Run Command and Automation Runbook execution",
            },
            "diagnostic_logs": {
                "categories": ["Administrative", "Security"],
                "priority": "medium",
            },
        },
        "gcp": {
            "cloud_logging": {
                "log_types": [
                    "compute.googleapis.com/activity",
                    "compute.googleapis.com/serial_port_output",
                ],
                "methods": ["compute.instances.setMetadata", "compute.instances.start"],
                "priority": "medium",
                "description": "VM metadata changes and startup scripts",
            },
        },
        "edr": {
            "vendors": {
                "crowdstrike": "ProcessRollup2",
                "defender": "DeviceProcessEvents",
                "carbon_black": "Process events",
                "sentinelone": "Deep Visibility",
            },
            "priority": "high",
        },
    },
    "T1566.001": {  # Phishing: Spearphishing Attachment
        "email_gateway": {
            "log_types": ["Message Tracking", "Attachment Analysis", "URL Analysis"],
            "vendors": {
                "proofpoint": "Message log with attachment disposition",
                "mimecast": "Attachment Protect logs",
                "microsoft_defender": "EmailEvents, EmailAttachmentInfo",
                "ironport": "Mail logs",
            },
            "priority": "critical",
            "description": "Email delivery, attachment analysis, and URL reputation",
        },
        "windows": {
            "event_logs": [
                {
                    "channel": "Security",
                    "event_ids": [4688],
                    "priority": "high",
                    "description": "Process creation from email client or attachment",
                }
            ],
            "sysmon": {
                "event_ids": [1, 11],
                "priority": "high",
                "description": "Process creation and file creation from attachments",
            },
        },
        "office365": {
            "logs": ["Exchange Online", "Defender for Office 365"],
            "tables": ["EmailEvents", "EmailAttachmentInfo", "EmailUrlInfo"],
            "priority": "critical",
            "description": "Email flow and attachment analysis in Microsoft 365",
        },
        "google_workspace": {
            "logs": ["Gmail logs", "Drive logs"],
            "log_types": ["gmail_log", "drive"],
            "priority": "high",
            "description": "Email delivery and attachment downloads",
        },
    },
    "T1053.005": {  # Scheduled Task/Job: Scheduled Task
        "windows": {
            "event_logs": [
                {
                    "channel": "Microsoft-Windows-TaskScheduler/Operational",
                    "event_ids": [106, 140, 141, 200, 201],
                    "priority": "critical",
                    "description": "Scheduled task creation, modification, and execution",
                },
                {
                    "channel": "Security",
                    "event_ids": [4698, 4699, 4700, 4701, 4702],
                    "priority": "high",
                    "description": "Scheduled task security events",
                },
            ],
            "sysmon": {
                "event_ids": [1],
                "priority": "high",
                "description": "Process creation from taskeng.exe or svchost.exe (Task Scheduler)",
            },
        },
        "aws": {
            "cloudwatch_events": {
                "services": ["EventBridge", "CloudWatch Events"],
                "priority": "medium",
                "description": "Scheduled Lambda or ECS task execution",
            },
        },
        "azure": {
            "activity_logs": {
                "operations": ["Microsoft.Automation/automationAccounts/jobs/write"],
                "priority": "medium",
                "description": "Scheduled Automation Runbooks",
            },
        },
        "gcp": {
            "cloud_scheduler": {
                "log_types": ["cloudscheduler.googleapis.com/execution"],
                "priority": "medium",
                "description": "Cloud Scheduler job execution",
            },
        },
    },
    "T1105": {  # Ingress Tool Transfer
        "network": {
            "firewall": {
                "log_types": ["Connection logs", "URL filtering"],
                "priority": "high",
                "description": "Outbound connections to suspicious domains/IPs",
            },
            "proxy": {
                "log_types": ["Web proxy logs", "SSL inspection"],
                "priority": "high",
                "description": "HTTP/HTTPS downloads",
            },
            "zeek": {
                "logs": ["conn.log", "http.log", "files.log"],
                "priority": "high",
                "description": "Network connections and file transfers",
            },
        },
        "windows": {
            "sysmon": {
                "event_ids": [3, 22],
                "priority": "high",
                "description": "Network connections and DNS queries",
            },
        },
        "aws": {
            "vpc_flow_logs": {
                "priority": "medium",
                "description": "Network traffic between instances",
            },
            "cloudtrail": {
                "services": ["S3"],
                "events": ["GetObject", "PutObject"],
                "priority": "medium",
                "description": "S3 downloads by compromised instances",
            },
        },
        "azure": {
            "nsg_flow_logs": {
                "priority": "medium",
                "description": "Network Security Group traffic logs",
            },
        },
        "gcp": {
            "vpc_flow_logs": {
                "priority": "medium",
                "description": "VPC network traffic",
            },
        },
    },
    "T1003.001": {  # OS Credential Dumping: LSASS Memory
        "windows": {
            "event_logs": [
                {
                    "channel": "Security",
                    "event_ids": [4656, 4663],
                    "priority": "critical",
                    "description": "LSASS process access attempts",
                }
            ],
            "sysmon": {
                "event_ids": [10],
                "priority": "critical",
                "description": "Process access to lsass.exe",
            },
        },
        "edr": {
            "vendors": {
                "crowdstrike": "ProcessRollup2, SuspiciousProcessAccess",
                "defender": "DeviceEvents (LSASS access)",
                "carbon_black": "Process access events",
            },
            "priority": "critical",
            "description": "EDR-specific LSASS protection alerts",
        },
    },
    "T1021.001": {  # Remote Services: Remote Desktop Protocol
        "windows": {
            "event_logs": [
                {
                    "channel": "Security",
                    "event_ids": [4624, 4625, 4634, 4647, 4778, 4779],
                    "priority": "critical",
                    "description": "Logon events (Type 10 = RemoteInteractive)",
                },
                {
                    "channel": "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
                    "event_ids": [21, 22, 23, 24, 25],
                    "priority": "high",
                    "description": "RDP session events",
                },
            ],
        },
        "network": {
            "firewall": {
                "ports": [3389],
                "priority": "high",
                "description": "RDP traffic (TCP 3389)",
            },
        },
        "aws": {
            "vpc_flow_logs": {
                "ports": [3389],
                "priority": "medium",
                "description": "RDP connections to EC2 instances",
            },
        },
        "azure": {
            "nsg_flow_logs": {
                "ports": [3389],
                "priority": "medium",
                "description": "RDP connections to Azure VMs",
            },
            "sign_in_logs": {
                "priority": "high",
                "description": "Azure AD authentication for RDP",
            },
        },
        "gcp": {
            "vpc_flow_logs": {
                "ports": [3389],
                "priority": "medium",
                "description": "RDP connections to GCE instances",
            },
        },
    },
    "T1078": {  # Valid Accounts
        "windows": {
            "event_logs": [
                {
                    "channel": "Security",
                    "event_ids": [4624, 4625, 4648, 4672],
                    "priority": "critical",
                    "description": "Account logon and privilege use",
                }
            ],
        },
        "aws": {
            "cloudtrail": {
                "services": ["IAM", "STS"],
                "events": ["AssumeRole", "GetSessionToken", "ConsoleLogin"],
                "priority": "critical",
                "description": "AWS account authentication and role assumption",
            },
        },
        "azure": {
            "sign_in_logs": {
                "priority": "critical",
                "description": "Azure AD sign-in events",
            },
            "activity_logs": {
                "operations": ["Microsoft.Authorization/roleAssignments/write"],
                "priority": "high",
                "description": "Role assignments and privilege changes",
            },
        },
        "gcp": {
            "cloud_logging": {
                "log_types": ["cloudaudit.googleapis.com/activity"],
                "methods": ["google.iam.admin.v1.CreateServiceAccountKey"],
                "priority": "critical",
                "description": "GCP authentication and service account activity",
            },
        },
        "office365": {
            "logs": ["Unified Audit Log"],
            "operations": ["UserLoggedIn", "UserLoginFailed"],
            "priority": "critical",
        },
    },
    "T1071.001": {  # Application Layer Protocol: Web Protocols
        "network": {
            "proxy": {
                "log_types": ["HTTP/HTTPS traffic"],
                "priority": "high",
                "description": "Web proxy logs for C2 communication",
            },
            "firewall": {
                "ports": [80, 443, 8080, 8443],
                "priority": "high",
                "description": "Outbound web traffic",
            },
        },
        "aws": {
            "vpc_flow_logs": {
                "ports": [80, 443],
                "priority": "medium",
                "description": "HTTP/HTTPS connections from instances",
            },
            "alb_logs": {
                "priority": "medium",
                "description": "Application Load Balancer access logs",
            },
        },
        "azure": {
            "nsg_flow_logs": {
                "ports": [80, 443],
                "priority": "medium",
            },
            "application_gateway_logs": {
                "priority": "medium",
                "description": "Application Gateway access logs",
            },
        },
        "gcp": {
            "vpc_flow_logs": {
                "ports": [80, 443],
                "priority": "medium",
            },
            "load_balancer_logs": {
                "priority": "medium",
                "description": "Cloud Load Balancing logs",
            },
        },
    },
    "T1547.001": {  # Boot or Logon Autostart Execution: Registry Run Keys
        "windows": {
            "event_logs": [
                {
                    "channel": "Security",
                    "event_ids": [4657],
                    "priority": "high",
                    "description": "Registry value modifications",
                }
            ],
            "sysmon": {
                "event_ids": [12, 13, 14],
                "priority": "critical",
                "description": "Registry events (create, set, rename)",
            },
        },
        "edr": {
            "vendors": {
                "crowdstrike": "RegSetValue events",
                "defender": "DeviceRegistryEvents",
                "carbon_black": "Registry modification events",
            },
            "priority": "high",
        },
    },
    "T1543.003": {  # Create or Modify System Process: Windows Service
        "windows": {
            "event_logs": [
                {
                    "channel": "System",
                    "event_ids": [7045, 7040, 7036],
                    "priority": "critical",
                    "description": "Service installation and state changes",
                },
                {
                    "channel": "Security",
                    "event_ids": [4697],
                    "priority": "critical",
                    "description": "Service installation",
                },
            ],
            "sysmon": {
                "event_ids": [1],
                "priority": "high",
                "description": "services.exe child processes",
            },
        },
    },
    "T1569.002": {  # System Services: Service Execution
        "windows": {
            "event_logs": [
                {
                    "channel": "Security",
                    "event_ids": [4688],
                    "priority": "high",
                    "description": "Process creation from services.exe",
                },
                {
                    "channel": "System",
                    "event_ids": [7036, 7040],
                    "priority": "medium",
                    "description": "Service start/stop events",
                },
            ],
        },
        "aws": {
            "ecs_logs": {
                "priority": "medium",
                "description": "ECS task execution logs",
            },
        },
        "azure": {
            "container_logs": {
                "priority": "medium",
                "description": "Azure Container Instances logs",
            },
        },
        "gcp": {
            "cloud_run_logs": {
                "priority": "medium",
                "description": "Cloud Run service execution",
            },
        },
    },
    "T1070.001": {  # Indicator Removal: Clear Windows Event Logs
        "windows": {
            "event_logs": [
                {
                    "channel": "Security",
                    "event_ids": [1102, 1100],
                    "priority": "critical",
                    "description": "Audit log cleared, Event logging service shutdown",
                },
                {
                    "channel": "System",
                    "event_ids": [104],
                    "priority": "critical",
                    "description": "Event log cleared",
                },
            ],
            "sysmon": {
                "event_ids": [1],
                "priority": "high",
                "description": "wevtutil.exe or Clear-EventLog execution",
            },
        },
        "aws": {
            "cloudtrail": {
                "services": ["CloudTrail"],
                "events": ["StopLogging", "DeleteTrail", "UpdateTrail"],
                "priority": "critical",
                "description": "CloudTrail tampering",
            },
        },
        "azure": {
            "activity_logs": {
                "operations": ["Microsoft.Insights/DiagnosticSettings/Delete"],
                "priority": "critical",
                "description": "Diagnostic settings deletion",
            },
        },
        "gcp": {
            "cloud_logging": {
                "methods": ["logging.sinks.delete", "logging.sinks.update"],
                "priority": "critical",
                "description": "Log sink tampering",
            },
        },
    },
    "T1136.001": {  # Create Account: Local Account
        "windows": {
            "event_logs": [
                {
                    "channel": "Security",
                    "event_ids": [4720, 4722, 4724, 4738],
                    "priority": "critical",
                    "description": "User account creation and modification",
                }
            ],
        },
        "linux": {
            "syslog": {
                "facilities": ["auth", "authpriv"],
                "priority": "critical",
                "description": "useradd, usermod commands",
            },
            "auditd": {
                "rules": ["-w /etc/passwd -p wa", "-w /etc/shadow -p wa"],
                "priority": "critical",
            },
        },
        "aws": {
            "cloudtrail": {
                "services": ["IAM"],
                "events": ["CreateUser", "CreateAccessKey", "AttachUserPolicy"],
                "priority": "critical",
                "description": "IAM user creation",
            },
        },
        "azure": {
            "activity_logs": {
                "operations": ["Microsoft.Authorization/roleAssignments/write"],
                "priority": "critical",
            },
            "sign_in_logs": {
                "priority": "high",
                "description": "First-time sign-ins for new accounts",
            },
        },
        "gcp": {
            "cloud_logging": {
                "methods": ["google.iam.admin.v1.CreateServiceAccount"],
                "priority": "critical",
                "description": "Service account creation",
            },
        },
    },
    "T1098": {  # Account Manipulation
        "windows": {
            "event_logs": [
                {
                    "channel": "Security",
                    "event_ids": [4738, 4728, 4732, 4756],
                    "priority": "critical",
                    "description": "Account changes and group membership modifications",
                }
            ],
        },
        "aws": {
            "cloudtrail": {
                "services": ["IAM"],
                "events": [
                    "AttachUserPolicy",
                    "PutUserPolicy",
                    "AddUserToGroup",
                    "UpdateAccessKey",
                ],
                "priority": "critical",
                "description": "IAM permission changes",
            },
        },
        "azure": {
            "activity_logs": {
                "operations": [
                    "Microsoft.Authorization/roleAssignments/write",
                    "Microsoft.Authorization/roleDefinitions/write",
                ],
                "priority": "critical",
                "description": "RBAC role assignments",
            },
            "audit_logs": {
                "operations": ["Add member to role", "Update user"],
                "priority": "critical",
            },
        },
        "gcp": {
            "cloud_logging": {
                "methods": [
                    "SetIamPolicy",
                    "google.iam.admin.v1.UpdateServiceAccount",
                ],
                "priority": "critical",
                "description": "IAM policy changes",
            },
        },
    },
    "T1190": {  # Exploit Public-Facing Application
        "network": {
            "waf": {
                "log_types": ["WAF logs", "ModSecurity logs"],
                "priority": "critical",
                "description": "Web application firewall alerts",
            },
            "ids_ips": {
                "log_types": ["Snort", "Suricata", "Zeek"],
                "priority": "high",
                "description": "Network intrusion detection",
            },
        },
        "aws": {
            "waf_logs": {
                "priority": "critical",
                "description": "AWS WAF logs for ALB/CloudFront",
            },
            "alb_logs": {
                "priority": "high",
                "description": "Application Load Balancer access logs",
            },
            "cloudfront_logs": {
                "priority": "high",
                "description": "CloudFront distribution logs",
            },
        },
        "azure": {
            "application_gateway_logs": {
                "priority": "critical",
                "description": "Application Gateway WAF logs",
            },
            "front_door_logs": {
                "priority": "high",
                "description": "Azure Front Door logs",
            },
        },
        "gcp": {
            "cloud_armor_logs": {
                "priority": "critical",
                "description": "Cloud Armor security policy logs",
            },
            "load_balancer_logs": {
                "priority": "high",
                "description": "HTTP(S) Load Balancer logs",
            },
        },
        "application": {
            "web_server": {
                "log_types": ["Apache access/error", "Nginx access/error", "IIS logs"],
                "priority": "high",
                "description": "Web server access and error logs",
            },
        },
    },
    "T1486": {  # Data Encrypted for Impact (Ransomware)
        "windows": {
            "event_logs": [
                {
                    "channel": "Security",
                    "event_ids": [4663, 5145],
                    "priority": "high",
                    "description": "File access and SMB share access",
                }
            ],
            "sysmon": {
                "event_ids": [11, 23],
                "priority": "critical",
                "description": "File creation and file deletion (mass file operations)",
            },
        },
        "edr": {
            "vendors": {
                "crowdstrike": "RansomwareIndicators",
                "defender": "DeviceFileEvents (mass file modifications)",
                "carbon_black": "File modification events",
            },
            "priority": "critical",
        },
        "aws": {
            "cloudtrail": {
                "services": ["S3", "EBS"],
                "events": ["DeleteObject", "DeleteVolume", "CreateSnapshot"],
                "priority": "high",
                "description": "Mass S3 deletions or EBS snapshot creation",
            },
        },
        "azure": {
            "activity_logs": {
                "operations": [
                    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete"
                ],
                "priority": "high",
                "description": "Mass blob deletions",
            },
        },
        "gcp": {
            "cloud_logging": {
                "methods": ["storage.objects.delete", "compute.disks.createSnapshot"],
                "priority": "high",
                "description": "Mass object deletions or disk snapshots",
            },
        },
    },
    "T1562.001": {  # Impair Defenses: Disable or Modify Tools
        "windows": {
            "event_logs": [
                {
                    "channel": "Security",
                    "event_ids": [4688, 4657],
                    "priority": "critical",
                    "description": "Process creation and registry modifications for security tools",
                }
            ],
            "sysmon": {
                "event_ids": [1, 13],
                "priority": "critical",
                "description": "Security tool process termination and registry changes",
            },
        },
        "aws": {
            "cloudtrail": {
                "services": ["GuardDuty", "SecurityHub", "Config"],
                "events": ["StopMonitoringMembers", "DisableSecurityHub", "DeleteConfigRule"],
                "priority": "critical",
                "description": "Security service tampering",
            },
        },
        "azure": {
            "activity_logs": {
                "operations": [
                    "Microsoft.Security/securityContacts/delete",
                    "Microsoft.Security/autoProvisioningSettings/write",
                ],
                "priority": "critical",
                "description": "Security Center configuration changes",
            },
        },
        "gcp": {
            "cloud_logging": {
                "methods": ["securitycenter.sources.setIamPolicy"],
                "priority": "critical",
                "description": "Security Command Center tampering",
            },
        },
    },
    "T1110.003": {  # Brute Force: Password Spraying
        "windows": {
            "event_logs": [
                {
                    "channel": "Security",
                    "event_ids": [4625, 4771, 4776],
                    "priority": "critical",
                    "description": "Failed authentication attempts",
                }
            ],
        },
        "aws": {
            "cloudtrail": {
                "services": ["IAM"],
                "events": ["ConsoleLogin"],
                "priority": "critical",
                "description": "Failed console login attempts",
            },
        },
        "azure": {
            "sign_in_logs": {
                "priority": "critical",
                "description": "Failed sign-in attempts across multiple accounts",
            },
        },
        "gcp": {
            "cloud_logging": {
                "log_types": ["cloudaudit.googleapis.com/activity"],
                "methods": ["google.login"],
                "priority": "critical",
                "description": "Failed authentication attempts",
            },
        },
        "office365": {
            "logs": ["Unified Audit Log"],
            "operations": ["UserLoginFailed"],
            "priority": "critical",
        },
    },
    "T1567.002": {  # Exfiltration Over Web Service: Exfiltration to Cloud Storage
        "network": {
            "proxy": {
                "domains": [
                    "*.amazonaws.com",
                    "*.blob.core.windows.net",
                    "*.storage.googleapis.com",
                ],
                "priority": "critical",
                "description": "Uploads to cloud storage services",
            },
            "firewall": {
                "priority": "high",
                "description": "Large outbound transfers to cloud IPs",
            },
        },
        "aws": {
            "cloudtrail": {
                "services": ["S3"],
                "events": ["PutObject", "CompleteMultipartUpload"],
                "priority": "critical",
                "description": "Unusual S3 uploads from compromised instances",
            },
            "vpc_flow_logs": {
                "priority": "medium",
                "description": "Large data transfers to S3 endpoints",
            },
        },
        "azure": {
            "storage_logs": {
                "operations": ["PutBlob", "PutBlock"],
                "priority": "critical",
                "description": "Blob storage uploads",
            },
        },
        "gcp": {
            "cloud_logging": {
                "methods": ["storage.objects.create"],
                "priority": "critical",
                "description": "Cloud Storage object creation",
            },
        },
    },
}


def get_log_sources_for_techniques(
    technique_ids: List[str], environment: str = "hybrid"
) -> Dict[str, Any]:
    """
    Get specific log source recommendations for given ATT&CK techniques.

    Args:
        technique_ids: List of ATT&CK technique IDs (e.g., ["T1059.001", "T1566.001"])
        environment: Target environment (aws, azure, gcp, on-prem, hybrid)

    Returns:
        Dictionary with prioritized log sources, specific event IDs, and configuration guidance
    """
    results: Dict[str, Any] = {
        "techniques": technique_ids,
        "log_sources": {},
        "priority_summary": {"critical": [], "high": [], "medium": []},
        "configuration_needed": [],
        "blind_spots": [],
    }

    platforms_seen: Dict[str, Dict] = {}

    for tid in technique_ids:
        tid_clean = tid.strip().upper()
        if tid_clean not in LOG_SOURCE_MAPPINGS:
            results["blind_spots"].append(
                f"{tid_clean} - No specific log source mappings available"
            )
            continue

        mapping = LOG_SOURCE_MAPPINGS[tid_clean]

        # Aggregate by platform
        for platform, sources in mapping.items():
            # Filter by environment
            if environment != "hybrid":
                if environment == "aws" and platform not in ["aws", "network", "edr"]:
                    continue
                if environment == "azure" and platform not in ["azure", "network", "edr"]:
                    continue
                if environment == "gcp" and platform not in ["gcp", "network", "edr"]:
                    continue
                if environment == "on-prem" and platform in ["aws", "azure", "gcp"]:
                    continue

            if platform not in platforms_seen:
                platforms_seen[platform] = {}

            # Merge sources
            for source_key, source_data in sources.items():
                if source_key not in platforms_seen[platform]:
                    platforms_seen[platform][source_key] = {
                        "techniques": [tid_clean],
                        "details": source_data,
                    }
                else:
                    if tid_clean not in platforms_seen[platform][source_key]["techniques"]:
                        platforms_seen[platform][source_key]["techniques"].append(tid_clean)

    results["log_sources"] = platforms_seen

    # Build priority summary
    for platform, sources in platforms_seen.items():
        for source_name, source_info in sources.items():
            details = source_info["details"]
            priority = details.get("priority", "medium") if isinstance(details, dict) else "medium"

            entry = {
                "platform": platform,
                "source": source_name,
                "techniques": source_info["techniques"],
            }

            if priority == "critical":
                results["priority_summary"]["critical"].append(entry)
            elif priority == "high":
                results["priority_summary"]["high"].append(entry)
            else:
                results["priority_summary"]["medium"].append(entry)

    return results
