"""
KQL (Kusto Query Language) detection rule generator.

KQL is used by Azure Sentinel, Microsoft Defender, and other Microsoft security products.

Reference: https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class KQLRule:
    """
    KQL detection rule structure.

    Attributes:
        name: Rule name
        description: Rule description
        severity: Severity level (High, Medium, Low, Informational)
        query: KQL query
        tactics: MITRE ATT&CK tactics
        techniques: MITRE ATT&CK techniques
        query_frequency: How often to run the query
        query_period: Time range for the query
        trigger_threshold: Threshold for triggering alert
        suppression_duration: Alert suppression duration
        entity_mappings: Entity mappings for investigation
        custom_details: Custom details to include in alert
        alert_details_override: Override default alert details
    """

    name: str
    description: str
    severity: str
    query: str
    tactics: List[str]
    techniques: List[str]
    query_frequency: str = "5m"
    query_period: str = "5m"
    trigger_threshold: int = 0
    suppression_duration: str = "PT5H"
    entity_mappings: List[Dict[str, Any]] = field(default_factory=list)
    custom_details: Dict[str, str] = field(default_factory=dict)
    alert_details_override: Optional[Dict[str, str]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
            "query": self.query,
            "tactics": self.tactics,
            "techniques": self.techniques,
            "queryFrequency": self.query_frequency,
            "queryPeriod": self.query_period,
            "triggerThreshold": self.trigger_threshold,
            "suppressionDuration": self.suppression_duration,
            "entityMappings": self.entity_mappings,
            "customDetails": self.custom_details,
            "alertDetailsOverride": self.alert_details_override,
        }


class KQLGenerator:
    """
    KQL detection rule generator for Azure Sentinel.

    Generates KQL queries from threat intelligence and hunt plans.
    """

    def __init__(self):
        """Initialize KQL generator."""
        self.name = "KQL"

    def generate_from_technique(self, technique_id: str, technique_name: str) -> KQLRule:
        """
        Generate KQL rule from ATT&CK technique.

        Args:
            technique_id: ATT&CK technique ID
            technique_name: Technique name

        Returns:
            Generated KQL rule
        """
        if technique_id == "T1059.001":  # PowerShell
            return self._generate_powershell_rule()
        elif technique_id == "T1003.001":  # LSASS Memory
            return self._generate_lsass_rule()
        elif technique_id == "T1071.001":  # Web Protocols
            return self._generate_web_protocols_rule()
        else:
            return self._generate_generic_rule(technique_id, technique_name)

    def _generate_powershell_rule(self) -> KQLRule:
        """Generate KQL rule for PowerShell download cradles."""
        query = """DeviceProcessEvents
| where Timestamp > ago(5m)
| where FileName =~ "powershell.exe" or FileName =~ "pwsh.exe"
| where ProcessCommandLine has_any ("DownloadString", "DownloadFile", "Net.WebClient", "Invoke-WebRequest", "Invoke-RestMethod", "Start-BitsTransfer")
| where ProcessCommandLine !has "Windows\\\\System32" // Exclude system paths
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| extend HostName = DeviceName, Account = AccountName"""

        return KQLRule(
            name="Suspicious PowerShell Download Cradle",
            description="Detects PowerShell download cradles used to fetch and execute malicious payloads",
            severity="High",
            query=query,
            tactics=["Execution", "CommandAndControl"],
            techniques=["T1059.001", "T1071.001"],
            query_frequency="5m",
            query_period="5m",
            entity_mappings=[
                {
                    "entityType": "Host",
                    "fieldMappings": [{"identifier": "HostName", "columnName": "HostName"}],
                },
                {
                    "entityType": "Account",
                    "fieldMappings": [{"identifier": "Name", "columnName": "Account"}],
                },
            ],
            custom_details={
                "CommandLine": "ProcessCommandLine",
                "ParentProcess": "InitiatingProcessFileName",
            },
        )

    def _generate_lsass_rule(self) -> KQLRule:
        """Generate KQL rule for LSASS memory access."""
        query = """DeviceEvents
| where Timestamp > ago(5m)
| where ActionType == "ProcessAccessed"
| where FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in~ ("svchost.exe", "wininit.exe", "csrss.exe", "wmiprvse.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath
| extend HostName = DeviceName, Account = AccountName"""

        return KQLRule(
            name="LSASS Memory Access for Credential Dumping",
            description="Detects processes accessing LSASS memory for credential dumping",
            severity="Critical",
            query=query,
            tactics=["CredentialAccess"],
            techniques=["T1003.001"],
            query_frequency="5m",
            query_period="5m",
            entity_mappings=[
                {
                    "entityType": "Host",
                    "fieldMappings": [{"identifier": "HostName", "columnName": "HostName"}],
                },
                {
                    "entityType": "Account",
                    "fieldMappings": [{"identifier": "Name", "columnName": "Account"}],
                },
            ],
            custom_details={
                "AccessingProcess": "InitiatingProcessFileName",
                "ProcessPath": "InitiatingProcessFolderPath",
            },
        )

    def _generate_web_protocols_rule(self) -> KQLRule:
        """Generate KQL rule for suspicious web protocols."""
        query = """DeviceNetworkEvents
| where Timestamp > ago(5m)
| where InitiatingProcessFileName in~ ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe")
| where RemoteIPType == "Public"
| where RemotePort in (80, 443, 8080, 8443)
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl
| extend HostName = DeviceName, Account = AccountName"""

        return KQLRule(
            name="Suspicious Outbound Connection from Uncommon Process",
            description="Detects suspicious outbound connections from processes that typically don't make network connections",
            severity="Medium",
            query=query,
            tactics=["CommandAndControl"],
            techniques=["T1071.001"],
            query_frequency="5m",
            query_period="5m",
            entity_mappings=[
                {
                    "entityType": "Host",
                    "fieldMappings": [{"identifier": "HostName", "columnName": "HostName"}],
                },
                {
                    "entityType": "Account",
                    "fieldMappings": [{"identifier": "Name", "columnName": "Account"}],
                },
                {
                    "entityType": "IP",
                    "fieldMappings": [{"identifier": "Address", "columnName": "RemoteIP"}],
                },
            ],
            custom_details={
                "Process": "InitiatingProcessFileName",
                "RemoteIP": "RemoteIP",
                "RemotePort": "RemotePort",
            },
        )

    def _generate_generic_rule(self, technique_id: str, technique_name: str) -> KQLRule:
        """Generate generic KQL rule for unknown technique."""
        query = f"""DeviceProcessEvents
| where Timestamp > ago(5m)
| where ProcessCommandLine contains "{technique_name.lower()}"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| extend HostName = DeviceName, Account = AccountName"""

        return KQLRule(
            name=f"Suspicious Activity - {technique_name}",
            description=f"Detects suspicious activity related to {technique_name} ({technique_id})",
            severity="Medium",
            query=query,
            tactics=["Unknown"],
            techniques=[technique_id],
            query_frequency="5m",
            query_period="5m",
        )

    def generate_from_hunt_plan(
        self, hunt_plan: Dict[str, Any], techniques: List[str]
    ) -> List[KQLRule]:
        """
        Generate KQL rules from hunt plan.

        Args:
            hunt_plan: Hunt plan dictionary
            techniques: List of technique IDs

        Returns:
            List of generated KQL rules
        """
        rules = []

        for technique in techniques:
            technique_name = self._get_technique_name(technique)
            rule = self.generate_from_technique(technique, technique_name)
            rules.append(rule)

        return rules

    def _get_technique_name(self, technique_id: str) -> str:
        """Get technique name from ID (simplified)."""
        technique_names = {
            "T1059.001": "PowerShell",
            "T1003.001": "LSASS Memory",
            "T1071.001": "Web Protocols",
            "T1566.001": "Spearphishing Attachment",
        }
        return technique_names.get(technique_id, "Unknown Technique")
