"""
Sigma detection rule generator.

Sigma is a generic signature format for SIEM systems that can be converted
to various target formats (Splunk, Elastic, QRadar, etc.).

Reference: https://github.com/SigmaHQ/sigma
"""

import uuid
import yaml
from typing import Dict, List, Any, Optional
from datetime import datetime
from dataclasses import dataclass, field

# Deterministic UUID namespace for all rules — same input → same rule ID
_RULE_NS = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")  # uuid.NAMESPACE_URL


def _rule_uuid(technique_id: str, variant: str = "") -> str:
    """Stable UUID derived from technique + variant; survives git round-trips."""
    return str(uuid.uuid5(_RULE_NS, f"threat-research-mcp/{technique_id}/{variant}"))


@dataclass
class SigmaRule:
    """
    Sigma rule structure.

    Attributes:
        title: Rule title
        id: Unique rule ID (UUID)
        status: Rule status (experimental, testing, stable)
        description: Rule description
        author: Rule author
        date: Creation date
        modified: Last modified date
        tags: Rule tags
        logsource: Log source specification
        detection: Detection logic
        falsepositives: Known false positives
        level: Severity level
        references: External references
    """

    title: str
    id: str
    status: str
    description: str
    author: str
    date: str
    logsource: Dict[str, str]
    detection: Dict[str, Any]
    level: str
    modified: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    falsepositives: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        rule = {
            "title": self.title,
            "id": self.id,
            "status": self.status,
            "description": self.description,
            "author": self.author,
            "date": self.date,
            "logsource": self.logsource,
            "detection": self.detection,
            "level": self.level,
        }

        if self.modified:
            rule["modified"] = self.modified
        if self.tags:
            rule["tags"] = self.tags
        if self.falsepositives:
            rule["falsepositives"] = self.falsepositives
        if self.references:
            rule["references"] = self.references

        return rule

    def to_yaml(self) -> str:
        """Convert to YAML format."""
        return yaml.dump(self.to_dict(), default_flow_style=False, sort_keys=False)


class SigmaGenerator:
    """
    Sigma detection rule generator.

    Generates Sigma rules from threat intelligence and hunt plans.
    """

    def __init__(self):
        """Initialize Sigma generator."""
        self.name = "Sigma"

    def generate_from_technique(
        self, technique_id: str, technique_name: str, environment: str = "windows"
    ) -> Optional[SigmaRule]:
        """
        Generate Sigma rule from ATT&CK technique.

        Args:
            technique_id: ATT&CK technique ID
            technique_name: Technique name
            environment: Environment type

        Returns:
            Generated Sigma rule
        """

        # Return a hand-written rule or None — never a generic stub
        if technique_id == "T1059.001":
            return self._generate_powershell_rule()
        elif technique_id == "T1003.001":
            return self._generate_lsass_rule()
        elif technique_id == "T1071.001":
            return self._generate_web_protocols_rule()
        return None  # caller must handle missing rule rather than generating garbage

    def _generate_powershell_rule(self) -> SigmaRule:
        return SigmaRule(
            title="Suspicious PowerShell Download Cradle",
            id=_rule_uuid("T1059.001", "download-cradle"),
            status="experimental",
            description="Detects PowerShell download cradles used to fetch and execute malicious payloads",
            author="Threat Research MCP",
            date=datetime.now().strftime("%Y-%m-%d"),
            tags=[
                "attack.execution",
                "attack.t1059.001",
                "attack.command_and_control",
                "attack.t1071.001",
            ],
            logsource={
                "product": "windows",
                "category": "process_creation",
            },
            detection={
                "selection": {
                    "Image|endswith": "\\powershell.exe",
                    "CommandLine|contains": [
                        "DownloadString",
                        "DownloadFile",
                        "Net.WebClient",
                        "Invoke-WebRequest",
                        "Invoke-RestMethod",
                        "Start-BitsTransfer",
                    ],
                },
                "condition": "selection",
            },
            falsepositives=[
                "Legitimate software update mechanisms",
                "Administrative scripts",
            ],
            level="high",
            references=[
                "https://attack.mitre.org/techniques/T1059/001/",
            ],
        )

    def _generate_lsass_rule(self) -> SigmaRule:
        return SigmaRule(
            title="LSASS Memory Access for Credential Dumping",
            id=_rule_uuid("T1003.001", "process-access"),
            status="experimental",
            description="Detects processes accessing LSASS memory for credential dumping",
            author="Threat Research MCP",
            date=datetime.now().strftime("%Y-%m-%d"),
            tags=[
                "attack.credential_access",
                "attack.t1003.001",
            ],
            logsource={
                "product": "windows",
                "category": "process_access",
            },
            detection={
                "selection": {
                    "TargetImage|endswith": "\\lsass.exe",
                    "GrantedAccess": ["0x1010", "0x1410", "0x1438"],
                },
                "filter": {
                    "SourceImage|endswith": [
                        "\\svchost.exe",
                        "\\wininit.exe",
                        "\\csrss.exe",
                    ],
                },
                "condition": "selection and not filter",
            },
            falsepositives=[
                "Legitimate security tools",
                "Backup software",
            ],
            level="critical",
            references=[
                "https://attack.mitre.org/techniques/T1003/001/",
            ],
        )

    def _generate_web_protocols_rule(self) -> SigmaRule:
        return SigmaRule(
            title="Suspicious Outbound Connection from Uncommon Process",
            id=_rule_uuid("T1071.001", "network-connection"),
            status="experimental",
            description="Detects suspicious outbound connections from processes that typically don't make network connections",
            author="Threat Research MCP",
            date=datetime.now().strftime("%Y-%m-%d"),
            tags=[
                "attack.command_and_control",
                "attack.t1071.001",
            ],
            logsource={
                "product": "windows",
                "category": "network_connection",
            },
            detection={
                "selection": {
                    "Image|endswith": [
                        "\\powershell.exe",
                        "\\cmd.exe",
                        "\\wscript.exe",
                        "\\cscript.exe",
                        "\\mshta.exe",
                        "\\regsvr32.exe",
                        "\\rundll32.exe",
                    ],
                    "Initiated": "true",
                },
                "filter": {
                    "DestinationIp|startswith": [
                        "10.",
                        "192.168.",
                        "172.16.",
                        "172.17.",
                        "172.18.",
                        "172.19.",
                        "172.20.",
                        "172.21.",
                        "172.22.",
                        "172.23.",
                        "172.24.",
                        "172.25.",
                        "172.26.",
                        "172.27.",
                        "172.28.",
                        "172.29.",
                        "172.30.",
                        "172.31.",
                    ],
                },
                "condition": "selection and not filter",
            },
            falsepositives=[
                "Legitimate administrative scripts",
                "Software update mechanisms",
            ],
            level="medium",
            references=[
                "https://attack.mitre.org/techniques/T1071/001/",
            ],
        )

    def generate_from_hunt_plan(
        self, hunt_plan: Dict[str, Any], techniques: List[str]
    ) -> List[SigmaRule]:
        """
        Generate Sigma rules from hunt plan.

        Args:
            hunt_plan: Hunt plan dictionary
            techniques: List of technique IDs

        Returns:
            List of generated Sigma rules
        """
        rules = []

        for technique in techniques:
            # Extract technique name (simplified)
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
