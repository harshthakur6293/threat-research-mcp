"""
HEARTH (Hunt Event Artifact Repository for Threat Hunting) integration.

HEARTH is a community-driven repository for sharing threat hunting hypotheses,
methodologies, and findings. This module provides integration with HEARTH-like
community hunt repositories.

Reference: https://github.com/ThreatHuntingProject/ThreatHunting
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class CommunityHunt:
    """
    Community hunt structure.

    Attributes:
        id: Unique hunt identifier
        name: Hunt name
        description: Hunt description
        hypothesis: Hunt hypothesis
        techniques: ATT&CK techniques targeted
        data_sources: Required data sources
        queries: Hunt queries by platform
        author: Hunt author
        created_date: Creation date
        tags: Hunt tags
        references: External references
        metadata: Additional metadata
    """

    id: str
    name: str
    description: str
    hypothesis: str
    techniques: List[str]
    data_sources: List[str]
    queries: Dict[str, List[str]]
    author: str = "Unknown"
    created_date: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "hypothesis": self.hypothesis,
            "techniques": self.techniques,
            "data_sources": self.data_sources,
            "queries": self.queries,
            "author": self.author,
            "created_date": self.created_date,
            "tags": self.tags,
            "references": self.references,
            "metadata": self.metadata,
        }


class HEARTHIntegration:
    """
    HEARTH integration for community threat hunting.

    This class provides methods to:
    - Search community hunts by technique
    - Contribute new hunts to the community
    - Adapt community hunts to local environment
    """

    def __init__(self):
        """Initialize HEARTH integration."""
        self.name = "HEARTH"
        self.community_hunts = self._load_community_hunts()

    def _load_community_hunts(self) -> List[CommunityHunt]:
        """
        Load community hunts from repository.

        In production, this would fetch from a real HEARTH repository.
        For now, we'll use a mock set of community hunts.
        """
        return [
            CommunityHunt(
                id="hunt-001",
                name="PowerShell Download Cradle Detection",
                description="Hunt for PowerShell download cradles used for initial access",
                hypothesis="Adversaries use PowerShell download cradles to fetch and execute malicious payloads",
                techniques=["T1059.001", "T1071.001"],
                data_sources=["Windows Event Logs", "Sysmon", "PowerShell Logs"],
                queries={
                    "splunk": [
                        'index=windows EventCode=4688 Image="*powershell.exe" CommandLine="*DownloadString*" OR CommandLine="*DownloadFile*"',
                        'index=windows EventCode=4104 ScriptBlockText="*Net.WebClient*" OR ScriptBlockText="*Invoke-WebRequest*"',
                    ],
                    "sentinel": [
                        'DeviceProcessEvents | where FileName =~ "powershell.exe" and ProcessCommandLine has_any ("DownloadString", "DownloadFile", "Net.WebClient")',
                    ],
                },
                author="Community",
                created_date="2024-01-15",
                tags=["powershell", "download-cradle", "initial-access"],
                references=[
                    "https://attack.mitre.org/techniques/T1059/001/",
                    "https://www.fireeye.com/blog/threat-research/2017/06/obfuscation-in-the-wild.html",
                ],
            ),
            CommunityHunt(
                id="hunt-002",
                name="Suspicious Parent-Child Process Relationships",
                description="Hunt for unusual parent-child process relationships indicating process injection",
                hypothesis="Adversaries spawn suspicious processes from unexpected parents to evade detection",
                techniques=["T1055", "T1059.001"],
                data_sources=["Windows Event Logs", "Sysmon", "EDR"],
                queries={
                    "splunk": [
                        'index=windows EventCode=1 ParentImage="*\\\\outlook.exe" Image!="*\\\\outlook.exe"',
                        'index=windows EventCode=1 ParentImage="*\\\\excel.exe" Image="*\\\\powershell.exe" OR Image="*\\\\cmd.exe"',
                    ],
                    "sentinel": [
                        'DeviceProcessEvents | where InitiatingProcessFileName in~ ("outlook.exe", "excel.exe", "winword.exe") and FileName in~ ("powershell.exe", "cmd.exe", "wscript.exe")',
                    ],
                },
                author="Community",
                created_date="2024-02-01",
                tags=["process-injection", "parent-child", "suspicious-execution"],
                references=[
                    "https://attack.mitre.org/techniques/T1055/",
                ],
            ),
            CommunityHunt(
                id="hunt-003",
                name="LSASS Memory Access Detection",
                description="Hunt for processes accessing LSASS memory for credential dumping",
                hypothesis="Adversaries access LSASS memory to extract credentials",
                techniques=["T1003.001"],
                data_sources=["Sysmon", "EDR"],
                queries={
                    "splunk": [
                        'index=windows EventCode=10 TargetImage="*\\\\lsass.exe" GrantedAccess="0x1010" OR GrantedAccess="0x1410"',
                    ],
                    "sentinel": [
                        'DeviceEvents | where ActionType == "ProcessAccessed" and FileName =~ "lsass.exe"',
                    ],
                },
                author="Community",
                created_date="2024-01-20",
                tags=["credential-dumping", "lsass", "mimikatz"],
                references=[
                    "https://attack.mitre.org/techniques/T1003/001/",
                ],
            ),
        ]

    def search_by_technique(self, technique_id: str) -> List[CommunityHunt]:
        """
        Search community hunts by ATT&CK technique.

        Args:
            technique_id: ATT&CK technique ID (e.g., "T1059.001")

        Returns:
            List of matching community hunts
        """
        matches = []
        for hunt in self.community_hunts:
            if technique_id in hunt.techniques:
                matches.append(hunt)

        return matches

    def search_by_tag(self, tag: str) -> List[CommunityHunt]:
        """
        Search community hunts by tag.

        Args:
            tag: Tag to search for

        Returns:
            List of matching community hunts
        """
        matches = []
        for hunt in self.community_hunts:
            if tag.lower() in [t.lower() for t in hunt.tags]:
                matches.append(hunt)

        return matches

    def search_by_keyword(self, keyword: str) -> List[CommunityHunt]:
        """
        Search community hunts by keyword in name or description.

        Args:
            keyword: Keyword to search for

        Returns:
            List of matching community hunts
        """
        matches = []
        keyword_lower = keyword.lower()

        for hunt in self.community_hunts:
            if (
                keyword_lower in hunt.name.lower()
                or keyword_lower in hunt.description.lower()
                or keyword_lower in hunt.hypothesis.lower()
            ):
                matches.append(hunt)

        return matches

    def adapt_hunt_to_environment(
        self, hunt: CommunityHunt, target_platform: str, environment: str
    ) -> Dict[str, Any]:
        """
        Adapt a community hunt to a specific environment and platform.

        Args:
            hunt: Community hunt to adapt
            target_platform: Target SIEM platform (e.g., "splunk", "sentinel")
            environment: Environment type (e.g., "aws", "azure", "on-prem")

        Returns:
            Adapted hunt plan
        """
        adapted = {
            "original_hunt": hunt.to_dict(),
            "target_platform": target_platform,
            "environment": environment,
            "adapted_queries": [],
            "additional_data_sources": [],
            "environment_notes": [],
        }

        # Get queries for target platform
        if target_platform in hunt.queries:
            adapted["adapted_queries"] = hunt.queries[target_platform]
        else:
            # Try to adapt from another platform
            adapted["adapted_queries"] = self._adapt_queries(hunt.queries, target_platform)
            adapted["environment_notes"].append(
                f"Queries adapted from other platforms to {target_platform}"
            )

        # Add environment-specific notes
        if environment == "aws":
            adapted["additional_data_sources"].extend(["CloudTrail", "VPC Flow Logs", "GuardDuty"])
            adapted["environment_notes"].append(
                "Consider CloudTrail logs for AWS-specific activity"
            )
        elif environment == "azure":
            adapted["additional_data_sources"].extend(
                ["Azure Activity Logs", "Azure AD Logs", "NSG Flow Logs"]
            )
            adapted["environment_notes"].append(
                "Consider Azure Activity Logs for cloud-specific activity"
            )
        elif environment == "gcp":
            adapted["additional_data_sources"].extend(
                ["Cloud Audit Logs", "VPC Flow Logs", "Security Command Center"]
            )
            adapted["environment_notes"].append(
                "Consider Cloud Audit Logs for GCP-specific activity"
            )

        return adapted

    def _adapt_queries(self, queries: Dict[str, List[str]], target_platform: str) -> List[str]:
        """
        Attempt to adapt queries from one platform to another.

        This is a simplified implementation. In production, this would use
        more sophisticated query translation logic.
        """
        adapted = []

        # If we have queries for any platform, note that manual adaptation is needed
        if queries:
            source_platform = list(queries.keys())[0]
            adapted.append(f"# TODO: Adapt queries from {source_platform} to {target_platform}")
            adapted.extend([f"# Original: {q}" for q in queries[source_platform]])

        return adapted

    def contribute_hunt(
        self,
        name: str,
        description: str,
        hypothesis: str,
        techniques: List[str],
        data_sources: List[str],
        queries: Dict[str, List[str]],
        tags: Optional[List[str]] = None,
        references: Optional[List[str]] = None,
    ) -> CommunityHunt:
        """
        Contribute a new hunt to the community repository.

        Args:
            name: Hunt name
            description: Hunt description
            hypothesis: Hunt hypothesis
            techniques: ATT&CK techniques
            data_sources: Required data sources
            queries: Hunt queries by platform
            tags: Optional tags
            references: Optional references

        Returns:
            Created community hunt
        """
        hunt = CommunityHunt(
            id=f"hunt-{len(self.community_hunts) + 1:03d}",
            name=name,
            description=description,
            hypothesis=hypothesis,
            techniques=techniques,
            data_sources=data_sources,
            queries=queries,
            author="User",
            created_date=datetime.now().strftime("%Y-%m-%d"),
            tags=tags or [],
            references=references or [],
        )

        self.community_hunts.append(hunt)

        return hunt

    def get_all_hunts(self) -> List[CommunityHunt]:
        """Get all community hunts."""
        return self.community_hunts

    def get_hunt_by_id(self, hunt_id: str) -> Optional[CommunityHunt]:
        """Get a specific hunt by ID."""
        for hunt in self.community_hunts:
            if hunt.id == hunt_id:
                return hunt
        return None
