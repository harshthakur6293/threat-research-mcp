"""
PEAK Framework implementation.

PEAK (Prepare, Execute, Act with Knowledge) is a structured threat hunting
framework developed by SANS. It provides a systematic approach to hypothesis-driven
threat hunting.

Reference: https://www.sans.org/white-papers/peak-framework/
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field


@dataclass
class PEAKHuntPlan:
    """
    PEAK hunt plan structure.

    Attributes:
        hypothesis: The threat hypothesis to test
        prepare: Preparation phase outputs
        execute: Execution phase outputs
        act: Action phase outputs
        confidence: Overall confidence in the hunt plan (0.0-1.0)
        metadata: Additional metadata
    """

    hypothesis: str
    prepare: Dict[str, Any]
    execute: Dict[str, Any]
    act: Dict[str, Any]
    confidence: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "framework": "PEAK",
            "hypothesis": self.hypothesis,
            "prepare": self.prepare,
            "execute": self.execute,
            "act": self.act,
            "confidence": self.confidence,
            "metadata": self.metadata,
        }


class PEAKFramework:
    """
    PEAK Framework for structured threat hunting.

    PEAK consists of three phases:
    1. PREPARE: Define hypothesis, identify data sources, set success criteria
    2. EXECUTE: Run hunt queries, collect evidence, analyze results
    3. ACT WITH KNOWLEDGE: Document findings, create detections, share knowledge
    """

    def __init__(self):
        """Initialize PEAK framework."""
        self.name = "PEAK"

    def create_hunt_plan(
        self,
        hypothesis: str,
        techniques: List[str],
        environment: str = "hybrid",
        siem_platforms: Optional[List[str]] = None,
    ) -> PEAKHuntPlan:
        """
        Create a PEAK-based hunt plan.

        Args:
            hypothesis: The threat hypothesis to test
            techniques: List of ATT&CK technique IDs
            environment: Environment type (aws, azure, gcp, on-prem, hybrid)
            siem_platforms: Target SIEM platforms

        Returns:
            Complete PEAK hunt plan
        """
        siem_platforms = siem_platforms or ["splunk", "sentinel"]

        # PREPARE phase
        prepare = self._prepare_phase(hypothesis, techniques, environment)

        # EXECUTE phase
        execute = self._execute_phase(techniques, environment, siem_platforms)

        # ACT phase
        act = self._act_phase(techniques)

        # Calculate confidence
        confidence = self._calculate_confidence(prepare, execute, act)

        return PEAKHuntPlan(
            hypothesis=hypothesis,
            prepare=prepare,
            execute=execute,
            act=act,
            confidence=confidence,
            metadata={
                "framework": "PEAK",
                "environment": environment,
                "siem_platforms": siem_platforms,
            },
        )

    def _prepare_phase(
        self, hypothesis: str, techniques: List[str], environment: str
    ) -> Dict[str, Any]:
        """
        PREPARE phase: Define hypothesis and identify data sources.

        Args:
            hypothesis: The threat hypothesis
            techniques: ATT&CK techniques
            environment: Environment type

        Returns:
            Preparation phase outputs
        """
        # Identify required data sources
        data_sources = self._identify_data_sources(techniques, environment)

        # Define success criteria
        success_criteria = self._define_success_criteria(hypothesis, techniques)

        return {
            "hypothesis": hypothesis,
            "techniques": techniques,
            "data_sources_required": data_sources,
            "success_criteria": success_criteria,
            "estimated_duration": "2-4 hours",
        }

    def _execute_phase(
        self, techniques: List[str], environment: str, siem_platforms: List[str]
    ) -> Dict[str, Any]:
        """
        EXECUTE phase: Generate hunt queries and expected behaviors.

        Args:
            techniques: ATT&CK techniques
            environment: Environment type
            siem_platforms: Target SIEM platforms

        Returns:
            Execution phase outputs
        """
        # Generate hunt queries for each platform
        hunt_queries = {}
        for platform in siem_platforms:
            hunt_queries[platform] = self._generate_hunt_queries(techniques, platform)

        # Define expected behaviors
        expected_behaviors = self._define_expected_behaviors(techniques)

        # Define false positive mitigation
        fp_mitigation = self._define_fp_mitigation(techniques)

        return {
            "hunt_queries": hunt_queries,
            "expected_behaviors": expected_behaviors,
            "false_positive_mitigation": fp_mitigation,
            "hunt_type": "Hypothesis-Driven (Flame)",
        }

    def _act_phase(self, techniques: List[str]) -> Dict[str, Any]:
        """
        ACT WITH KNOWLEDGE phase: Document and operationalize findings.

        Args:
            techniques: ATT&CK techniques

        Returns:
            Action phase outputs
        """
        return {
            "documentation_plan": [
                "Record findings in threat intelligence platform",
                "Update threat actor profile if attribution possible",
                "Document hunt methodology for future use",
            ],
            "detection_plan": [
                "Create Sigma rules for confirmed behaviors",
                "Deploy to SIEM for continuous monitoring",
                "Set appropriate alerting thresholds",
            ],
            "knowledge_sharing": [
                "Share findings with security team",
                "Update runbooks and playbooks",
                "Contribute to community (HEARTH, etc.)",
            ],
        }

    def _identify_data_sources(
        self, techniques: List[str], environment: str
    ) -> List[Dict[str, Any]]:
        """Identify required data sources for techniques."""
        # Simplified mapping
        data_source_map = {
            "T1059.001": [
                {
                    "source": "Windows Security Event Log",
                    "event_id": "4688",
                    "description": "Process Creation",
                },
                {
                    "source": "Sysmon",
                    "event_id": "1",
                    "description": "Process Creation",
                },
                {
                    "source": "PowerShell Logs",
                    "event_id": "4104",
                    "description": "Script Block Logging",
                },
            ],
            "T1071.001": [
                {
                    "source": "Network Traffic Logs",
                    "event_id": "N/A",
                    "description": "HTTP/HTTPS traffic",
                },
                {"source": "Proxy Logs", "event_id": "N/A", "description": "Web requests"},
            ],
        }

        sources = []
        for technique in techniques:
            if technique in data_source_map:
                sources.extend(data_source_map[technique])

        return sources

    def _define_success_criteria(self, hypothesis: str, techniques: List[str]) -> List[str]:
        """Define success criteria for the hunt."""
        return [
            f"Identify at least one instance of {techniques[0]} activity"
            if techniques
            else "Identify suspicious activity",
            "Confirm or refute the hypothesis",
            "Document findings with evidence",
            "Create actionable detections if threats found",
        ]

    def _generate_hunt_queries(self, techniques: List[str], platform: str) -> List[Dict[str, str]]:
        """Generate hunt queries for a platform."""
        queries = []

        for technique in techniques:
            if technique == "T1059.001":  # PowerShell
                if platform == "splunk":
                    queries.append(
                        {
                            "technique": technique,
                            "query": 'index=windows EventCode=4688 Image="*powershell.exe" | stats count by ComputerName, User, CommandLine',
                            "description": "Hunt for PowerShell execution",
                        }
                    )
                elif platform == "sentinel":
                    queries.append(
                        {
                            "technique": technique,
                            "query": 'DeviceProcessEvents | where FileName =~ "powershell.exe" | project Timestamp, DeviceName, AccountName, ProcessCommandLine',
                            "description": "Hunt for PowerShell execution",
                        }
                    )

        return queries

    def _define_expected_behaviors(self, techniques: List[str]) -> List[str]:
        """Define expected malicious behaviors."""
        behavior_map = {
            "T1059.001": [
                "PowerShell spawned by unusual parent process (e.g., Outlook, Excel)",
                "Encoded or obfuscated PowerShell commands",
                "PowerShell downloading files from internet",
                "PowerShell accessing LSASS memory",
            ],
            "T1071.001": [
                "Unusual outbound connections to uncommon ports",
                "Beaconing behavior (regular intervals)",
                "Large data uploads to external IPs",
            ],
        }

        behaviors = []
        for technique in techniques:
            if technique in behavior_map:
                behaviors.extend(behavior_map[technique])

        return behaviors

    def _define_fp_mitigation(self, techniques: List[str]) -> List[str]:
        """Define false positive mitigation strategies."""
        return [
            "Whitelist known administrative scripts",
            "Exclude service accounts",
            "Filter legitimate software update processes",
            "Add time-based logic (after hours = higher severity)",
            "Correlate with other suspicious indicators",
        ]

    def _calculate_confidence(
        self, prepare: Dict[str, Any], execute: Dict[str, Any], act: Dict[str, Any]
    ) -> float:
        """Calculate confidence in the hunt plan."""
        confidence = 0.0

        # Data sources available
        if prepare["data_sources_required"]:
            confidence += 0.3

        # Hunt queries generated
        if execute["hunt_queries"]:
            confidence += 0.3

        # Expected behaviors defined
        if execute["expected_behaviors"]:
            confidence += 0.2

        # Action plan defined
        if act["detection_plan"]:
            confidence += 0.2

        return min(confidence, 1.0)
