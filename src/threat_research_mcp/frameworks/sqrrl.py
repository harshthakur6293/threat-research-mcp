"""
SQRRL Framework implementation.

SQRRL's Hypothesis Maturity Model (HMM) provides a structured approach to
developing and testing threat hunting hypotheses across five maturity levels.

Reference: https://www.threathunting.net/files/framework-for-threat-hunting-whitepaper.pdf
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum


class HypothesisMaturityLevel(Enum):
    """Hypothesis Maturity Model levels."""

    HMM0 = "HMM0: Initial - No hypothesis, reactive hunting"
    HMM1 = "HMM1: Minimal - Basic hypothesis, limited data"
    HMM2 = "HMM2: Procedural - Documented procedures, repeatable"
    HMM3 = "HMM3: Innovative - Data-driven, analytics-based"
    HMM4 = "HMM4: Leading - Automated, continuous hunting"


@dataclass
class SQRRLHuntPlan:
    """
    SQRRL hunt plan structure.

    Attributes:
        hypothesis: The hunt hypothesis
        maturity_level: HMM level
        create: Creation phase outputs
        investigate: Investigation phase outputs
        inform: Information sharing outputs
        confidence: Overall confidence (0.0-1.0)
        metadata: Additional metadata
    """

    hypothesis: str
    maturity_level: HypothesisMaturityLevel
    create: Dict[str, Any]
    investigate: Dict[str, Any]
    inform: Dict[str, Any]
    confidence: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "framework": "SQRRL",
            "hypothesis": self.hypothesis,
            "maturity_level": self.maturity_level.value,
            "create": self.create,
            "investigate": self.investigate,
            "inform": self.inform,
            "confidence": self.confidence,
            "metadata": self.metadata,
        }


class SQRRLFramework:
    """
    SQRRL Framework for hypothesis-driven threat hunting.

    SQRRL phases:
    1. CREATE: Develop hunt hypothesis
    2. INVESTIGATE: Execute hunt and analyze data
    3. INFORM: Share findings and improve defenses

    Includes Hypothesis Maturity Model (HMM0-HMM4) assessment.
    """

    def __init__(self):
        """Initialize SQRRL framework."""
        self.name = "SQRRL"

    def create_hunt_plan(
        self,
        hypothesis: str,
        techniques: List[str],
        threat_intel: Optional[Dict[str, Any]] = None,
        automation_level: str = "manual",
    ) -> SQRRLHuntPlan:
        """
        Create a SQRRL-based hunt plan.

        Args:
            hypothesis: The hunt hypothesis
            techniques: List of ATT&CK technique IDs
            threat_intel: Optional threat intelligence
            automation_level: Level of automation (manual, semi-automated, automated)

        Returns:
            Complete SQRRL hunt plan
        """
        threat_intel = threat_intel or {}

        # Assess maturity level
        maturity_level = self._assess_maturity_level(hypothesis, threat_intel, automation_level)

        # Phase 1: CREATE
        create = self._create_phase(hypothesis, techniques, threat_intel)

        # Phase 2: INVESTIGATE
        investigate = self._investigate_phase(techniques, maturity_level)

        # Phase 3: INFORM
        inform = self._inform_phase(techniques, maturity_level)

        # Calculate confidence
        confidence = self._calculate_confidence(create, investigate, inform, maturity_level)

        return SQRRLHuntPlan(
            hypothesis=hypothesis,
            maturity_level=maturity_level,
            create=create,
            investigate=investigate,
            inform=inform,
            confidence=confidence,
            metadata={
                "framework": "SQRRL",
                "automation_level": automation_level,
            },
        )

    def _assess_maturity_level(
        self, hypothesis: str, threat_intel: Dict[str, Any], automation_level: str
    ) -> HypothesisMaturityLevel:
        """Assess the hypothesis maturity level."""
        score = 0

        # Has hypothesis
        if hypothesis:
            score += 1

        # Has threat intelligence
        if threat_intel:
            score += 1

        # Automation level
        if automation_level == "semi-automated":
            score += 1
        elif automation_level == "automated":
            score += 2

        # Map score to HMM level
        if score == 0:
            return HypothesisMaturityLevel.HMM0
        elif score == 1:
            return HypothesisMaturityLevel.HMM1
        elif score == 2:
            return HypothesisMaturityLevel.HMM2
        elif score == 3:
            return HypothesisMaturityLevel.HMM3
        else:
            return HypothesisMaturityLevel.HMM4

    def _create_phase(
        self, hypothesis: str, techniques: List[str], threat_intel: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Phase 1: CREATE - Develop hunt hypothesis."""
        return {
            "hypothesis": hypothesis,
            "techniques": techniques,
            "threat_intel_used": bool(threat_intel),
            "data_requirements": self._identify_data_requirements(techniques),
            "expected_evidence": self._define_expected_evidence(techniques),
            "hunt_type": self._determine_hunt_type(hypothesis, threat_intel),
        }

    def _investigate_phase(
        self, techniques: List[str], maturity_level: HypothesisMaturityLevel
    ) -> Dict[str, Any]:
        """Phase 2: INVESTIGATE - Execute hunt and analyze data."""
        # Hunt approach varies by maturity level
        if maturity_level == HypothesisMaturityLevel.HMM0:
            approach = "Reactive, IOC-based"
        elif maturity_level == HypothesisMaturityLevel.HMM1:
            approach = "Basic hypothesis testing"
        elif maturity_level == HypothesisMaturityLevel.HMM2:
            approach = "Documented, repeatable procedures"
        elif maturity_level == HypothesisMaturityLevel.HMM3:
            approach = "Data-driven analytics"
        else:
            approach = "Automated, continuous hunting"

        return {
            "hunt_approach": approach,
            "maturity_level": maturity_level.value,
            "hunt_queries": self._generate_hunt_queries(techniques, maturity_level),
            "analysis_techniques": self._define_analysis_techniques(maturity_level),
            "pivot_opportunities": self._identify_pivot_opportunities(techniques),
        }

    def _inform_phase(
        self, techniques: List[str], maturity_level: HypothesisMaturityLevel
    ) -> Dict[str, Any]:
        """Phase 3: INFORM - Share findings and improve defenses."""
        return {
            "documentation": self._define_documentation_plan(maturity_level),
            "detection_engineering": [
                "Create detection rules for confirmed behaviors",
                "Tune existing detections",
                "Deploy to SIEM/EDR",
            ],
            "knowledge_sharing": self._define_knowledge_sharing(maturity_level),
            "continuous_improvement": [
                "Update hunt hypothesis based on findings",
                "Refine data collection requirements",
                "Improve automation where possible",
            ],
        }

    def _identify_data_requirements(self, techniques: List[str]) -> List[str]:
        """Identify data requirements for techniques."""
        requirements = ["Windows Event Logs", "Network Traffic"]

        if any(t.startswith("T1059") for t in techniques):
            requirements.extend(["PowerShell Logs", "Command Line Logs"])

        if any(t.startswith("T1003") for t in techniques):
            requirements.extend(["LSASS Access Logs", "Memory Dumps"])

        return list(set(requirements))

    def _define_expected_evidence(self, techniques: List[str]) -> List[str]:
        """Define expected evidence for techniques."""
        evidence = []
        for technique in techniques:
            if technique == "T1059.001":
                evidence.extend(
                    [
                        "PowerShell process creation events",
                        "Script block logging entries",
                        "Encoded command execution",
                    ]
                )
            elif technique == "T1071.001":
                evidence.extend(
                    [
                        "HTTP/HTTPS connections to unusual domains",
                        "Regular beaconing patterns",
                        "Suspicious user agents",
                    ]
                )
        return evidence

    def _determine_hunt_type(self, hypothesis: str, threat_intel: Dict[str, Any]) -> str:
        """Determine the type of hunt."""
        if threat_intel:
            return "Intelligence-Driven"
        elif hypothesis:
            return "Hypothesis-Driven"
        else:
            return "Exploratory"

    def _generate_hunt_queries(
        self, techniques: List[str], maturity_level: HypothesisMaturityLevel
    ) -> List[Dict[str, str]]:
        """Generate hunt queries based on maturity level."""
        queries = []

        for technique in techniques:
            if maturity_level in [
                HypothesisMaturityLevel.HMM0,
                HypothesisMaturityLevel.HMM1,
            ]:
                # Basic queries
                queries.append(
                    {
                        "technique": technique,
                        "query": f"Basic search for {technique} indicators",
                        "complexity": "low",
                    }
                )
            elif maturity_level == HypothesisMaturityLevel.HMM2:
                # Documented procedures
                queries.append(
                    {
                        "technique": technique,
                        "query": f"Documented hunt procedure for {technique}",
                        "complexity": "medium",
                    }
                )
            else:
                # Advanced analytics
                queries.append(
                    {
                        "technique": technique,
                        "query": f"Advanced analytics query for {technique}",
                        "complexity": "high",
                    }
                )

        return queries

    def _define_analysis_techniques(self, maturity_level: HypothesisMaturityLevel) -> List[str]:
        """Define analysis techniques based on maturity."""
        if maturity_level in [
            HypothesisMaturityLevel.HMM0,
            HypothesisMaturityLevel.HMM1,
        ]:
            return ["Manual log review", "IOC matching"]
        elif maturity_level == HypothesisMaturityLevel.HMM2:
            return ["Structured log analysis", "Pattern matching", "Timeline analysis"]
        else:
            return [
                "Statistical analysis",
                "Machine learning",
                "Behavioral analytics",
                "Graph analysis",
            ]

    def _identify_pivot_opportunities(self, techniques: List[str]) -> List[str]:
        """Identify opportunities to pivot during investigation."""
        return [
            "Pivot on suspicious process trees",
            "Pivot on network connections from suspicious processes",
            "Pivot on file modifications",
            "Pivot on user accounts involved",
            "Pivot on similar behaviors across systems",
        ]

    def _define_documentation_plan(self, maturity_level: HypothesisMaturityLevel) -> List[str]:
        """Define documentation plan based on maturity."""
        base_docs = [
            "Document hunt hypothesis",
            "Record findings and evidence",
            "Create timeline of events",
        ]

        if maturity_level.value >= HypothesisMaturityLevel.HMM2.value:
            base_docs.extend(
                [
                    "Document repeatable procedures",
                    "Create hunt playbook",
                ]
            )

        if maturity_level.value >= HypothesisMaturityLevel.HMM3.value:
            base_docs.extend(
                [
                    "Document analytics methodology",
                    "Share data models",
                ]
            )

        return base_docs

    def _define_knowledge_sharing(self, maturity_level: HypothesisMaturityLevel) -> List[str]:
        """Define knowledge sharing approach."""
        sharing = ["Share findings with security team"]

        if maturity_level.value >= HypothesisMaturityLevel.HMM2.value:
            sharing.append("Contribute to internal knowledge base")

        if maturity_level.value >= HypothesisMaturityLevel.HMM3.value:
            sharing.extend(
                [
                    "Share with security community (HEARTH, etc.)",
                    "Publish anonymized case studies",
                ]
            )

        return sharing

    def _calculate_confidence(
        self,
        create: Dict[str, Any],
        investigate: Dict[str, Any],
        inform: Dict[str, Any],
        maturity_level: HypothesisMaturityLevel,
    ) -> float:
        """Calculate confidence in the hunt plan."""
        confidence = 0.0

        # Hypothesis quality
        if create["hypothesis"]:
            confidence += 0.2

        # Data requirements defined
        if create["data_requirements"]:
            confidence += 0.2

        # Hunt queries generated
        if investigate["hunt_queries"]:
            confidence += 0.2

        # Documentation plan
        if inform["documentation"]:
            confidence += 0.2

        # Maturity level bonus
        maturity_bonus = maturity_level.value[3] if maturity_level.value[3].isdigit() else 0
        confidence += int(maturity_bonus) * 0.04

        return min(confidence, 1.0)
