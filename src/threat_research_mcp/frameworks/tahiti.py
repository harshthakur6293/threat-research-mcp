"""
TaHiTI Framework implementation.

TaHiTI (Targeted Hunting integrating Threat Intelligence) is a framework that
emphasizes the integration of threat intelligence into the hunting process.

Reference: https://www.betaalvereniging.nl/en/safety/tahiti/
"""

from typing import Dict, List, Any
from dataclasses import dataclass, field


@dataclass
class TaHiTIHuntPlan:
    """
    TaHiTI hunt plan structure.

    Attributes:
        threat_intel: Threat intelligence used
        targeting: Targeting phase outputs
        analysis: Analysis phase outputs
        hypothesis: Hypothesis phase outputs
        investigation: Investigation phase outputs
        confidence: Overall confidence (0.0-1.0)
        metadata: Additional metadata
    """

    threat_intel: Dict[str, Any]
    targeting: Dict[str, Any]
    analysis: Dict[str, Any]
    hypothesis: Dict[str, Any]
    investigation: Dict[str, Any]
    confidence: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "framework": "TaHiTI",
            "threat_intel": self.threat_intel,
            "targeting": self.targeting,
            "analysis": self.analysis,
            "hypothesis": self.hypothesis,
            "investigation": self.investigation,
            "confidence": self.confidence,
            "metadata": self.metadata,
        }


class TaHiTIFramework:
    """
    TaHiTI Framework for intelligence-driven threat hunting.

    TaHiTI phases:
    1. THREAT INTELLIGENCE: Collect and analyze threat intel
    2. TARGETING: Identify hunt targets based on intel
    3. ANALYSIS: Analyze environment for indicators
    4. HYPOTHESIS: Develop testable hypotheses
    5. INVESTIGATION: Execute hunt and investigate findings
    """

    def __init__(self):
        """Initialize TaHiTI framework."""
        self.name = "TaHiTI"

    def create_hunt_plan(
        self,
        threat_intel: Dict[str, Any],
        techniques: List[str],
        environment: str = "hybrid",
    ) -> TaHiTIHuntPlan:
        """
        Create a TaHiTI-based hunt plan.

        Args:
            threat_intel: Threat intelligence data (IOCs, TTPs, actor info)
            techniques: List of ATT&CK technique IDs
            environment: Environment type

        Returns:
            Complete TaHiTI hunt plan
        """
        # Phase 1: Threat Intelligence
        intel_phase = self._threat_intelligence_phase(threat_intel, techniques)

        # Phase 2: Targeting
        targeting = self._targeting_phase(intel_phase, environment)

        # Phase 3: Analysis
        analysis = self._analysis_phase(targeting, techniques)

        # Phase 4: Hypothesis
        hypothesis = self._hypothesis_phase(analysis, techniques)

        # Phase 5: Investigation
        investigation = self._investigation_phase(hypothesis, techniques)

        # Calculate confidence
        confidence = self._calculate_confidence(
            intel_phase, targeting, analysis, hypothesis, investigation
        )

        return TaHiTIHuntPlan(
            threat_intel=intel_phase,
            targeting=targeting,
            analysis=analysis,
            hypothesis=hypothesis,
            investigation=investigation,
            confidence=confidence,
            metadata={"framework": "TaHiTI", "environment": environment},
        )

    def _threat_intelligence_phase(
        self, threat_intel: Dict[str, Any], techniques: List[str]
    ) -> Dict[str, Any]:
        """Phase 1: Collect and analyze threat intelligence."""
        return {
            "iocs": threat_intel.get("iocs", []),
            "ttps": techniques,
            "threat_actors": threat_intel.get("threat_actors", []),
            "campaigns": threat_intel.get("campaigns", []),
            "intel_sources": threat_intel.get("sources", ["internal", "osint"]),
            "intel_confidence": threat_intel.get("confidence", 0.7),
        }

    def _targeting_phase(self, intel_phase: Dict[str, Any], environment: str) -> Dict[str, Any]:
        """Phase 2: Identify hunt targets based on intelligence."""
        # Determine which assets are most at risk
        high_value_targets = self._identify_high_value_targets(intel_phase["ttps"], environment)

        # Determine hunt scope
        hunt_scope = self._determine_hunt_scope(intel_phase, environment)

        return {
            "high_value_targets": high_value_targets,
            "hunt_scope": hunt_scope,
            "priority_systems": self._prioritize_systems(intel_phase["ttps"], environment),
        }

    def _analysis_phase(self, targeting: Dict[str, Any], techniques: List[str]) -> Dict[str, Any]:
        """Phase 3: Analyze environment for indicators."""
        return {
            "baseline_behavior": "Establish normal behavior patterns",
            "anomaly_detection": [
                "Identify deviations from baseline",
                "Focus on high-value targets",
                "Correlate with threat intelligence",
            ],
            "data_sources": self._identify_data_sources(techniques),
            "analysis_techniques": [
                "Statistical analysis",
                "Behavioral analysis",
                "Pattern matching",
            ],
        }

    def _hypothesis_phase(self, analysis: Dict[str, Any], techniques: List[str]) -> Dict[str, Any]:
        """Phase 4: Develop testable hypotheses."""
        hypotheses = []
        for technique in techniques:
            hypotheses.append(
                {
                    "technique": technique,
                    "hypothesis": f"Adversary is using {technique} in our environment",
                    "testable": True,
                    "indicators": self._get_technique_indicators(technique),
                }
            )

        return {"hypotheses": hypotheses, "priority": "intelligence-driven"}

    def _investigation_phase(
        self, hypothesis: Dict[str, Any], techniques: List[str]
    ) -> Dict[str, Any]:
        """Phase 5: Execute hunt and investigate findings."""
        return {
            "hunt_queries": self._generate_hunt_queries(techniques),
            "investigation_steps": [
                "Execute hunt queries against identified targets",
                "Analyze results for hypothesis validation",
                "Pivot on findings to discover additional activity",
                "Document evidence and create timeline",
            ],
            "escalation_criteria": [
                "Confirmed malicious activity",
                "Multiple indicators correlate",
                "High-confidence threat actor attribution",
            ],
        }

    def _identify_high_value_targets(self, techniques: List[str], environment: str) -> List[str]:
        """Identify high-value targets based on TTPs."""
        targets = ["Domain Controllers", "File Servers", "Database Servers"]

        if "T1003" in techniques:  # Credential Dumping
            targets.extend(["Workstations with admin access", "Jump servers"])

        if "T1071" in techniques:  # Application Layer Protocol
            targets.extend(["Web servers", "API gateways"])

        return list(set(targets))

    def _determine_hunt_scope(
        self, intel_phase: Dict[str, Any], environment: str
    ) -> Dict[str, Any]:
        """Determine the scope of the hunt."""
        return {
            "timeframe": "Last 90 days",
            "systems": "High-value targets + sample of general population",
            "data_sources": "All available telemetry",
            "geographic_scope": "All locations" if environment == "hybrid" else environment,
        }

    def _prioritize_systems(self, techniques: List[str], environment: str) -> List[Dict[str, Any]]:
        """Prioritize systems for hunting."""
        return [
            {
                "system": "Domain Controllers",
                "priority": "critical",
                "reason": "Central authentication",
            },
            {
                "system": "Email Servers",
                "priority": "high",
                "reason": "Common initial access vector",
            },
            {"system": "VPN Gateways", "priority": "high", "reason": "Remote access entry point"},
        ]

    def _identify_data_sources(self, techniques: List[str]) -> List[str]:
        """Identify required data sources."""
        sources = ["Windows Event Logs", "Sysmon", "Network Traffic"]

        if any(t.startswith("T1059") for t in techniques):
            sources.append("PowerShell Logs")

        if any(t.startswith("T1071") for t in techniques):
            sources.extend(["Proxy Logs", "Firewall Logs"])

        return list(set(sources))

    def _get_technique_indicators(self, technique: str) -> List[str]:
        """Get indicators for a technique."""
        indicator_map = {
            "T1059.001": [
                "powershell.exe execution",
                "Encoded commands",
                "Download cradles",
            ],
            "T1071.001": [
                "Unusual HTTP user agents",
                "Beaconing behavior",
                "C2 domains",
            ],
        }
        return indicator_map.get(technique, ["Generic suspicious behavior"])

    def _generate_hunt_queries(self, techniques: List[str]) -> List[Dict[str, str]]:
        """Generate hunt queries."""
        queries = []
        for technique in techniques:
            queries.append(
                {
                    "technique": technique,
                    "query": f"Hunt query for {technique}",
                    "platform": "multi-platform",
                }
            )
        return queries

    def _calculate_confidence(
        self,
        intel_phase: Dict[str, Any],
        targeting: Dict[str, Any],
        analysis: Dict[str, Any],
        hypothesis: Dict[str, Any],
        investigation: Dict[str, Any],
    ) -> float:
        """Calculate confidence in the hunt plan."""
        confidence = 0.0

        # Intel quality
        confidence += intel_phase.get("intel_confidence", 0.5) * 0.3

        # Targeting clarity
        if targeting["high_value_targets"]:
            confidence += 0.2

        # Analysis depth
        if analysis["data_sources"]:
            confidence += 0.2

        # Hypothesis quality
        if hypothesis["hypotheses"]:
            confidence += 0.15

        # Investigation plan
        if investigation["hunt_queries"]:
            confidence += 0.15

        return min(confidence, 1.0)
