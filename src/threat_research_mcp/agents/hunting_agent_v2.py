"""
Hunting Agent v2 - Framework-based threat hunting.

This agent generates threat hunting plans using structured frameworks:
- PEAK (Prepare, Execute, Act with Knowledge)
- TaHiTI (Targeted Hunting integrating Threat Intelligence)
- SQRRL (Hypothesis Maturity Model)
- Pyramid of Pain (Behavioral focus)
- HEARTH (Community hunt integration)
"""

import logging
from typing import Dict, Any

from threat_research_mcp.agents.base_agent import BaseAgent
from threat_research_mcp.schemas.workflow_state import ThreatAnalysisState
from threat_research_mcp.frameworks.peak import PEAKFramework
from threat_research_mcp.frameworks.tahiti import TaHiTIFramework
from threat_research_mcp.frameworks.sqrrl import SQRRLFramework
from threat_research_mcp.frameworks.pyramid_of_pain import PyramidOfPain
from threat_research_mcp.frameworks.hearth import HEARTHIntegration

logger = logging.getLogger(__name__)


class HuntingAgentV2(BaseAgent):
    """
    Hunting Agent v2 - Framework-based threat hunting.

    This agent:
    1. Receives research findings (IOCs, techniques, enrichment)
    2. Selects appropriate hunting framework based on user preference
    3. Generates framework-specific hunt plan
    4. Applies Pyramid of Pain for behavioral focus
    5. Integrates community hunts from HEARTH
    6. Returns comprehensive hunt plan with queries and expected behaviors
    """

    def __init__(self):
        """Initialize Hunting Agent v2."""
        super().__init__("Hunting Agent v2")

        # Initialize frameworks
        self.peak = PEAKFramework()
        self.tahiti = TaHiTIFramework()
        self.sqrrl = SQRRLFramework()
        self.pyramid = PyramidOfPain()
        self.hearth = HEARTHIntegration()

        logger.info("Hunting Agent v2 initialized with all frameworks")

    def execute(self, state: ThreatAnalysisState) -> Dict[str, Any]:
        """
        Execute hunting agent logic.

        Args:
            state: Current workflow state

        Returns:
            Partial state update with hunt plan
        """
        self._validate_input(state, ["intel_text", "research_findings"])

        # Extract inputs
        research_findings = state["research_findings"]
        framework = state.get("framework", "PEAK")
        environment = state.get("environment", "hybrid")
        target_platforms = state.get("target_platforms", ["splunk", "sentinel"])

        logger.info(f"Starting hunt plan generation using {framework} framework")

        # Extract techniques and IOCs from research findings
        findings = research_findings.get("findings", {})
        techniques = [t["technique_id"] for t in findings.get("techniques", [])]
        iocs = self._extract_iocs_from_findings(findings)

        # Generate framework-specific hunt plan
        framework_plan = self._generate_framework_plan(
            framework, techniques, environment, target_platforms
        )

        # Apply Pyramid of Pain analysis
        pyramid_analysis = self.pyramid.analyze_indicators(iocs, techniques)

        # Find relevant community hunts
        community_hunts = self._find_community_hunts(techniques)

        # Combine into comprehensive hunt plan
        hunt_plan = {
            "framework": framework,
            "framework_plan": framework_plan,
            "pyramid_analysis": pyramid_analysis.to_dict(),
            "community_hunts": [h.to_dict() for h in community_hunts],
            "hunt_summary": self._create_hunt_summary(
                framework_plan, pyramid_analysis, community_hunts
            ),
        }

        # Calculate confidence
        confidence = self._calculate_confidence(framework_plan, pyramid_analysis, community_hunts)

        logger.info(
            f"Hunt plan generated: {len(techniques)} techniques, "
            f"{len(community_hunts)} community hunts, confidence: {confidence:.2f}"
        )

        # Return only modified fields
        return {
            "hunt_plan": self._create_output(
                findings=hunt_plan,
                confidence=confidence,
                metadata={
                    "framework": framework,
                    "techniques_count": len(techniques),
                    "community_hunts_count": len(community_hunts),
                },
            ),
            "agent_history": self._get_updated_history(state),
        }

    def _extract_iocs_from_findings(self, findings: Dict[str, Any]) -> Dict[str, list]:
        """Extract IOCs from research findings."""
        iocs = {}

        for ioc_data in findings.get("iocs", []):
            ioc_type = ioc_data.get("type")
            ioc_value = ioc_data.get("value")

            if ioc_type and ioc_value:
                if ioc_type not in iocs:
                    iocs[ioc_type] = []
                iocs[ioc_type].append(ioc_value)

        return iocs

    def _generate_framework_plan(
        self,
        framework: str,
        techniques: list,
        environment: str,
        target_platforms: list,
    ) -> Dict[str, Any]:
        """Generate hunt plan using specified framework."""
        if not techniques:
            # Create a generic hypothesis if no techniques
            hypothesis = "Hunt for suspicious activity patterns"
            techniques = ["T1059.001"]  # Default to PowerShell as example
        else:
            # Create hypothesis from techniques
            hypothesis = f"Hunt for adversary activity using {', '.join(techniques[:3])}"
            if len(techniques) > 3:
                hypothesis += f" and {len(techniques) - 3} more techniques"

        if framework.upper() == "PEAK":
            plan = self.peak.create_hunt_plan(
                hypothesis=hypothesis,
                techniques=techniques,
                environment=environment,
                siem_platforms=target_platforms,
            )
            return plan.to_dict()

        elif framework.upper() == "TAHITI":
            # Extract threat intel from hypothesis
            threat_intel = {
                "techniques": techniques,
                "hypothesis": hypothesis,
            }
            plan = self.tahiti.create_hunt_plan(
                threat_intel=threat_intel,
                techniques=techniques,
                environment=environment,
            )
            return plan.to_dict()

        elif framework.upper() == "SQRRL":
            plan = self.sqrrl.create_hunt_plan(
                hypothesis=hypothesis,
                techniques=techniques,
            )
            return plan.to_dict()

        else:
            # Default to PEAK
            logger.warning(f"Unknown framework {framework}, defaulting to PEAK")
            plan = self.peak.create_hunt_plan(
                hypothesis=hypothesis,
                techniques=techniques,
                environment=environment,
                siem_platforms=target_platforms,
            )
            return plan.to_dict()

    def _find_community_hunts(self, techniques: list) -> list:
        """Find relevant community hunts for techniques."""
        community_hunts = []

        for technique in techniques:
            hunts = self.hearth.search_by_technique(technique)
            for hunt in hunts:
                if hunt not in community_hunts:
                    community_hunts.append(hunt)

        return community_hunts

    def _create_hunt_summary(
        self, framework_plan: Dict[str, Any], pyramid_analysis: Any, community_hunts: list
    ) -> Dict[str, Any]:
        """Create a summary of the hunt plan."""
        # Convert pyramid_analysis to dict if it's not already
        if hasattr(pyramid_analysis, "to_dict"):
            pyramid_dict = pyramid_analysis.to_dict()
        else:
            pyramid_dict = pyramid_analysis

        return {
            "framework_used": framework_plan.get("framework", "Unknown"),
            "hypothesis": framework_plan.get("hypothesis", ""),
            "behavioral_focus": pyramid_dict.get("focus_level", "unknown"),
            "hunt_strategies": pyramid_dict.get("behavioral_focus", {}).get("hunt_strategies", []),
            "community_hunts_available": len(community_hunts),
            "recommended_approach": self._get_recommended_approach(framework_plan, pyramid_dict),
        }

    def _get_recommended_approach(
        self, framework_plan: Dict[str, Any], pyramid_analysis: Dict[str, Any]
    ) -> str:
        """Get recommended hunting approach based on analysis."""
        focus_level = pyramid_analysis.get("focus_level", "")

        if focus_level == "ttps":
            return (
                "Focus on behavioral hunting using TTPs. "
                "Hunt for adversary techniques rather than specific indicators. "
                "This approach is most resilient to adversary changes."
            )
        elif focus_level == "tools":
            return (
                "Focus on tool behaviors and capabilities. "
                "Hunt for how tools are used, not just their presence. "
                "Combine with TTP-based detections for better coverage."
            )
        else:
            return (
                "Use indicators as pivot points for deeper investigation. "
                "Escalate to behavioral hunting when possible. "
                "Correlate multiple indicators for higher confidence."
            )

    def _calculate_confidence(
        self,
        framework_plan: Dict[str, Any],
        pyramid_analysis: Any,
        community_hunts: list,
    ) -> float:
        """Calculate confidence in the hunt plan."""
        confidence = 0.0

        # Framework plan confidence
        if framework_plan.get("confidence"):
            confidence += framework_plan["confidence"] * 0.4

        # Pyramid analysis confidence
        # Convert to dict if it's an object
        if hasattr(pyramid_analysis, "confidence"):
            confidence += pyramid_analysis.confidence * 0.3
        elif isinstance(pyramid_analysis, dict) and pyramid_analysis.get("confidence"):
            confidence += pyramid_analysis["confidence"] * 0.3

        # Community hunts boost confidence
        if community_hunts:
            confidence += min(len(community_hunts) * 0.1, 0.3)

        return min(confidence, 1.0)
