"""
Detection Agent v2 - Multi-schema detection rule generation.

This agent generates detection rules in multiple formats:
- Sigma (universal format)
- KQL (Azure Sentinel)
- SPL (Splunk)
- EQL (Elastic Security)

It also validates rules and provides tuning recommendations.
"""

import logging
from typing import Dict, Any, List

from threat_research_mcp.agents.base_agent import BaseAgent
from threat_research_mcp.schemas.workflow_state import ThreatAnalysisState
from threat_research_mcp.detection.generators.sigma import SigmaGenerator
from threat_research_mcp.detection.generators.kql import KQLGenerator
from threat_research_mcp.detection.generators.spl import SPLGenerator
from threat_research_mcp.detection.generators.eql import EQLGenerator
from threat_research_mcp.detection.validators.sigma_validator import SigmaValidator
from threat_research_mcp.detection.validators.kql_validator import KQLValidator
from threat_research_mcp.detection.validators.spl_validator import SPLValidator
from threat_research_mcp.detection.validators.eql_validator import EQLValidator

logger = logging.getLogger(__name__)


class DetectionAgentV2(BaseAgent):
    """
    Detection Agent v2 - Multi-schema detection rule generation.

    This agent:
    1. Receives hunt plan with techniques and expected behaviors
    2. Generates detection rules in multiple formats (Sigma, KQL, SPL, EQL)
    3. Validates generated rules
    4. Provides tuning recommendations
    5. Returns comprehensive detection package
    """

    def __init__(self):
        """Initialize Detection Agent v2."""
        super().__init__("Detection Agent v2")

        # Initialize generators
        self.sigma_generator = SigmaGenerator()
        self.kql_generator = KQLGenerator()
        self.spl_generator = SPLGenerator()
        self.eql_generator = EQLGenerator()

        # Initialize validators
        self.sigma_validator = SigmaValidator()
        self.kql_validator = KQLValidator()
        self.spl_validator = SPLValidator()
        self.eql_validator = EQLValidator()

        logger.info("Detection Agent v2 initialized with all generators and validators")

    def execute(self, state: ThreatAnalysisState) -> Dict[str, Any]:
        """
        Execute detection agent logic.

        Args:
            state: Current workflow state

        Returns:
            Partial state update with detection rules
        """
        self._validate_input(state, ["intel_text", "research_findings", "hunt_plan"])

        # Extract inputs
        research_findings = state["research_findings"]
        hunt_plan = state["hunt_plan"]
        target_platforms = state.get("target_platforms", ["splunk", "sentinel"])

        logger.info(f"Starting detection rule generation for platforms: {target_platforms}")

        # Extract techniques from research findings
        findings = research_findings.get("findings", {})
        techniques = [t["technique_id"] for t in findings.get("techniques", [])]

        if not techniques:
            logger.warning("No techniques found, using default technique")
            techniques = ["T1059.001"]  # Default to PowerShell

        # Generate rules for each platform
        detections = {}

        # Always generate Sigma (universal format)
        sigma_rules = self._generate_sigma_rules(techniques)
        detections["sigma"] = sigma_rules

        # Generate platform-specific rules
        if "sentinel" in target_platforms or "azure" in target_platforms:
            kql_rules = self._generate_kql_rules(techniques)
            detections["kql"] = kql_rules

        if "splunk" in target_platforms:
            spl_rules = self._generate_spl_rules(techniques)
            detections["spl"] = spl_rules

        if "elastic" in target_platforms:
            eql_rules = self._generate_eql_rules(techniques)
            detections["eql"] = eql_rules

        # Validate all rules
        validation_results = self._validate_all_rules(detections)

        # Generate tuning recommendations
        tuning_recommendations = self._generate_tuning_recommendations(detections, hunt_plan)

        # Create detection package
        detection_package = {
            "detections": detections,
            "validation_results": validation_results,
            "tuning_recommendations": tuning_recommendations,
            "summary": self._create_detection_summary(detections, validation_results),
        }

        # Calculate confidence
        confidence = self._calculate_confidence(detections, validation_results)

        logger.info(
            f"Detection rules generated: {sum(len(v['rules']) for v in detections.values())} total rules, "
            f"confidence: {confidence:.2f}"
        )

        # Return only modified fields
        return {
            "detections": self._create_output(
                findings=detection_package,
                confidence=confidence,
                metadata={
                    "platforms": list(detections.keys()),
                    "total_rules": sum(len(v["rules"]) for v in detections.values()),
                    "techniques_covered": len(techniques),
                },
            ),
            "agent_history": self._get_updated_history(state),
        }

    def _generate_sigma_rules(self, techniques: List[str]) -> Dict[str, Any]:
        """Generate Sigma rules for techniques."""
        rules = []

        for technique in techniques:
            technique_name = self._get_technique_name(technique)
            rule = self.sigma_generator.generate_from_technique(technique, technique_name)
            rules.append(rule.to_dict())

        return {
            "format": "sigma",
            "rules": rules,
            "count": len(rules),
        }

    def _generate_kql_rules(self, techniques: List[str]) -> Dict[str, Any]:
        """Generate KQL rules for techniques."""
        rules = []

        for technique in techniques:
            technique_name = self._get_technique_name(technique)
            rule = self.kql_generator.generate_from_technique(technique, technique_name)
            rules.append(rule.to_dict())

        return {
            "format": "kql",
            "rules": rules,
            "count": len(rules),
        }

    def _generate_spl_rules(self, techniques: List[str]) -> Dict[str, Any]:
        """Generate SPL rules for techniques."""
        rules = []

        for technique in techniques:
            technique_name = self._get_technique_name(technique)
            rule = self.spl_generator.generate_from_technique(technique, technique_name)
            rules.append(rule.to_dict())

        return {
            "format": "spl",
            "rules": rules,
            "count": len(rules),
        }

    def _generate_eql_rules(self, techniques: List[str]) -> Dict[str, Any]:
        """Generate EQL rules for techniques."""
        rules = []

        for technique in techniques:
            technique_name = self._get_technique_name(technique)
            rule = self.eql_generator.generate_from_technique(technique, technique_name)
            rules.append(rule.to_dict())

        return {
            "format": "eql",
            "rules": rules,
            "count": len(rules),
        }

    def _validate_all_rules(self, detections: Dict[str, Any]) -> Dict[str, Any]:
        """Validate all generated rules."""
        validation_results = {}

        for format_name, detection_data in detections.items():
            rules = detection_data.get("rules", [])
            validator = self._get_validator(format_name)

            format_results = []
            for rule in rules:
                is_valid, issues = validator.validate(rule)
                format_results.append(
                    {
                        "rule_name": rule.get("name") or rule.get("title", "Unknown"),
                        "is_valid": is_valid,
                        "issues": issues,
                    }
                )

            validation_results[format_name] = {
                "total_rules": len(rules),
                "valid_rules": sum(1 for r in format_results if r["is_valid"]),
                "invalid_rules": sum(1 for r in format_results if not r["is_valid"]),
                "results": format_results,
            }

        return validation_results

    def _get_validator(self, format_name: str):
        """Get validator for format."""
        validators = {
            "sigma": self.sigma_validator,
            "kql": self.kql_validator,
            "spl": self.spl_validator,
            "eql": self.eql_validator,
        }
        return validators.get(format_name, self.sigma_validator)

    def _generate_tuning_recommendations(
        self, detections: Dict[str, Any], hunt_plan: Dict[str, Any]
    ) -> List[Dict[str, str]]:
        """Generate tuning recommendations for detections."""
        recommendations = []

        # Get behavioral focus from hunt plan
        hunt_findings = hunt_plan.get("findings", {})
        pyramid_analysis = hunt_findings.get("pyramid_analysis", {})
        behavioral_focus = pyramid_analysis.get("behavioral_focus", {})

        # Recommendation 1: Baseline period
        recommendations.append(
            {
                "category": "Baseline",
                "recommendation": "Run detections in monitor-only mode for 1-2 weeks to establish baseline",
                "rationale": "Understand normal activity patterns before enabling alerting",
            }
        )

        # Recommendation 2: False positive mitigation
        recommendations.append(
            {
                "category": "False Positives",
                "recommendation": "Implement whitelisting for known legitimate processes and users",
                "rationale": "Reduce alert fatigue by filtering expected behavior",
            }
        )

        # Recommendation 3: Severity tuning
        recommendations.append(
            {
                "category": "Severity",
                "recommendation": "Start with lower severity and increase based on observed impact",
                "rationale": "Prevent alert fatigue while validating detection effectiveness",
            }
        )

        # Recommendation 4: Correlation
        recommendations.append(
            {
                "category": "Correlation",
                "recommendation": "Correlate multiple low-confidence detections for higher-confidence alerts",
                "rationale": "Improve detection accuracy by identifying attack chains",
            }
        )

        # Recommendation 5: Behavioral focus
        if behavioral_focus.get("focus_level") == "ttps":
            recommendations.append(
                {
                    "category": "Behavioral Focus",
                    "recommendation": "Prioritize behavioral detections over indicator-based alerts",
                    "rationale": "TTPs are more resilient to adversary changes than IOCs",
                }
            )

        return recommendations

    def _create_detection_summary(
        self, detections: Dict[str, Any], validation_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Create summary of detection package."""
        total_rules = sum(d.get("count", 0) for d in detections.values())
        total_valid = sum(v.get("valid_rules", 0) for v in validation_results.values())

        return {
            "total_rules_generated": total_rules,
            "total_valid_rules": total_valid,
            "formats": list(detections.keys()),
            "validation_pass_rate": (total_valid / total_rules if total_rules > 0 else 0.0),
        }

    def _calculate_confidence(
        self, detections: Dict[str, Any], validation_results: Dict[str, Any]
    ) -> float:
        """Calculate confidence in detection package."""
        confidence = 0.0

        # Base confidence from number of rules
        total_rules = sum(d.get("count", 0) for d in detections.values())
        if total_rules > 0:
            confidence += min(total_rules * 0.1, 0.4)

        # Confidence from validation
        total_valid = sum(v.get("valid_rules", 0) for v in validation_results.values())
        if total_rules > 0:
            validation_rate = total_valid / total_rules
            confidence += validation_rate * 0.4

        # Confidence from multiple formats
        confidence += min(len(detections) * 0.1, 0.2)

        return min(confidence, 1.0)

    def _get_technique_name(self, technique_id: str) -> str:
        """Get technique name from ID (simplified)."""
        technique_names = {
            "T1059.001": "PowerShell",
            "T1003.001": "LSASS Memory",
            "T1071.001": "Web Protocols",
            "T1566.001": "Spearphishing Attachment",
        }
        return technique_names.get(technique_id, "Unknown Technique")
