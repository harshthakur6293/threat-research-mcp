"""
Pyramid of Pain implementation.

The Pyramid of Pain is a framework for understanding the difficulty of detecting
and defending against different types of indicators. It emphasizes hunting for
TTPs (Tactics, Techniques, and Procedures) rather than simple IOCs.

Reference: http://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html

Pyramid Levels (bottom to top):
1. Hash Values (Trivial) - Easy to change
2. IP Addresses (Easy) - Simple to change
3. Domain Names (Simple) - Requires some effort
4. Network/Host Artifacts (Annoying) - More difficult to change
5. Tools (Challenging) - Requires retooling
6. TTPs (Tough) - Fundamental behavior changes required
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum


class PyramidLevel(Enum):
    """Pyramid of Pain levels."""

    HASH_VALUES = "hash_values"
    IP_ADDRESSES = "ip_addresses"
    DOMAIN_NAMES = "domain_names"
    NETWORK_HOST_ARTIFACTS = "network_host_artifacts"
    TOOLS = "tools"
    TTPS = "ttps"


@dataclass
class PyramidAnalysis:
    """
    Pyramid of Pain analysis structure.

    Attributes:
        focus_level: Primary focus level for hunting
        indicators_by_level: Indicators organized by pyramid level
        behavioral_focus: Behavioral patterns to hunt for
        confidence: Overall confidence (0.0-1.0)
        metadata: Additional metadata
    """

    focus_level: PyramidLevel
    indicators_by_level: Dict[str, List[str]]
    behavioral_focus: Dict[str, Any]
    confidence: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "framework": "Pyramid of Pain",
            "focus_level": self.focus_level.value,
            "indicators_by_level": self.indicators_by_level,
            "behavioral_focus": self.behavioral_focus,
            "confidence": self.confidence,
            "metadata": self.metadata,
        }


class PyramidOfPain:
    """
    Pyramid of Pain framework for behavioral threat hunting.

    This framework helps prioritize hunting efforts by focusing on indicators
    that are most difficult for adversaries to change (TTPs > Tools > Artifacts > etc.)
    """

    def __init__(self):
        """Initialize Pyramid of Pain framework."""
        self.name = "Pyramid of Pain"

        # Define difficulty/impact for each level
        self.level_impact = {
            PyramidLevel.HASH_VALUES: {
                "difficulty": "Trivial",
                "impact": "Low",
                "description": "Easy for adversary to change",
            },
            PyramidLevel.IP_ADDRESSES: {
                "difficulty": "Easy",
                "impact": "Low-Medium",
                "description": "Simple for adversary to change",
            },
            PyramidLevel.DOMAIN_NAMES: {
                "difficulty": "Simple",
                "impact": "Medium",
                "description": "Requires some effort to change",
            },
            PyramidLevel.NETWORK_HOST_ARTIFACTS: {
                "difficulty": "Annoying",
                "impact": "Medium-High",
                "description": "More difficult to change",
            },
            PyramidLevel.TOOLS: {
                "difficulty": "Challenging",
                "impact": "High",
                "description": "Requires retooling",
            },
            PyramidLevel.TTPS: {
                "difficulty": "Tough",
                "impact": "Very High",
                "description": "Fundamental behavior changes required",
            },
        }

    def analyze_indicators(
        self,
        iocs: Dict[str, List[str]],
        techniques: List[str],
        tools: Optional[List[str]] = None,
    ) -> PyramidAnalysis:
        """
        Analyze indicators and organize by Pyramid of Pain level.

        Args:
            iocs: Dictionary of IOCs by type
            techniques: List of ATT&CK technique IDs
            tools: Optional list of tools identified

        Returns:
            Pyramid analysis with behavioral focus recommendations
        """
        tools = tools or []

        # Organize indicators by pyramid level
        indicators_by_level = self._organize_by_level(iocs, techniques, tools)

        # Determine optimal focus level
        focus_level = self._determine_focus_level(indicators_by_level, techniques)

        # Generate behavioral focus recommendations
        behavioral_focus = self._generate_behavioral_focus(techniques, focus_level)

        # Calculate confidence
        confidence = self._calculate_confidence(indicators_by_level, techniques)

        return PyramidAnalysis(
            focus_level=focus_level,
            indicators_by_level=indicators_by_level,
            behavioral_focus=behavioral_focus,
            confidence=confidence,
            metadata={
                "framework": "Pyramid of Pain",
                "total_indicators": sum(len(v) for v in indicators_by_level.values()),
                "has_ttps": len(techniques) > 0,
            },
        )

    def _organize_by_level(
        self, iocs: Dict[str, List[str]], techniques: List[str], tools: List[str]
    ) -> Dict[str, List[str]]:
        """Organize indicators by pyramid level."""
        organized = {
            "hash_values": [],
            "ip_addresses": [],
            "domain_names": [],
            "network_host_artifacts": [],
            "tools": [],
            "ttps": [],
        }

        # Hash values
        for ioc_type in ["hash_md5", "hash_sha1", "hash_sha256"]:
            if ioc_type in iocs:
                organized["hash_values"].extend(iocs[ioc_type])

        # IP addresses
        if "ip" in iocs:
            organized["ip_addresses"].extend(iocs["ip"])

        # Domain names
        if "domain" in iocs:
            organized["domain_names"].extend(iocs["domain"])

        # URLs could be network artifacts
        if "url" in iocs:
            organized["network_host_artifacts"].extend(iocs["url"])

        # Tools
        organized["tools"].extend(tools)

        # TTPs (techniques)
        organized["ttps"].extend(techniques)

        return organized

    def _determine_focus_level(
        self, indicators_by_level: Dict[str, List[str]], techniques: List[str]
    ) -> PyramidLevel:
        """Determine the optimal focus level for hunting."""
        # Always prioritize TTPs if available
        if techniques:
            return PyramidLevel.TTPS

        # Otherwise, find the highest level with indicators
        priority_order = [
            PyramidLevel.TTPS,
            PyramidLevel.TOOLS,
            PyramidLevel.NETWORK_HOST_ARTIFACTS,
            PyramidLevel.DOMAIN_NAMES,
            PyramidLevel.IP_ADDRESSES,
            PyramidLevel.HASH_VALUES,
        ]

        for level in priority_order:
            if indicators_by_level.get(level.value):
                return level

        # Default to TTPs even if no indicators (behavioral focus)
        return PyramidLevel.TTPS

    def _generate_behavioral_focus(
        self, techniques: List[str], focus_level: PyramidLevel
    ) -> Dict[str, Any]:
        """Generate behavioral focus recommendations."""
        behavioral_focus = {
            "recommended_level": focus_level.value,
            "rationale": self.level_impact[focus_level]["description"],
            "impact": self.level_impact[focus_level]["impact"],
            "hunt_strategies": [],
            "detection_priorities": [],
        }

        if focus_level == PyramidLevel.TTPS:
            behavioral_focus["hunt_strategies"] = [
                "Focus on adversary behavior patterns, not specific indicators",
                "Hunt for technique implementations (e.g., process injection, credential dumping)",
                "Look for chains of techniques (attack paths)",
                "Identify deviations from normal behavior",
            ]
            behavioral_focus["detection_priorities"] = [
                "Behavioral analytics (e.g., unusual process relationships)",
                "Anomaly detection (e.g., rare parent-child process combinations)",
                "Technique-specific detections (e.g., LSASS access patterns)",
                "Attack chain detection (e.g., reconnaissance -> lateral movement)",
            ]

        elif focus_level == PyramidLevel.TOOLS:
            behavioral_focus["hunt_strategies"] = [
                "Hunt for tool behaviors, not just tool names",
                "Look for tool capabilities (e.g., network scanning, credential dumping)",
                "Identify tool artifacts (e.g., specific registry keys, files)",
                "Focus on how tools are used, not just their presence",
            ]
            behavioral_focus["detection_priorities"] = [
                "Tool behavior signatures",
                "Capability-based detections",
                "Tool artifact patterns",
                "Execution context analysis",
            ]

        elif focus_level == PyramidLevel.NETWORK_HOST_ARTIFACTS:
            behavioral_focus["hunt_strategies"] = [
                "Hunt for persistent artifacts (e.g., registry keys, scheduled tasks)",
                "Look for network patterns (e.g., beaconing, data exfiltration)",
                "Identify host-based artifacts (e.g., specific file paths, services)",
                "Focus on artifact combinations",
            ]
            behavioral_focus["detection_priorities"] = [
                "Persistence mechanism detections",
                "Network pattern analysis",
                "Host artifact monitoring",
                "Artifact correlation",
            ]

        else:
            # For lower levels (domains, IPs, hashes)
            behavioral_focus["hunt_strategies"] = [
                "Use indicators as pivot points, not final detections",
                "Correlate with higher-level indicators",
                "Look for patterns across multiple indicators",
                "Escalate to behavioral hunting when possible",
            ]
            behavioral_focus["detection_priorities"] = [
                "Indicator-based alerting (low confidence)",
                "Correlation with other indicators",
                "Contextual analysis",
                "Escalation to behavioral detections",
            ]

        # Add technique-specific recommendations
        if techniques:
            behavioral_focus["technique_focus"] = self._get_technique_behaviors(techniques)

        return behavioral_focus

    def _get_technique_behaviors(self, techniques: List[str]) -> List[Dict[str, str]]:
        """Get behavioral patterns for specific techniques."""
        # Simplified mapping of techniques to behaviors
        technique_behaviors = {
            "T1059.001": {
                "technique": "PowerShell",
                "behaviors": [
                    "PowerShell spawned by unusual parent",
                    "Encoded/obfuscated commands",
                    "Network connections from PowerShell",
                    "LSASS memory access",
                ],
            },
            "T1071.001": {
                "technique": "Web Protocols",
                "behaviors": [
                    "Beaconing to external IPs",
                    "Unusual user-agent strings",
                    "Large data uploads",
                    "Connections to uncommon ports",
                ],
            },
            "T1566.001": {
                "technique": "Spearphishing Attachment",
                "behaviors": [
                    "Office apps spawning suspicious processes",
                    "Macros executing PowerShell",
                    "Document downloads from internet",
                    "Unusual file writes from Office apps",
                ],
            },
        }

        behaviors = []
        for technique in techniques:
            if technique in technique_behaviors:
                behaviors.append(technique_behaviors[technique])

        return behaviors

    def _calculate_confidence(
        self, indicators_by_level: Dict[str, List[str]], techniques: List[str]
    ) -> float:
        """Calculate confidence in the pyramid analysis."""
        confidence = 0.0

        # Higher confidence with TTPs
        if techniques:
            confidence += 0.5

        # Additional confidence for tools
        if indicators_by_level.get("tools"):
            confidence += 0.2

        # Additional confidence for artifacts
        if indicators_by_level.get("network_host_artifacts"):
            confidence += 0.15

        # Some confidence for lower-level indicators
        if any(
            indicators_by_level.get(level)
            for level in ["domain_names", "ip_addresses", "hash_values"]
        ):
            confidence += 0.15

        return min(confidence, 1.0)

    def get_level_info(self, level: PyramidLevel) -> Dict[str, str]:
        """Get information about a specific pyramid level."""
        return self.level_impact[level]
