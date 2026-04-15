"""
Tests for Hunting Agent v2.
"""

import pytest
from threat_research_mcp.agents.hunting_agent_v2 import HuntingAgentV2
from threat_research_mcp.schemas.workflow_state import create_initial_state


class TestHuntingAgentV2:
    """Tests for Hunting Agent v2."""

    def test_initialization(self):
        """Test Hunting Agent v2 initialization."""
        agent = HuntingAgentV2()
        assert agent.name == "Hunting Agent v2"
        assert agent.peak is not None
        assert agent.tahiti is not None
        assert agent.sqrrl is not None
        assert agent.pyramid is not None
        assert agent.hearth is not None

    def test_execute_with_peak_framework(self):
        """Test executing with PEAK framework."""
        agent = HuntingAgentV2()

        # Create state with research findings
        state = create_initial_state(
            intel_text="APT29 using PowerShell for C2",
            framework="PEAK",
            environment="aws",
            target_platforms=["splunk"],
        )

        # Add research findings
        state["research_findings"] = {
            "agent": "Research Agent v2",
            "findings": {
                "iocs": [
                    {"value": "1.2.3.4", "type": "ip", "confidence": 0.8},
                ],
                "techniques": [
                    {"technique_id": "T1059.001", "name": "PowerShell"},
                ],
            },
            "confidence": 0.8,
        }

        result = agent.execute(state)

        assert "hunt_plan" in result
        assert "agent_history" in result

        hunt_plan = result["hunt_plan"]
        assert hunt_plan["confidence"] > 0
        assert "findings" in hunt_plan

        findings = hunt_plan["findings"]
        assert findings["framework"] == "PEAK"
        assert "framework_plan" in findings
        assert "pyramid_analysis" in findings
        assert "community_hunts" in findings

    def test_execute_with_tahiti_framework(self):
        """Test executing with TaHiTI framework."""
        agent = HuntingAgentV2()

        state = create_initial_state(
            intel_text="APT29 using PowerShell",
            framework="TaHiTI",
            environment="azure",
        )

        state["research_findings"] = {
            "findings": {
                "iocs": [],
                "techniques": [{"technique_id": "T1059.001", "name": "PowerShell"}],
            },
            "confidence": 0.8,
        }

        result = agent.execute(state)

        assert "hunt_plan" in result
        findings = result["hunt_plan"]["findings"]
        assert findings["framework"] == "TaHiTI"

    def test_execute_with_sqrrl_framework(self):
        """Test executing with SQRRL framework."""
        agent = HuntingAgentV2()

        state = create_initial_state(
            intel_text="PowerShell activity",
            framework="SQRRL",
        )

        state["research_findings"] = {
            "findings": {
                "iocs": [],
                "techniques": [{"technique_id": "T1059.001", "name": "PowerShell"}],
            },
            "confidence": 0.8,
        }

        result = agent.execute(state)

        assert "hunt_plan" in result
        findings = result["hunt_plan"]["findings"]
        assert findings["framework"] == "SQRRL"

    def test_execute_with_no_techniques(self):
        """Test executing with no techniques (should use defaults)."""
        agent = HuntingAgentV2()

        state = create_initial_state(intel_text="Generic threat intelligence")

        state["research_findings"] = {
            "findings": {
                "iocs": [],
                "techniques": [],
            },
            "confidence": 0.5,
        }

        result = agent.execute(state)

        assert "hunt_plan" in result
        # Should still generate a plan with default technique

    def test_pyramid_analysis_integration(self):
        """Test Pyramid of Pain analysis integration."""
        agent = HuntingAgentV2()

        state = create_initial_state(intel_text="Threat with multiple IOCs")

        state["research_findings"] = {
            "findings": {
                "iocs": [
                    {"value": "1.2.3.4", "type": "ip", "confidence": 0.8},
                    {"value": "evil.com", "type": "domain", "confidence": 0.9},
                    {"value": "abc123", "type": "hash_md5", "confidence": 0.7},
                ],
                "techniques": [
                    {"technique_id": "T1059.001", "name": "PowerShell"},
                    {"technique_id": "T1071.001", "name": "Web Protocols"},
                ],
            },
            "confidence": 0.8,
        }

        result = agent.execute(state)

        findings = result["hunt_plan"]["findings"]
        pyramid_analysis = findings["pyramid_analysis"]

        assert "focus_level" in pyramid_analysis
        assert "behavioral_focus" in pyramid_analysis
        assert pyramid_analysis["focus_level"] == "ttps"  # Should focus on TTPs

    def test_community_hunts_integration(self):
        """Test HEARTH community hunts integration."""
        agent = HuntingAgentV2()

        state = create_initial_state(intel_text="PowerShell threat")

        state["research_findings"] = {
            "findings": {
                "iocs": [],
                "techniques": [{"technique_id": "T1059.001", "name": "PowerShell"}],
            },
            "confidence": 0.8,
        }

        result = agent.execute(state)

        findings = result["hunt_plan"]["findings"]
        community_hunts = findings["community_hunts"]

        assert len(community_hunts) > 0
        # Should find community hunts for PowerShell

    def test_hunt_summary_generation(self):
        """Test hunt summary generation."""
        agent = HuntingAgentV2()

        state = create_initial_state(intel_text="Threat intelligence")

        state["research_findings"] = {
            "findings": {
                "iocs": [],
                "techniques": [{"technique_id": "T1059.001", "name": "PowerShell"}],
            },
            "confidence": 0.8,
        }

        result = agent.execute(state)

        findings = result["hunt_plan"]["findings"]
        hunt_summary = findings["hunt_summary"]

        assert "framework_used" in hunt_summary
        assert "hypothesis" in hunt_summary
        assert "behavioral_focus" in hunt_summary
        assert "hunt_strategies" in hunt_summary
        assert "recommended_approach" in hunt_summary

    def test_confidence_calculation(self):
        """Test confidence calculation."""
        agent = HuntingAgentV2()

        state = create_initial_state(intel_text="Threat")

        state["research_findings"] = {
            "findings": {
                "iocs": [],
                "techniques": [{"technique_id": "T1059.001", "name": "PowerShell"}],
            },
            "confidence": 0.8,
        }

        result = agent.execute(state)

        hunt_plan = result["hunt_plan"]
        assert 0 <= hunt_plan["confidence"] <= 1.0

    def test_missing_required_fields(self):
        """Test error handling for missing required fields."""
        agent = HuntingAgentV2()

        state = create_initial_state(intel_text="Test")
        # Missing research_findings

        with pytest.raises(ValueError, match="missing required fields"):
            agent.execute(state)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
