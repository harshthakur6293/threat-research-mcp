"""
Tests for Detection Agent v2.
"""

import pytest
from threat_research_mcp.agents.detection_agent_v2 import DetectionAgentV2
from threat_research_mcp.schemas.workflow_state import create_initial_state


class TestDetectionAgentV2:
    """Tests for Detection Agent v2."""

    def test_initialization(self):
        """Test Detection Agent v2 initialization."""
        agent = DetectionAgentV2()
        assert agent.name == "Detection Agent v2"
        assert agent.sigma_generator is not None
        assert agent.kql_generator is not None
        assert agent.spl_generator is not None
        assert agent.eql_generator is not None
        assert agent.sigma_validator is not None

    def test_execute_with_splunk_platform(self):
        """Test executing with Splunk platform."""
        agent = DetectionAgentV2()

        state = create_initial_state(
            intel_text="PowerShell threat",
            target_platforms=["splunk"],
        )

        state["research_findings"] = {
            "findings": {
                "iocs": [],
                "techniques": [{"technique_id": "T1059.001", "name": "PowerShell"}],
            },
            "confidence": 0.8,
        }

        state["hunt_plan"] = {
            "findings": {
                "framework": "PEAK",
                "pyramid_analysis": {"behavioral_focus": {"focus_level": "ttps"}},
            },
            "confidence": 0.8,
        }

        result = agent.execute(state)

        assert "detections" in result
        assert "agent_history" in result

        detections = result["detections"]
        assert detections["confidence"] > 0

        findings = detections["findings"]
        assert "detections" in findings
        assert "sigma" in findings["detections"]  # Always generate Sigma
        assert "spl" in findings["detections"]  # Splunk platform

    def test_execute_with_sentinel_platform(self):
        """Test executing with Azure Sentinel platform."""
        agent = DetectionAgentV2()

        state = create_initial_state(
            intel_text="PowerShell threat",
            target_platforms=["sentinel"],
        )

        state["research_findings"] = {
            "findings": {
                "iocs": [],
                "techniques": [{"technique_id": "T1059.001", "name": "PowerShell"}],
            },
            "confidence": 0.8,
        }

        state["hunt_plan"] = {
            "findings": {
                "framework": "PEAK",
                "pyramid_analysis": {"behavioral_focus": {}},
            },
            "confidence": 0.8,
        }

        result = agent.execute(state)

        findings = result["detections"]["findings"]
        assert "kql" in findings["detections"]  # Sentinel platform

    def test_execute_with_elastic_platform(self):
        """Test executing with Elastic platform."""
        agent = DetectionAgentV2()

        state = create_initial_state(
            intel_text="PowerShell threat",
            target_platforms=["elastic"],
        )

        state["research_findings"] = {
            "findings": {
                "iocs": [],
                "techniques": [{"technique_id": "T1059.001", "name": "PowerShell"}],
            },
            "confidence": 0.8,
        }

        state["hunt_plan"] = {
            "findings": {
                "framework": "PEAK",
                "pyramid_analysis": {"behavioral_focus": {}},
            },
            "confidence": 0.8,
        }

        result = agent.execute(state)

        findings = result["detections"]["findings"]
        assert "eql" in findings["detections"]  # Elastic platform

    def test_execute_with_multiple_platforms(self):
        """Test executing with multiple platforms."""
        agent = DetectionAgentV2()

        state = create_initial_state(
            intel_text="PowerShell threat",
            target_platforms=["splunk", "sentinel", "elastic"],
        )

        state["research_findings"] = {
            "findings": {
                "iocs": [],
                "techniques": [{"technique_id": "T1059.001", "name": "PowerShell"}],
            },
            "confidence": 0.8,
        }

        state["hunt_plan"] = {
            "findings": {
                "framework": "PEAK",
                "pyramid_analysis": {"behavioral_focus": {}},
            },
            "confidence": 0.8,
        }

        result = agent.execute(state)

        findings = result["detections"]["findings"]
        detections = findings["detections"]

        assert "sigma" in detections
        assert "kql" in detections
        assert "spl" in detections
        assert "eql" in detections

    def test_execute_with_multiple_techniques(self):
        """Test executing with multiple techniques."""
        agent = DetectionAgentV2()

        state = create_initial_state(
            intel_text="Multiple threats",
            target_platforms=["splunk"],
        )

        state["research_findings"] = {
            "findings": {
                "iocs": [],
                "techniques": [
                    {"technique_id": "T1059.001", "name": "PowerShell"},
                    {"technique_id": "T1003.001", "name": "LSASS Memory"},
                    {"technique_id": "T1071.001", "name": "Web Protocols"},
                ],
            },
            "confidence": 0.8,
        }

        state["hunt_plan"] = {
            "findings": {
                "framework": "PEAK",
                "pyramid_analysis": {"behavioral_focus": {}},
            },
            "confidence": 0.8,
        }

        result = agent.execute(state)

        findings = result["detections"]["findings"]
        sigma_rules = findings["detections"]["sigma"]["rules"]

        assert len(sigma_rules) == 3  # One rule per technique

    def test_validation_integration(self):
        """Test rule validation integration."""
        agent = DetectionAgentV2()

        state = create_initial_state(
            intel_text="PowerShell threat",
            target_platforms=["splunk"],
        )

        state["research_findings"] = {
            "findings": {
                "iocs": [],
                "techniques": [{"technique_id": "T1059.001", "name": "PowerShell"}],
            },
            "confidence": 0.8,
        }

        state["hunt_plan"] = {
            "findings": {
                "framework": "PEAK",
                "pyramid_analysis": {"behavioral_focus": {}},
            },
            "confidence": 0.8,
        }

        result = agent.execute(state)

        findings = result["detections"]["findings"]
        validation_results = findings["validation_results"]

        assert "sigma" in validation_results
        assert "spl" in validation_results

        sigma_validation = validation_results["sigma"]
        assert "total_rules" in sigma_validation
        assert "valid_rules" in sigma_validation
        assert "invalid_rules" in sigma_validation

    def test_tuning_recommendations(self):
        """Test tuning recommendations generation."""
        agent = DetectionAgentV2()

        state = create_initial_state(
            intel_text="PowerShell threat",
            target_platforms=["splunk"],
        )

        state["research_findings"] = {
            "findings": {
                "iocs": [],
                "techniques": [{"technique_id": "T1059.001", "name": "PowerShell"}],
            },
            "confidence": 0.8,
        }

        state["hunt_plan"] = {
            "findings": {
                "framework": "PEAK",
                "pyramid_analysis": {
                    "behavioral_focus": {"focus_level": "ttps"},
                },
            },
            "confidence": 0.8,
        }

        result = agent.execute(state)

        findings = result["detections"]["findings"]
        tuning_recommendations = findings["tuning_recommendations"]

        assert len(tuning_recommendations) > 0
        assert all("category" in r for r in tuning_recommendations)
        assert all("recommendation" in r for r in tuning_recommendations)
        assert all("rationale" in r for r in tuning_recommendations)

    def test_detection_summary(self):
        """Test detection summary generation."""
        agent = DetectionAgentV2()

        state = create_initial_state(
            intel_text="PowerShell threat",
            target_platforms=["splunk"],
        )

        state["research_findings"] = {
            "findings": {
                "iocs": [],
                "techniques": [{"technique_id": "T1059.001", "name": "PowerShell"}],
            },
            "confidence": 0.8,
        }

        state["hunt_plan"] = {
            "findings": {
                "framework": "PEAK",
                "pyramid_analysis": {"behavioral_focus": {}},
            },
            "confidence": 0.8,
        }

        result = agent.execute(state)

        findings = result["detections"]["findings"]
        summary = findings["summary"]

        assert "total_rules_generated" in summary
        assert "total_valid_rules" in summary
        assert "formats" in summary
        assert "validation_pass_rate" in summary

    def test_execute_with_no_techniques(self):
        """Test executing with no techniques (should use defaults)."""
        agent = DetectionAgentV2()

        state = create_initial_state(
            intel_text="Generic threat",
            target_platforms=["splunk"],
        )

        state["research_findings"] = {
            "findings": {
                "iocs": [],
                "techniques": [],
            },
            "confidence": 0.5,
        }

        state["hunt_plan"] = {
            "findings": {
                "framework": "PEAK",
                "pyramid_analysis": {"behavioral_focus": {}},
            },
            "confidence": 0.5,
        }

        result = agent.execute(state)

        assert "detections" in result
        # Should still generate rules with default technique

    def test_confidence_calculation(self):
        """Test confidence calculation."""
        agent = DetectionAgentV2()

        state = create_initial_state(
            intel_text="PowerShell threat",
            target_platforms=["splunk", "sentinel"],
        )

        state["research_findings"] = {
            "findings": {
                "iocs": [],
                "techniques": [{"technique_id": "T1059.001", "name": "PowerShell"}],
            },
            "confidence": 0.8,
        }

        state["hunt_plan"] = {
            "findings": {
                "framework": "PEAK",
                "pyramid_analysis": {"behavioral_focus": {}},
            },
            "confidence": 0.8,
        }

        result = agent.execute(state)

        detections = result["detections"]
        assert 0 <= detections["confidence"] <= 1.0

    def test_missing_required_fields(self):
        """Test error handling for missing required fields."""
        agent = DetectionAgentV2()

        state = create_initial_state(intel_text="Test")
        # Missing research_findings and hunt_plan

        with pytest.raises(ValueError, match="missing required fields"):
            agent.execute(state)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
