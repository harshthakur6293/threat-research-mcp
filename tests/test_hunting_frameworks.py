"""
Tests for hunting frameworks (PEAK, TaHiTI, SQRRL, Pyramid of Pain, HEARTH).
"""

import pytest
from threat_research_mcp.frameworks.peak import PEAKFramework
from threat_research_mcp.frameworks.tahiti import TaHiTIFramework
from threat_research_mcp.frameworks.sqrrl import SQRRLFramework, HypothesisMaturityLevel
from threat_research_mcp.frameworks.pyramid_of_pain import PyramidOfPain, PyramidLevel
from threat_research_mcp.frameworks.hearth import HEARTHIntegration


class TestPEAKFramework:
    """Tests for PEAK framework."""

    def test_initialization(self):
        """Test PEAK framework initialization."""
        peak = PEAKFramework()
        assert peak.name == "PEAK"

    def test_create_hunt_plan(self):
        """Test creating a PEAK hunt plan."""
        peak = PEAKFramework()
        techniques = ["T1059.001", "T1071.001"]
        hypothesis = "Adversary using PowerShell for C2"

        plan = peak.create_hunt_plan(
            hypothesis=hypothesis,
            techniques=techniques,
            environment="aws",
            siem_platforms=["splunk"],
        )

        assert plan.hypothesis == hypothesis
        assert "prepare" in plan.to_dict()
        assert "execute" in plan.to_dict()
        assert "act" in plan.to_dict()
        assert plan.confidence > 0

    def test_prepare_phase(self):
        """Test PEAK prepare phase."""
        peak = PEAKFramework()
        techniques = ["T1059.001"]

        prepare = peak._prepare_phase("Test hypothesis", techniques, "on-prem")

        assert "hypothesis" in prepare
        assert "data_sources_required" in prepare
        assert "success_criteria" in prepare
        assert len(prepare["data_sources_required"]) > 0

    def test_execute_phase(self):
        """Test PEAK execute phase."""
        peak = PEAKFramework()
        techniques = ["T1059.001"]

        execute = peak._execute_phase(techniques, "hybrid", ["splunk", "sentinel"])

        assert "hunt_queries" in execute
        assert "splunk" in execute["hunt_queries"]
        assert "sentinel" in execute["hunt_queries"]
        assert "expected_behaviors" in execute


class TestTaHiTIFramework:
    """Tests for TaHiTI framework."""

    def test_initialization(self):
        """Test TaHiTI framework initialization."""
        tahiti = TaHiTIFramework()
        assert tahiti.name == "TaHiTI"

    def test_create_hunt_plan(self):
        """Test creating a TaHiTI hunt plan."""
        tahiti = TaHiTIFramework()
        threat_intel = {
            "techniques": ["T1059.001"],
            "actor": "APT29",
        }

        plan = tahiti.create_hunt_plan(
            threat_intel=threat_intel,
            techniques=["T1059.001"],
            environment="azure",
        )

        assert "threat_intel" in plan.to_dict()
        assert "targeting" in plan.to_dict()
        assert "analysis" in plan.to_dict()
        assert "hypothesis" in plan.to_dict()
        assert "investigation" in plan.to_dict()
        assert plan.confidence > 0


class TestSQRRLFramework:
    """Tests for SQRRL framework."""

    def test_initialization(self):
        """Test SQRRL framework initialization."""
        sqrrl = SQRRLFramework()
        assert sqrrl.name == "SQRRL"

    def test_create_hunt_plan(self):
        """Test creating a SQRRL hunt plan."""
        sqrrl = SQRRLFramework()
        techniques = ["T1059.001"]
        hypothesis = "PowerShell used for malicious activity"

        plan = sqrrl.create_hunt_plan(
            hypothesis=hypothesis,
            techniques=techniques,
        )

        assert plan.hypothesis == hypothesis
        assert isinstance(plan.maturity_level, HypothesisMaturityLevel)
        assert "create" in plan.to_dict()
        assert "investigate" in plan.to_dict()
        assert "inform" in plan.to_dict()

    def test_maturity_levels(self):
        """Test hypothesis maturity levels."""
        levels = list(HypothesisMaturityLevel)
        assert len(levels) == 5
        assert HypothesisMaturityLevel.HMM0 in levels
        assert HypothesisMaturityLevel.HMM4 in levels


class TestPyramidOfPain:
    """Tests for Pyramid of Pain framework."""

    def test_initialization(self):
        """Test Pyramid of Pain initialization."""
        pyramid = PyramidOfPain()
        assert pyramid.name == "Pyramid of Pain"
        assert len(pyramid.level_impact) == 6

    def test_analyze_indicators(self):
        """Test analyzing indicators."""
        pyramid = PyramidOfPain()
        iocs = {
            "ip": ["1.2.3.4"],
            "domain": ["evil.com"],
            "hash_md5": ["abc123"],
        }
        techniques = ["T1059.001", "T1071.001"]

        analysis = pyramid.analyze_indicators(iocs, techniques)

        assert analysis.focus_level == PyramidLevel.TTPS
        assert "indicators_by_level" in analysis.to_dict()
        assert "behavioral_focus" in analysis.to_dict()
        assert analysis.confidence > 0

    def test_determine_focus_level(self):
        """Test determining focus level."""
        pyramid = PyramidOfPain()

        # With TTPs
        indicators = {"ttps": ["T1059.001"]}
        focus = pyramid._determine_focus_level(indicators, ["T1059.001"])
        assert focus == PyramidLevel.TTPS

        # Without TTPs
        indicators = {"ip_addresses": ["1.2.3.4"]}
        focus = pyramid._determine_focus_level(indicators, [])
        assert focus == PyramidLevel.IP_ADDRESSES

    def test_behavioral_focus_generation(self):
        """Test behavioral focus generation."""
        pyramid = PyramidOfPain()
        techniques = ["T1059.001"]

        behavioral_focus = pyramid._generate_behavioral_focus(techniques, PyramidLevel.TTPS)

        assert "recommended_level" in behavioral_focus
        assert "hunt_strategies" in behavioral_focus
        assert "detection_priorities" in behavioral_focus
        assert len(behavioral_focus["hunt_strategies"]) > 0


class TestHEARTHIntegration:
    """Tests for HEARTH integration."""

    def test_initialization(self):
        """Test HEARTH integration initialization."""
        hearth = HEARTHIntegration()
        assert hearth.name == "HEARTH"
        assert len(hearth.community_hunts) > 0

    def test_search_by_technique(self):
        """Test searching community hunts by technique."""
        hearth = HEARTHIntegration()
        hunts = hearth.search_by_technique("T1059.001")

        assert len(hunts) > 0
        assert all("T1059.001" in hunt.techniques for hunt in hunts)

    def test_search_by_tag(self):
        """Test searching community hunts by tag."""
        hearth = HEARTHIntegration()
        hunts = hearth.search_by_tag("powershell")

        assert len(hunts) > 0
        assert all("powershell" in [t.lower() for t in hunt.tags] for hunt in hunts)

    def test_search_by_keyword(self):
        """Test searching community hunts by keyword."""
        hearth = HEARTHIntegration()
        hunts = hearth.search_by_keyword("PowerShell")

        assert len(hunts) > 0

    def test_adapt_hunt_to_environment(self):
        """Test adapting hunt to environment."""
        hearth = HEARTHIntegration()
        hunt = hearth.community_hunts[0]

        adapted = hearth.adapt_hunt_to_environment(hunt, "splunk", "aws")

        assert adapted["target_platform"] == "splunk"
        assert adapted["environment"] == "aws"
        assert "adapted_queries" in adapted
        assert "additional_data_sources" in adapted

    def test_contribute_hunt(self):
        """Test contributing a new hunt."""
        hearth = HEARTHIntegration()
        initial_count = len(hearth.community_hunts)

        new_hunt = hearth.contribute_hunt(
            name="Test Hunt",
            description="Test description",
            hypothesis="Test hypothesis",
            techniques=["T1059.001"],
            data_sources=["Windows Event Logs"],
            queries={"splunk": ["index=windows"]},
            tags=["test"],
        )

        assert len(hearth.community_hunts) == initial_count + 1
        assert new_hunt.name == "Test Hunt"
        assert new_hunt.author == "User"

    def test_get_hunt_by_id(self):
        """Test getting hunt by ID."""
        hearth = HEARTHIntegration()
        hunt = hearth.get_hunt_by_id("hunt-001")

        assert hunt is not None
        assert hunt.id == "hunt-001"

        # Test non-existent ID
        hunt = hearth.get_hunt_by_id("hunt-999")
        assert hunt is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
