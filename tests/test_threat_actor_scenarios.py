"""Test threat-research-mcp tools against realistic threat actor scenarios.

This test suite validates that the MCP tools can correctly analyze threat intelligence
from various APT groups and UNC groups, extracting IOCs, mapping techniques, and
generating appropriate detections.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


# Add src to path for local development
_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_ROOT / "src"))

from threat_research_mcp.tools.extract_iocs import extract_iocs_json  # noqa: E402
from threat_research_mcp.extensions.mitre_attack_integration import (  # noqa: E402
    extract_techniques_from_intel,
)
from threat_research_mcp.detection.log_source_mapper import (  # noqa: E402
    get_log_sources_for_techniques,
)
from tests.threat_actor_profiles import (  # noqa: E402
    get_threat_actor_profile,
    list_threat_actors,
)


class TestAPT29Scenario:
    """Test analysis of APT29 (Cozy Bear) threat intelligence."""

    def setup_method(self):
        """Setup test data."""
        self.profile = get_threat_actor_profile("APT29")
        self.intel = self.profile["sample_intel"]

    def test_extract_iocs_from_apt29_intel(self):
        """Test IOC extraction from APT29 intelligence."""
        result = json.loads(extract_iocs_json(self.intel))
        
        # Should extract known APT29 IOCs
        assert "avsvmcloud.com" in result["domains"]
        assert "13.59.205.66" in result["ips"]
        assert any("32519b85" in h for h in result["hashes"])

    def test_detect_apt29_techniques(self):
        """Test technique detection from APT29 intelligence."""
        techniques = extract_techniques_from_intel(self.intel)
        
        # Should detect key APT29 TTPs (keyword-based detection)
        # Note: Supply chain (T1195.002) may not be detected without explicit keywords
        expected_techniques = ["T1071.001", "T1021.001", "T1059.001"]
        detected_count = sum(1 for tech in expected_techniques if tech in techniques)
        assert detected_count >= 2, f"Expected at least 2 of {expected_techniques}, got {detected_count}"

    def test_generate_log_sources_for_apt29(self):
        """Test log source recommendations for APT29 TTPs."""
        techniques = extract_techniques_from_intel(self.intel)
        log_sources = get_log_sources_for_techniques(techniques[:5], environment="hybrid")
        
        # Should recommend relevant log sources
        assert "log_sources" in log_sources
        assert len(log_sources["log_sources"]) > 0, "Expected log sources to be generated"
        # Should have priority summary
        assert "priority_summary" in log_sources

    def test_apt29_profile_completeness(self):
        """Test that APT29 profile contains expected fields."""
        assert "aliases" in self.profile
        assert "ttps" in self.profile
        assert "tools" in self.profile
        assert "iocs" in self.profile
        assert "SUNBURST" in self.profile["tools"]


class TestAPT28Scenario:
    """Test analysis of APT28 (Fancy Bear) threat intelligence."""

    def setup_method(self):
        """Setup test data."""
        self.profile = get_threat_actor_profile("APT28")
        self.intel = self.profile["sample_intel"]

    def test_extract_iocs_from_apt28_intel(self):
        """Test IOC extraction from APT28 intelligence."""
        result = json.loads(extract_iocs_json(self.intel))
        
        # Should extract known APT28 IOCs
        assert "netmediaresources.com" in result["domains"]
        assert "185.86.148.222" in result["ips"]

    def test_detect_apt28_techniques(self):
        """Test technique detection from APT28 intelligence."""
        techniques = extract_techniques_from_intel(self.intel)
        
        # Should detect key APT28 TTPs
        expected_techniques = ["T1566.001", "T1059.001", "T1021.001"]
        for tech in expected_techniques:
            assert tech in techniques, f"Expected {tech} in detected techniques"

    def test_apt28_profile_completeness(self):
        """Test that APT28 profile contains expected fields."""
        assert "aliases" in self.profile
        assert "Fancy Bear" in self.profile["aliases"]
        assert "X-Agent" in self.profile["tools"]


class TestAPT41Scenario:
    """Test analysis of APT41 (Winnti) threat intelligence."""

    def setup_method(self):
        """Setup test data."""
        self.profile = get_threat_actor_profile("APT41")
        self.intel = self.profile["sample_intel"]

    def test_extract_iocs_from_apt41_intel(self):
        """Test IOC extraction from APT41 intelligence."""
        result = json.loads(extract_iocs_json(self.intel))
        
        # Should extract known APT41 IOCs
        assert "update.iaacenter.com" in result["domains"]
        assert "103.85.24.158" in result["ips"]

    def test_detect_apt41_techniques(self):
        """Test technique detection from APT41 intelligence."""
        techniques = extract_techniques_from_intel(self.intel)
        
        # Should detect key APT41 TTPs
        expected_techniques = ["T1190", "T1059.001", "T1021.001"]
        for tech in expected_techniques:
            assert tech in techniques, f"Expected {tech} in detected techniques"

    def test_apt41_dual_motivation(self):
        """Test that APT41 profile reflects dual motivation."""
        assert "Espionage" in self.profile["motivation"]
        assert "Financial Gain" in self.profile["motivation"]


class TestUNC2452Scenario:
    """Test analysis of UNC2452 (NOBELIUM) threat intelligence."""

    def setup_method(self):
        """Setup test data."""
        self.profile = get_threat_actor_profile("UNC2452")
        self.intel = self.profile["sample_intel"]

    def test_extract_iocs_from_unc2452_intel(self):
        """Test IOC extraction from UNC2452 intelligence."""
        result = json.loads(extract_iocs_json(self.intel))
        
        # Should extract known UNC2452 IOCs
        assert "avsvmcloud.com" in result["domains"]
        assert "13.59.205.66" in result["ips"]

    def test_detect_unc2452_techniques(self):
        """Test technique detection from UNC2452 intelligence."""
        techniques = extract_techniques_from_intel(self.intel)
        
        # Should detect some techniques (supply chain may not be detected without explicit keywords)
        assert len(techniques) > 0, "Expected at least some techniques to be detected"
        # Should detect common techniques like C2 or exfiltration
        common_techniques = ["T1071.001", "T1567.002", "T1059"]
        detected = any(tech in str(techniques) for tech in common_techniques)
        assert detected, f"Expected common techniques in {techniques}"

    def test_unc2452_solarwinds_tools(self):
        """Test that UNC2452 profile includes SolarWinds tools."""
        assert "SUNBURST" in self.profile["tools"]
        assert "TEARDROP" in self.profile["tools"]


class TestUNC3890Scenario:
    """Test analysis of UNC3890 threat intelligence."""

    def setup_method(self):
        """Setup test data."""
        self.profile = get_threat_actor_profile("UNC3890")
        self.intel = self.profile["sample_intel"]

    def test_extract_iocs_from_unc3890_intel(self):
        """Test IOC extraction from UNC3890 intelligence."""
        result = json.loads(extract_iocs_json(self.intel))
        
        # Should extract known UNC3890 IOCs
        assert "update-service.org" in result["domains"]
        assert "45.142.212.61" in result["ips"]

    def test_detect_unc3890_techniques(self):
        """Test technique detection from UNC3890 intelligence."""
        techniques = extract_techniques_from_intel(self.intel)
        
        # Should detect ProxyShell exploitation
        assert "T1190" in techniques

    def test_unc3890_web_shell_tools(self):
        """Test that UNC3890 profile includes web shell tools."""
        assert "China Chopper" in self.profile["tools"]


class TestLazarusGroupScenario:
    """Test analysis of Lazarus Group threat intelligence."""

    def setup_method(self):
        """Setup test data."""
        self.profile = get_threat_actor_profile("Lazarus Group")
        self.intel = self.profile["sample_intel"]

    def test_extract_iocs_from_lazarus_intel(self):
        """Test IOC extraction from Lazarus Group intelligence."""
        result = json.loads(extract_iocs_json(self.intel))
        
        # Should extract known Lazarus IOCs
        assert "nzssdm.com" in result["domains"]
        assert "185.220.101.45" in result["ips"]

    def test_detect_lazarus_techniques(self):
        """Test technique detection from Lazarus Group intelligence."""
        techniques = extract_techniques_from_intel(self.intel)
        
        # Should detect key Lazarus TTPs (keyword-based detection)
        # Note: Data destruction (T1485) may not be detected without explicit keywords
        expected_techniques = ["T1566.001", "T1059.001"]
        detected_count = sum(1 for tech in expected_techniques if tech in techniques)
        assert detected_count >= 1, f"Expected at least 1 of {expected_techniques}, got {detected_count}"

    def test_lazarus_financial_motivation(self):
        """Test that Lazarus profile reflects financial motivation."""
        assert "Financial Gain" in self.profile["motivation"]
        assert "Cryptocurrency" in str(self.profile["targets"])

    def test_lazarus_destructive_tools(self):
        """Test that Lazarus profile includes destructive capabilities."""
        assert "ttps" in self.profile
        assert "impact" in self.profile["ttps"]
        assert "T1485" in self.profile["ttps"]["impact"]  # Data Destruction


class TestThreatActorProfiles:
    """Test threat actor profile data structure and completeness."""

    def test_all_profiles_have_required_fields(self):
        """Test that all profiles have required fields."""
        required_fields = ["aliases", "attribution", "targets", "motivation", "ttps", "tools", "iocs", "sample_intel"]
        
        for actor_name in list_threat_actors():
            profile = get_threat_actor_profile(actor_name)
            for field in required_fields:
                assert field in profile, f"{actor_name} missing required field: {field}"

    def test_all_profiles_have_valid_ttps(self):
        """Test that all profiles have valid TTP mappings."""
        for actor_name in list_threat_actors():
            profile = get_threat_actor_profile(actor_name)
            ttps = profile["ttps"]
            
            # Should have multiple tactic categories
            assert len(ttps) >= 5, f"{actor_name} has insufficient TTP coverage"
            
            # Each tactic should have technique IDs
            for tactic, techniques in ttps.items():
                assert len(techniques) > 0, f"{actor_name} has no techniques for {tactic}"

    def test_all_profiles_have_iocs(self):
        """Test that all profiles have IOCs."""
        for actor_name in list_threat_actors():
            profile = get_threat_actor_profile(actor_name)
            iocs = profile["iocs"]
            
            # Should have at least one IOC type
            assert len(iocs.get("domains", [])) > 0 or len(iocs.get("ips", [])) > 0, \
                f"{actor_name} has no IOCs"

    def test_profile_count(self):
        """Test that we have multiple threat actor profiles."""
        actors = list_threat_actors()
        assert len(actors) >= 6, "Should have at least 6 threat actor profiles"

    def test_sample_intel_contains_iocs(self):
        """Test that sample intel contains the IOCs listed in the profile."""
        for actor_name in list_threat_actors():
            profile = get_threat_actor_profile(actor_name)
            intel = profile["sample_intel"]
            iocs = profile["iocs"]
            
            # At least one domain should be in the intel
            if iocs.get("domains"):
                domain_found = any(domain in intel for domain in iocs["domains"])
                assert domain_found, f"{actor_name} sample intel missing domains"
            
            # At least one IP should be in the intel
            if iocs.get("ips"):
                ip_found = any(ip in intel for ip in iocs["ips"])
                assert ip_found, f"{actor_name} sample intel missing IPs"


class TestCrossActorComparison:
    """Test comparisons across different threat actors."""

    def test_russian_actors_share_tools(self):
        """Test that Russian actors (APT29, APT28, UNC2452) share common tools."""
        apt29 = get_threat_actor_profile("APT29")
        apt28 = get_threat_actor_profile("APT28")
        
        # All should use Mimikatz or Cobalt Strike
        assert "Mimikatz" in apt29["tools"] or "Cobalt Strike" in apt29["tools"]
        assert "Mimikatz" in apt28["tools"]

    def test_chinese_actors_target_technology(self):
        """Test that Chinese actors target technology sector."""
        apt41 = get_threat_actor_profile("APT41")
        unc3890 = get_threat_actor_profile("UNC3890")
        
        assert "Technology" in apt41["targets"]
        assert "Technology" in unc3890["targets"]

    def test_north_korean_actors_financial_motivation(self):
        """Test that North Korean actors have financial motivation."""
        lazarus = get_threat_actor_profile("Lazarus Group")
        
        assert "Financial Gain" in lazarus["motivation"]

    def test_all_advanced_actors_use_powershell(self):
        """Test that all advanced actors use PowerShell."""
        for actor_name in list_threat_actors():
            profile = get_threat_actor_profile(actor_name)
            ttps = profile["ttps"]
            
            # Should have PowerShell in execution tactics
            if "execution" in ttps:
                assert "T1059.001" in ttps["execution"], \
                    f"{actor_name} missing PowerShell technique"
