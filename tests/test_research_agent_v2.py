"""
Tests for Research Agent v2.

This module tests the Research Agent v2 with multi-source enrichment.
"""

import pytest

from threat_research_mcp.agents.research_agent_v2 import ResearchAgentV2
from threat_research_mcp.schemas.workflow_state import create_initial_state


class TestResearchAgentV2:
    """Tests for Research Agent v2."""
    
    def test_agent_initialization(self):
        """Test agent initializes correctly."""
        agent = ResearchAgentV2()
        
        assert agent.name == "Research Agent v2"
        assert agent.enrichment_manager is not None
        assert agent.confidence_scorer is not None
    
    def test_agent_with_api_keys(self):
        """Test agent initialization with API keys."""
        api_keys = {
            "VirusTotal": "test_key",
            "Shodan": "test_key",
        }
        
        agent = ResearchAgentV2(api_keys=api_keys)
        
        # Check that API keys were set
        vt_source = agent.enrichment_manager.sources.get("VirusTotal")
        assert vt_source is not None
        assert vt_source.has_api_key()
    
    def test_extract_iocs(self):
        """Test IOC extraction."""
        agent = ResearchAgentV2()
        
        text = """
        APT29 campaign detected using PowerShell.
        IOCs:
        - IP: 185.220.101.45
        - Domain: malicious-c2.com
        - Hash: 1234567890abcdef1234567890abcdef
        """
        
        iocs = agent._extract_iocs(text)
        
        assert len(iocs) > 0
        # Should extract IP
        from threat_research_mcp.enrichment.base import IOCType
        if IOCType.IP in iocs:
            assert "185.220.101.45" in iocs[IOCType.IP]
    
    def test_extract_techniques(self):
        """Test ATT&CK technique extraction."""
        agent = ResearchAgentV2()
        
        text = """
        Observed techniques:
        - T1059.001 (PowerShell)
        - T1071.001 (Web Protocols)
        """
        
        techniques = agent._extract_techniques(text)
        
        assert len(techniques) > 0
        technique_ids = [t["technique_id"] for t in techniques]
        assert "T1059.001" in technique_ids
    
    def test_execute_with_simple_intel(self):
        """Test agent execution with simple intelligence."""
        agent = ResearchAgentV2()
        
        state = create_initial_state(
            intel_text="""
            APT29 campaign using PowerShell for initial access.
            IP: 185.220.101.45
            Technique: T1059.001
            """
        )
        
        result = agent.execute(state)
        
        # Check that research findings were created
        assert "research_findings" in result
        findings = result["research_findings"]
        
        assert "findings" in findings
        assert "iocs" in findings["findings"]
        assert "techniques" in findings["findings"]
        assert "confidence" in findings
    
    def test_execute_with_multiple_iocs(self):
        """Test agent execution with multiple IOCs."""
        agent = ResearchAgentV2()
        
        state = create_initial_state(
            intel_text="""
            Multiple IOCs detected:
            - 185.220.101.45
            - 192.168.1.100
            - malicious-c2.com
            - http://evil.com/payload.exe
            """
        )
        
        result = agent.execute(state)
        
        findings = result["research_findings"]["findings"]
        assert len(findings["iocs"]) > 0
        
        # Check enrichment summary
        summary = findings["enrichment_summary"]
        assert "total_iocs" in summary
        assert summary["total_iocs"] > 0
    
    def test_execute_with_api_keys_in_state(self):
        """Test agent execution with API keys from state."""
        agent = ResearchAgentV2()
        
        state = create_initial_state(
            intel_text="IP: 185.220.101.45",
            api_keys={
                "VirusTotal": "test_key",
                "AbuseIPDB": "test_key",
            }
        )
        
        result = agent.execute(state)
        
        # Check that enrichment was performed
        findings = result["research_findings"]["findings"]
        assert "enrichment_summary" in findings
    
    def test_confidence_scoring(self):
        """Test that confidence scoring is applied."""
        agent = ResearchAgentV2()
        
        state = create_initial_state(
            intel_text="Malicious IP: 185.220.101.45"
        )
        
        result = agent.execute(state)
        
        findings = result["research_findings"]
        
        # Check overall confidence
        assert "confidence" in findings
        assert 0.0 <= findings["confidence"] <= 1.0
        
        # Check confidence analysis
        confidence_analysis = findings["findings"]["confidence_analysis"]
        assert "overall_confidence" in confidence_analysis
        assert "factors" in confidence_analysis
    
    def test_enrichment_with_multiple_sources(self):
        """Test that multiple sources are used for enrichment."""
        agent = ResearchAgentV2()
        
        state = create_initial_state(
            intel_text="IP: 185.220.101.45"
        )
        
        result = agent.execute(state)
        
        findings = result["research_findings"]["findings"]
        
        # Check that multiple sources enriched the IOC
        if findings["iocs"]:
            first_ioc = findings["iocs"][0]
            assert "enrichment_data" in first_ioc
            # Should have multiple sources (Tier 1 sources)
            assert first_ioc["enrichment_count"] > 0
    
    def test_agent_history_tracking(self):
        """Test that agent execution is tracked in history."""
        agent = ResearchAgentV2()
        
        state = create_initial_state(intel_text="Test")
        result = agent.execute(state)
        
        assert "agent_history" in result
        assert "Research Agent v2" in result["agent_history"]
    
    def test_empty_intel_text(self):
        """Test agent with empty intelligence text."""
        agent = ResearchAgentV2()
        
        # Empty text will fail validation, so use minimal text instead
        state = create_initial_state(intel_text=" ")
        result = agent.execute(state)
        
        # Should still complete without errors
        assert "research_findings" in result
        findings = result["research_findings"]["findings"]
        assert "iocs" in findings
        assert len(findings["iocs"]) == 0
    
    def test_intel_with_no_iocs(self):
        """Test agent with intelligence containing no IOCs."""
        agent = ResearchAgentV2()
        
        state = create_initial_state(
            intel_text="This is some text with no indicators."
        )
        
        result = agent.execute(state)
        
        findings = result["research_findings"]["findings"]
        assert "iocs" in findings
        # May have empty IOC list
        assert isinstance(findings["iocs"], list)


class TestResearchAgentIntegration:
    """Integration tests for Research Agent v2."""
    
    def test_full_workflow_with_apt29_intel(self):
        """Test full workflow with APT29 intelligence."""
        agent = ResearchAgentV2()
        
        state = create_initial_state(
            intel_text="""
            APT29 (Cozy Bear) Campaign Analysis
            
            Observed IOCs:
            - IP Address: 185.220.101.45
            - Domain: malicious-c2.com
            - Hash: 1234567890abcdef1234567890abcdef
            
            ATT&CK Techniques:
            - T1059.001: PowerShell execution
            - T1071.001: Web-based C2 communication
            - T1566.001: Spearphishing attachment
            
            The adversary used encoded PowerShell commands to establish
            persistence and communicate with the C2 server.
            """,
            target_platforms=["splunk", "sentinel"],
            framework="PEAK",
        )
        
        result = agent.execute(state)
        
        # Verify complete analysis
        assert "research_findings" in result
        findings = result["research_findings"]["findings"]
        
        # Check IOCs
        assert len(findings["iocs"]) > 0
        
        # Check techniques
        assert len(findings["techniques"]) > 0
        technique_ids = [t["technique_id"] for t in findings["techniques"]]
        assert "T1059.001" in technique_ids
        
        # Check enrichment
        summary = findings["enrichment_summary"]
        assert summary["total_iocs"] > 0
        
        # Check confidence
        confidence_analysis = findings["confidence_analysis"]
        assert confidence_analysis["overall_confidence"] > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
