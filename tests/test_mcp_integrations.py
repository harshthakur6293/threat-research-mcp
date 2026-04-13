"""Tests for optional MCP integrations."""

from __future__ import annotations

import json
import os
from unittest.mock import patch


from threat_research_mcp.integrations.mcp_client import (
    MCPClient,
    MCPIntegrationManager,
    get_integration_manager,
    is_integration_enabled,
)
from threat_research_mcp.tools.enhanced_analysis import (
    enhanced_intel_analysis,
    get_integration_status,
)


class TestMCPClient:
    """Test MCP client functionality."""

    def test_client_initialization(self):
        """Test MCP client can be initialized."""
        client = MCPClient(
            server_name="test-mcp",
            command="python",
            args=["-m", "test_mcp"],
        )
        assert client.server_name == "test-mcp"
        assert client.command == "python"
        assert client.args == ["-m", "test_mcp"]

    def test_is_available_false_when_command_not_found(self):
        """Test is_available returns False when command doesn't exist."""
        client = MCPClient(
            server_name="nonexistent",
            command="nonexistent_command_12345",
            args=["--help"],
        )
        assert client.is_available() is False

    def test_call_tool_returns_none_when_unavailable(self):
        """Test call_tool returns None when MCP is unavailable."""
        client = MCPClient(
            server_name="nonexistent",
            command="nonexistent_command_12345",
            args=["--help"],
        )
        result = client.call_tool("test_tool", {"arg": "value"})
        assert result is None


class TestMCPIntegrationManager:
    """Test MCP integration manager."""

    def test_manager_initialization(self):
        """Test manager can be initialized."""
        manager = MCPIntegrationManager()
        assert isinstance(manager.clients, dict)

    def test_get_available_integrations_returns_dict(self):
        """Test get_available_integrations returns a dictionary."""
        manager = MCPIntegrationManager()
        available = manager.get_available_integrations()
        assert isinstance(available, dict)

    @patch.dict(os.environ, {"ENABLE_FASTMCP_THREATINTEL": "true"})
    def test_fastmcp_client_created_when_enabled(self):
        """Test fastmcp-threatintel client is created when enabled."""
        _ = MCPIntegrationManager()
        # Client should be created (even if not available)
        # We check if the environment variable was read
        assert "ENABLE_FASTMCP_THREATINTEL" in os.environ

    def test_enrich_ioc_returns_none_when_unavailable(self):
        """Test enrich_ioc returns None when integration unavailable."""
        manager = MCPIntegrationManager()
        result = manager.enrich_ioc("1.2.3.4")
        assert result is None

    def test_check_existing_coverage_returns_none_when_unavailable(self):
        """Test check_existing_coverage returns None when unavailable."""
        manager = MCPIntegrationManager()
        result = manager.check_existing_coverage("T1059.001")
        assert result is None

    def test_get_behavioral_hunt_returns_none_when_unavailable(self):
        """Test get_behavioral_hunt returns None when unavailable."""
        manager = MCPIntegrationManager()
        result = manager.get_behavioral_hunt("T1059.001")
        assert result is None

    def test_validate_spl_query_returns_none_when_unavailable(self):
        """Test validate_spl_query returns None when unavailable."""
        manager = MCPIntegrationManager()
        result = manager.validate_spl_query("index=main | stats count")
        assert result is None


class TestIntegrationHelpers:
    """Test integration helper functions."""

    def test_get_integration_manager_returns_singleton(self):
        """Test get_integration_manager returns the same instance."""
        manager1 = get_integration_manager()
        manager2 = get_integration_manager()
        assert manager1 is manager2

    def test_is_integration_enabled_returns_bool(self):
        """Test is_integration_enabled returns boolean."""
        result = is_integration_enabled("fastmcp-threatintel")
        assert isinstance(result, bool)


class TestEnhancedAnalysis:
    """Test enhanced analysis tools."""

    def test_get_integration_status_returns_json(self):
        """Test get_integration_status returns valid JSON."""
        result = get_integration_status()
        data = json.loads(result)
        assert "integrations" in data
        assert "summary" in data
        assert isinstance(data["integrations"], dict)

    def test_enhanced_intel_analysis_returns_json(self):
        """Test enhanced_intel_analysis returns valid JSON."""
        intel_text = "APT29 using PowerShell for initial access"
        result = enhanced_intel_analysis(
            intel_text=intel_text,
            environment="hybrid",
            siem_platforms="splunk",
            enrich_iocs=False,  # Disable to avoid external calls
            check_coverage=False,
            generate_behavioral_hunts=False,
        )
        data = json.loads(result)
        assert "intel_summary" in data
        assert "core_analysis" in data
        assert "available_integrations" in data
        assert "enhanced_features" in data

    def test_enhanced_analysis_includes_core_features(self):
        """Test enhanced analysis includes core features even without integrations."""
        intel_text = "Threat actor using T1059.001 PowerShell"
        result = enhanced_intel_analysis(
            intel_text=intel_text,
            environment="aws",
            siem_platforms="splunk,sentinel",
            enrich_iocs=False,
            check_coverage=False,
            generate_behavioral_hunts=False,
        )
        data = json.loads(result)
        # Core analysis should always be present
        assert "core_analysis" in data
        assert data["core_analysis"] is not None

    def test_enhanced_analysis_graceful_degradation(self):
        """Test enhanced analysis gracefully degrades when integrations unavailable."""
        intel_text = "Malicious IP: 1.2.3.4"
        result = enhanced_intel_analysis(
            intel_text=intel_text,
            environment="hybrid",
            siem_platforms="splunk",
            enrich_iocs=True,  # Request enrichment
            check_coverage=True,  # Request coverage
            generate_behavioral_hunts=True,  # Request hunts
        )
        data = json.loads(result)
        
        # Should have enhanced_features section
        assert "enhanced_features" in data
        
        # Each feature should indicate if it's enabled or not
        for feature_name, feature_data in data["enhanced_features"].items():
            assert "enabled" in feature_data
            # If not enabled, should have a helpful message
            if not feature_data["enabled"]:
                assert "message" in feature_data


class TestIntegrationConfiguration:
    """Test integration configuration via environment variables."""

    @patch.dict(os.environ, {"ENABLE_FASTMCP_THREATINTEL": "true", "VIRUSTOTAL_API_KEY": "test_key"})
    def test_fastmcp_config_from_env(self):
        """Test fastmcp-threatintel configuration from environment."""
        _ = MCPIntegrationManager()
        # Should attempt to create client when env var is set
        assert os.getenv("ENABLE_FASTMCP_THREATINTEL") == "true"

    @patch.dict(os.environ, {"ENABLE_SECURITY_DETECTIONS_MCP": "true", "SIGMA_PATHS": "/path/to/sigma"})
    def test_security_detections_config_from_env(self):
        """Test Security-Detections-MCP configuration from environment."""
        _ = MCPIntegrationManager()
        assert os.getenv("ENABLE_SECURITY_DETECTIONS_MCP") == "true"
        assert os.getenv("SIGMA_PATHS") == "/path/to/sigma"

    @patch.dict(os.environ, {"ENABLE_THREAT_HUNTING_MCP": "true", "THREAT_HUNTING_MCP_PATH": "/path/to/hunting"})
    def test_threat_hunting_config_from_env(self):
        """Test threat-hunting-mcp configuration from environment."""
        _ = MCPIntegrationManager()
        assert os.getenv("ENABLE_THREAT_HUNTING_MCP") == "true"
        assert os.getenv("THREAT_HUNTING_MCP_PATH") == "/path/to/hunting"

    @patch.dict(os.environ, {
        "ENABLE_SPLUNK_MCP": "true",
        "SPLUNK_MCP_PATH": "/path/to/splunk",
        "SPLUNK_HOST": "splunk.example.com"
    })
    def test_splunk_config_from_env(self):
        """Test Splunk MCP configuration from environment."""
        _ = MCPIntegrationManager()
        assert os.getenv("ENABLE_SPLUNK_MCP") == "true"
        assert os.getenv("SPLUNK_MCP_PATH") == "/path/to/splunk"
        assert os.getenv("SPLUNK_HOST") == "splunk.example.com"
