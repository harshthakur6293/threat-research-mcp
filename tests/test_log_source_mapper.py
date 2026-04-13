"""Tests for log source mapper and query generator."""

from __future__ import annotations

import json

from threat_research_mcp.detection.log_source_mapper import get_log_sources_for_techniques
from threat_research_mcp.detection.query_generator import (
    generate_deployment_checklist,
    generate_hunt_queries,
)
from threat_research_mcp.tools.recommend_log_sources import recommend_log_sources_json


def test_get_log_sources_for_powershell():
    """Test log source mapping for PowerShell technique."""
    result = get_log_sources_for_techniques(["T1059.001"], environment="hybrid")

    assert "techniques" in result
    assert "T1059.001" in result["techniques"]
    assert "log_sources" in result
    assert "priority_summary" in result

    # Should have Windows logs
    assert "windows" in result["log_sources"]

    # Should have priority items (critical or high)
    total_priority = len(result["priority_summary"]["critical"]) + len(
        result["priority_summary"]["high"]
    )
    assert total_priority > 0


def test_get_log_sources_for_multiple_techniques():
    """Test log source mapping for multiple techniques."""
    techniques = ["T1059.001", "T1566.001", "T1053.005"]
    result = get_log_sources_for_techniques(techniques, environment="hybrid")

    assert result["techniques"] == techniques
    assert len(result["log_sources"]) > 0

    # Should have multiple platforms
    assert "windows" in result["log_sources"]
    assert "email_gateway" in result["log_sources"]


def test_get_log_sources_aws_environment():
    """Test log source mapping filtered for AWS environment."""
    result = get_log_sources_for_techniques(["T1059.001"], environment="aws")

    assert "log_sources" in result
    # Should include AWS-specific sources
    if "aws" in result["log_sources"]:
        assert "cloudtrail" in result["log_sources"]["aws"]


def test_get_log_sources_unknown_technique():
    """Test handling of unknown technique."""
    result = get_log_sources_for_techniques(["T9999.999"], environment="hybrid")

    assert "blind_spots" in result
    assert len(result["blind_spots"]) > 0
    assert "T9999.999" in result["blind_spots"][0]


def test_generate_hunt_queries_powershell():
    """Test query generation for PowerShell technique."""
    result = generate_hunt_queries(["T1059.001"], ["splunk", "sentinel"])

    assert "queries" in result
    assert "T1059.001" in result["queries"]

    # Should have Splunk and Sentinel queries
    assert "splunk" in result["queries"]["T1059.001"]
    assert "sentinel" in result["queries"]["T1059.001"]

    # Queries should be ready to run
    splunk_query = result["queries"]["T1059.001"]["splunk"]
    assert "query" in splunk_query
    assert splunk_query["ready_to_run"] is True
    assert "index=" in splunk_query["query"]


def test_generate_hunt_queries_all_siems():
    """Test query generation for all SIEM platforms."""
    result = generate_hunt_queries(
        ["T1059.001"], ["splunk", "sentinel", "elastic", "athena", "chronicle"]
    )

    queries = result["queries"]["T1059.001"]
    assert "splunk" in queries
    assert "sentinel" in queries
    assert "elastic" in queries
    assert "athena" in queries
    assert "chronicle" in queries


def test_generate_hunt_queries_unknown_technique():
    """Test query generation for unknown technique."""
    result = generate_hunt_queries(["T9999.999"], ["splunk"])

    assert "T9999.999" in result["queries"]
    assert result["queries"]["T9999.999"]["status"] == "no_template"


def test_generate_deployment_checklist():
    """Test deployment checklist generation."""
    log_sources = get_log_sources_for_techniques(["T1059.001", "T1003.001"])
    checklist = generate_deployment_checklist(log_sources)

    assert isinstance(checklist, list)
    assert len(checklist) > 0

    # Check first item structure
    first_item = checklist[0]
    assert "platform" in first_item
    assert "source" in first_item
    assert "priority" in first_item
    assert "action" in first_item

    # Should be sorted by priority (critical first)
    assert first_item["priority"] in ["critical", "high"]


def test_recommend_log_sources_json_tool():
    """Test the MCP tool wrapper."""
    result_json = recommend_log_sources_json(
        technique_ids="T1059.001,T1566.001", environment="hybrid", siem_platforms="splunk,sentinel"
    )

    result = json.loads(result_json)

    assert "techniques" in result
    assert "T1059.001" in result["techniques"]
    assert "T1566.001" in result["techniques"]

    assert "log_sources" in result
    assert "hunt_queries" in result
    assert "deployment_checklist" in result

    # Should have queries for both techniques
    assert "T1059.001" in result["hunt_queries"]
    assert "T1566.001" in result["hunt_queries"]


def test_recommend_log_sources_json_empty_input():
    """Test MCP tool with empty input."""
    result_json = recommend_log_sources_json(technique_ids="")
    result = json.loads(result_json)

    assert "error" in result


def test_log_source_coverage_for_common_techniques():
    """Test that we have coverage for common techniques."""
    common_techniques = [
        "T1059.001",  # PowerShell
        "T1566.001",  # Phishing
        "T1053.005",  # Scheduled Task
        "T1105",  # Ingress Tool Transfer
        "T1003.001",  # LSASS Memory
        "T1021.001",  # RDP
        "T1078",  # Valid Accounts
        "T1070.001",  # Clear Event Logs
        "T1136.001",  # Create Account
        "T1486",  # Ransomware
    ]

    result = get_log_sources_for_techniques(common_techniques)

    # Should have minimal blind spots
    assert len(result["blind_spots"]) == 0

    # Should have log sources for all techniques
    assert len(result["log_sources"]) > 0


def test_query_coverage_for_common_techniques():
    """Test that we have queries for common techniques."""
    common_techniques = [
        "T1059.001",
        "T1566.001",
        "T1053.005",
        "T1003.001",
        "T1078",
    ]

    result = generate_hunt_queries(common_techniques, ["splunk", "sentinel"])

    for tid in common_techniques:
        assert tid in result["queries"]
        assert "splunk" in result["queries"][tid]
        assert "sentinel" in result["queries"][tid]
