"""MCP tool wrapper for log source recommendations."""

from __future__ import annotations

import json
from typing import List

from threat_research_mcp.detection.log_source_mapper import get_log_sources_for_techniques
from threat_research_mcp.detection.query_generator import (
    generate_deployment_checklist,
    generate_hunt_queries,
)


def recommend_log_sources_json(
    technique_ids: str, environment: str = "hybrid", siem_platforms: str = "splunk,sentinel,elastic"
) -> str:
    """
    Get log source recommendations and hunt queries for ATT&CK techniques.

    Args:
        technique_ids: Comma-separated technique IDs (e.g., "T1059.001,T1566.001")
        environment: Target environment (aws, azure, gcp, on-prem, hybrid)
        siem_platforms: Comma-separated SIEM platforms

    Returns:
        JSON string with log sources, queries, and deployment checklist
    """
    # Parse inputs
    tid_list: List[str] = [t.strip() for t in technique_ids.split(",") if t.strip()]
    siem_list: List[str] = [s.strip() for s in siem_platforms.split(",") if s.strip()]

    if not tid_list:
        return json.dumps({"error": "No technique IDs provided"}, indent=2)

    # Get log sources
    log_sources = get_log_sources_for_techniques(tid_list, environment)

    # Generate hunt queries
    queries = generate_hunt_queries(tid_list, siem_list)

    # Generate deployment checklist
    checklist = generate_deployment_checklist(log_sources)

    # Combine results
    result = {
        "techniques": tid_list,
        "environment": environment,
        "log_sources": log_sources["log_sources"],
        "priority_summary": log_sources["priority_summary"],
        "hunt_queries": queries["queries"],
        "deployment_checklist": checklist,
        "blind_spots": log_sources.get("blind_spots", []),
    }

    return json.dumps(result, indent=2)
