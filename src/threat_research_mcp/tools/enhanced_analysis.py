"""Enhanced analysis tools that leverage optional MCP integrations.

These tools provide enhanced functionality when other MCPs are installed,
but gracefully degrade to basic functionality when they're not available.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from threat_research_mcp.integrations.mcp_client import get_integration_manager


def enhanced_intel_analysis(
    intel_text: str,
    environment: str = "hybrid",
    siem_platforms: str = "splunk,sentinel,elastic",
    enrich_iocs: bool = True,
    check_coverage: bool = True,
    generate_behavioral_hunts: bool = True,
) -> str:
    """
    Enhanced threat intelligence analysis using all available MCP integrations.

    This tool orchestrates multiple MCPs to provide comprehensive analysis:
    1. Auto-detect techniques (built-in)
    2. Generate log sources and queries (built-in)
    3. Enrich IOCs (fastmcp-threatintel, if available)
    4. Check existing coverage (Security-Detections-MCP, if available)
    5. Generate behavioral hunts (threat-hunting-mcp, if available)

    Args:
        intel_text: Threat intelligence text to analyze
        environment: Target environment (aws, azure, gcp, on-prem, hybrid)
        siem_platforms: Comma-separated SIEM platforms
        enrich_iocs: Enable IOC enrichment (requires fastmcp-threatintel)
        check_coverage: Enable coverage check (requires Security-Detections-MCP)
        generate_behavioral_hunts: Enable behavioral hunts (requires threat-hunting-mcp)

    Returns:
        JSON with comprehensive analysis including all available integrations
    """
    from threat_research_mcp.extensions.mitre_attack_integration import (
        intel_to_log_sources,
    )
    from threat_research_mcp.tools.extract_iocs import extract_iocs_json

    manager = get_integration_manager()
    available_integrations = manager.get_available_integrations()

    # Step 1: Core analysis (always available)
    core_analysis = intel_to_log_sources(
        intel_text=intel_text,
        environment=environment,
        siem_platforms=siem_platforms,
        auto_detect_techniques=True,
    )

    # Extract IOCs for enrichment
    iocs_result = json.loads(extract_iocs_json(intel_text))

    result: Dict[str, Any] = {
        "intel_summary": intel_text[:200] + "..." if len(intel_text) > 200 else intel_text,
        "core_analysis": core_analysis,
        "available_integrations": available_integrations,
        "enhanced_features": {},
    }

    # Step 2: IOC Enrichment (optional)
    if enrich_iocs and available_integrations.get("fastmcp-threatintel"):
        enriched_iocs: List[Dict[str, Any]] = []

        # Enrich IPs
        for ip in iocs_result.get("ips", [])[:5]:  # Limit to 5 to avoid rate limits
            enrichment = manager.enrich_ioc(ip)
            if enrichment:
                enriched_iocs.append({"ioc": ip, "type": "ip", "enrichment": enrichment})

        # Enrich domains
        for domain in iocs_result.get("domains", [])[:5]:
            enrichment = manager.enrich_ioc(domain)
            if enrichment:
                enriched_iocs.append({"ioc": domain, "type": "domain", "enrichment": enrichment})

        result["enhanced_features"]["ioc_enrichment"] = {
            "enabled": True,
            "enriched_iocs": enriched_iocs,
            "total_enriched": len(enriched_iocs),
        }
    elif enrich_iocs:
        result["enhanced_features"]["ioc_enrichment"] = {
            "enabled": False,
            "message": "fastmcp-threatintel not available. Install: pip install fastmcp-threatintel",
        }

    # Step 3: Coverage Check (optional)
    if check_coverage and available_integrations.get("security-detections"):
        coverage_data: List[Dict[str, Any]] = []

        for technique_id in core_analysis.get("detected_techniques", [])[:10]:
            coverage = manager.check_existing_coverage(technique_id)
            if coverage:
                coverage_data.append(
                    {
                        "technique_id": technique_id,
                        "existing_detections": coverage.get("count", 0),
                        "sources": coverage.get("sources", []),
                    }
                )

        result["enhanced_features"]["coverage_check"] = {
            "enabled": True,
            "coverage_data": coverage_data,
            "summary": f"Checked {len(coverage_data)} techniques against 8,200+ existing rules",
        }
    elif check_coverage:
        result["enhanced_features"]["coverage_check"] = {
            "enabled": False,
            "message": "Security-Detections-MCP not available. Install: npx -y security-detections-mcp",
        }

    # Step 4: Behavioral Hunts (optional)
    if generate_behavioral_hunts and available_integrations.get("threat-hunting"):
        behavioral_hunts: List[Dict[str, Any]] = []

        for technique_id in core_analysis.get("detected_techniques", [])[:5]:
            hunt = manager.get_behavioral_hunt(technique_id)
            if hunt:
                behavioral_hunts.append(
                    {
                        "technique_id": technique_id,
                        "hunt_hypothesis": hunt.get("hypothesis", ""),
                        "behavioral_indicators": hunt.get("behavioral_indicators", []),
                    }
                )

        result["enhanced_features"]["behavioral_hunts"] = {
            "enabled": True,
            "hunts": behavioral_hunts,
            "summary": f"Generated {len(behavioral_hunts)} behavioral hunt hypotheses",
        }
    elif generate_behavioral_hunts:
        result["enhanced_features"]["behavioral_hunts"] = {
            "enabled": False,
            "message": "threat-hunting-mcp not available. Install from: https://github.com/THORCollective/threat-hunting-mcp-server",
        }

    return json.dumps(result, indent=2)


def get_integration_status() -> str:
    """
    Get status of all optional MCP integrations.

    Returns:
        JSON with integration availability and setup instructions
    """
    manager = get_integration_manager()
    available = manager.get_available_integrations()

    status = {
        "integrations": {
            "fastmcp-threatintel": {
                "available": available.get("fastmcp-threatintel", False),
                "purpose": "IOC enrichment (VirusTotal, OTX, AbuseIPDB, IPinfo)",
                "install": "pip install fastmcp-threatintel && threatintel setup",
                "env_vars": ["VIRUSTOTAL_API_KEY", "OTX_API_KEY"],
                "enable": "Set ENABLE_FASTMCP_THREATINTEL=true in environment",
            },
            "security-detections": {
                "available": available.get("security-detections", False),
                "purpose": "Search 8,200+ existing detection rules, coverage analysis",
                "install": "npx -y security-detections-mcp (no install needed)",
                "env_vars": ["SIGMA_PATHS", "SPLUNK_PATHS", "ELASTIC_PATHS"],
                "enable": "Set ENABLE_SECURITY_DETECTIONS_MCP=true in environment",
            },
            "threat-hunting": {
                "available": available.get("threat-hunting", False),
                "purpose": "Behavioral hunting, HEARTH community hunts, cognitive analysis",
                "install": "git clone https://github.com/THORCollective/threat-hunting-mcp-server",
                "env_vars": ["THREAT_HUNTING_MCP_PATH"],
                "enable": "Set ENABLE_THREAT_HUNTING_MCP=true and THREAT_HUNTING_MCP_PATH=/path/to/server",
            },
            "splunk": {
                "available": available.get("splunk", False),
                "purpose": "Query validation (risk scoring), safe execution",
                "install": "git clone https://github.com/splunk/splunk-mcp-server2",
                "env_vars": ["SPLUNK_MCP_PATH", "SPLUNK_HOST", "SPLUNK_PORT"],
                "enable": "Set ENABLE_SPLUNK_MCP=true and SPLUNK_MCP_PATH=/path/to/server",
            },
        },
        "summary": {
            "total_integrations": len(available),
            "available_count": sum(1 for v in available.values() if v),
            "standalone_mode": sum(1 for v in available.values() if v) == 0,
        },
        "note": "All integrations are OPTIONAL. threat-research-mcp works standalone without any of these.",
    }

    return json.dumps(status, indent=2)
