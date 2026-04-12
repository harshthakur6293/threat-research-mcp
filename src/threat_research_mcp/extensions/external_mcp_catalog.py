"""Catalog of optional open-source MCP servers that pair with threat-research-mcp.

This module does not spawn or call other MCPs. It encodes *architecture intent*:
which capability gaps community MCPs typically fill, and how adopters compose them.

Embedded (in-process) clients for these servers are a possible future extension; the
supported default for multi-MCP today is *host-level composition* (e.g. Cursor).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import List, Tuple


class CapabilityDomain(str, Enum):
    """Coarse capability areas across the intel → hunt → detection lifecycle."""

    WORKFLOW_ORCHESTRATION = "workflow_orchestration"  # this project
    INTEL_INGESTION = "intel_ingestion"
    ATTACK_KNOWLEDGE = "attack_knowledge"
    DETECTION_CATALOG = "detection_catalog"
    HUNT_METHODOLOGY = "hunt_methodology"
    IOC_ENRICHMENT = "ioc_enrichment"


@dataclass(frozen=True)
class ExternalMCPReference:
    """A well-known OSS MCP server adopters may run alongside this repo."""

    key: str
    title: str
    repo_url: str
    fills: Tuple[CapabilityDomain, ...]
    composition_note: str


RECOMMENDED_EXTERNAL_MCPS: Tuple[ExternalMCPReference, ...] = (
    ExternalMCPReference(
        key="mitre-attack-mcp",
        title="MITRE ATT&CK MCP",
        repo_url="https://github.com/MHaggis/mitre-attack-mcp",
        fills=(CapabilityDomain.ATTACK_KNOWLEDGE,),
        composition_note=(
            "Full ATT&CK matrix, FTS search, Navigator layers, group coverage math. "
            "Pairs with this project for technique lookups beyond keyword mapping."
        ),
    ),
    ExternalMCPReference(
        key="security-detections-mcp",
        title="Security Detections MCP",
        repo_url="https://github.com/MHaggis/Security-Detections-MCP",
        fills=(CapabilityDomain.DETECTION_CATALOG,),
        composition_note=(
            "Large indexed rule corpora (Sigma, Splunk, Elastic, etc.) and coverage/gap analysis. "
            "Pairs with this project when you need inventory-backed answers."
        ),
    ),
    ExternalMCPReference(
        key="threat-hunting-mcp-server",
        title="THOR Threat Hunting MCP",
        repo_url="https://github.com/THORCollective/threat-hunting-mcp-server",
        fills=(CapabilityDomain.HUNT_METHODOLOGY,),
        composition_note=(
            "TTP-first hunting frameworks, community hunt patterns, optional SIEM integrations. "
            "Pairs with this project for deeper hunt operations vs lightweight hypotheses here."
        ),
    ),
    ExternalMCPReference(
        key="fastmcp-threatintel",
        title="FastMCP ThreatIntel",
        repo_url="https://github.com/4R9UN/fastmcp-threatintel",
        fills=(CapabilityDomain.IOC_ENRICHMENT,),
        composition_note=(
            "Multi-vendor IOC reputation (VT, OTX, etc.) and rich reporting. "
            "Pairs with this project after IOC extraction for enrichment."
        ),
    ),
)


def list_external_mcp_keys() -> List[str]:
    return [e.key for e in RECOMMENDED_EXTERNAL_MCPS]


def this_project_domains() -> Tuple[CapabilityDomain, ...]:
    """Capabilities threat-research-mcp owns first-party (expand over time)."""
    return (
        CapabilityDomain.WORKFLOW_ORCHESTRATION,
        CapabilityDomain.INTEL_INGESTION,
    )
