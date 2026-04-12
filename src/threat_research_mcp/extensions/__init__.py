"""
Extension and composition surface for adopters and integrators.

- First-party pipeline: ingestion → research → hunt → detection → review (see docs).
- Optional OSS MCP servers are *catalogued* in `external_mcp_catalog` for host-level
  composition (recommended) or future in-process bridges (not implemented yet).
"""

from threat_research_mcp.extensions.external_mcp_catalog import (
    CapabilityDomain,
    ExternalMCPReference,
    RECOMMENDED_EXTERNAL_MCPS,
    list_external_mcp_keys,
    this_project_domains,
)

__all__ = [
    "CapabilityDomain",
    "ExternalMCPReference",
    "RECOMMENDED_EXTERNAL_MCPS",
    "list_external_mcp_keys",
    "this_project_domains",
]
