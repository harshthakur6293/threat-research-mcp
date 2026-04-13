"""MCP tool: Automatic intel → techniques → log sources pipeline."""

from __future__ import annotations

from threat_research_mcp.extensions.mitre_attack_integration import (
    intel_to_log_sources_json,
)

# Re-export for MCP tool registration
__all__ = ["intel_to_log_sources_json"]
