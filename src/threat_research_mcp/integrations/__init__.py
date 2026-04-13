"""Optional MCP integrations.

This module provides integration with other MCP servers for enhanced functionality.
All integrations are OPTIONAL - threat-research-mcp works standalone without any of these.
"""

from threat_research_mcp.integrations.mcp_client import (
    MCPClient,
    MCPIntegrationManager,
    get_integration_manager,
    is_integration_enabled,
)

__all__ = [
    "MCPClient",
    "MCPIntegrationManager",
    "get_integration_manager",
    "is_integration_enabled",
]
