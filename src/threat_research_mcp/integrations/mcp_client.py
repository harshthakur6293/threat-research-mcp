"""MCP client for calling other MCP servers (optional integrations).

This module provides utilities to call other MCP servers when they are available.
All integrations are OPTIONAL - the threat-research-mcp works standalone.
"""

from __future__ import annotations

import os
import subprocess
from typing import Any, Dict, List, Optional


class MCPClient:
    """Client for calling other MCP servers via stdio protocol."""

    def __init__(
        self, server_name: str, command: str, args: List[str], env: Optional[Dict[str, str]] = None
    ):
        """
        Initialize MCP client.

        Args:
            server_name: Name of the MCP server (for logging)
            command: Command to start the MCP server
            args: Command arguments
            env: Optional environment variables
        """
        self.server_name = server_name
        self.command = command
        self.args = args
        self.env = {**os.environ.copy(), **(env or {})}
        self._available: Optional[bool] = None

    def is_available(self) -> bool:
        """
        Check if the MCP server is available.

        Returns:
            True if server can be started, False otherwise
        """
        if self._available is not None:
            return self._available

        try:
            # Try to start the server briefly to check availability
            # This is a simple check - in production, you'd use MCP protocol handshake
            result = subprocess.run(  # nosec B603 - command and args are validated from user config, not untrusted input
                [self.command] + self.args + ["--help"],
                capture_output=True,
                timeout=5,
                env=self.env,
            )
            self._available = (
                result.returncode == 0 or result.returncode == 1
            )  # Some MCPs return 1 for --help
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            self._available = False

        return self._available

    def call_tool(
        self, tool_name: str, arguments: Dict[str, Any], timeout: int = 30
    ) -> Optional[Dict[str, Any]]:
        """
        Call a tool on the MCP server.

        Args:
            tool_name: Name of the tool to call
            arguments: Tool arguments
            timeout: Timeout in seconds

        Returns:
            Tool result as dictionary, or None if call failed
        """
        if not self.is_available():
            return None

        try:
            # In production, this would use the MCP protocol (JSON-RPC over stdio)
            # For now, this is a placeholder that returns None
            #
            # Actual implementation would:
            # 1. Start MCP server process
            # 2. Send JSON-RPC request via stdin
            # 3. Read JSON-RPC response from stdout
            # 4. Parse and return result

            return None
        except Exception:
            return None


class MCPIntegrationManager:
    """Manages optional integrations with other MCP servers."""

    def __init__(self):
        """Initialize integration manager with optional MCP clients."""
        self.clients: Dict[str, MCPClient] = {}
        self._initialize_clients()

    def _initialize_clients(self) -> None:
        """Initialize MCP clients for optional integrations."""
        # Check environment variables for MCP configurations

        # fastmcp-threatintel
        if os.getenv("ENABLE_FASTMCP_THREATINTEL", "").lower() == "true":
            self.clients["fastmcp-threatintel"] = MCPClient(
                server_name="fastmcp-threatintel",
                command="threatintel",
                args=["server"],
                env={
                    "VIRUSTOTAL_API_KEY": os.getenv("VIRUSTOTAL_API_KEY", ""),
                    "OTX_API_KEY": os.getenv("OTX_API_KEY", ""),
                },
            )

        # Security-Detections-MCP
        if os.getenv("ENABLE_SECURITY_DETECTIONS_MCP", "").lower() == "true":
            sigma_paths = os.getenv("SIGMA_PATHS", "")
            if sigma_paths:
                self.clients["security-detections"] = MCPClient(
                    server_name="security-detections",
                    command="npx",
                    args=["-y", "security-detections-mcp"],
                    env={"SIGMA_PATHS": sigma_paths},
                )

        # threat-hunting-mcp
        if os.getenv("ENABLE_THREAT_HUNTING_MCP", "").lower() == "true":
            hunting_path = os.getenv("THREAT_HUNTING_MCP_PATH", "")
            if hunting_path:
                self.clients["threat-hunting"] = MCPClient(
                    server_name="threat-hunting",
                    command="python",
                    args=["-u", f"{hunting_path}/run_server.py"],
                )

        # Splunk MCP
        if os.getenv("ENABLE_SPLUNK_MCP", "").lower() == "true":
            splunk_path = os.getenv("SPLUNK_MCP_PATH", "")
            if splunk_path:
                self.clients["splunk"] = MCPClient(
                    server_name="splunk",
                    command="python",
                    args=[f"{splunk_path}/server.py"],
                    env={
                        "SPLUNK_HOST": os.getenv("SPLUNK_HOST", ""),
                        "SPLUNK_PORT": os.getenv("SPLUNK_PORT", "8089"),
                    },
                )

    def get_available_integrations(self) -> Dict[str, bool]:
        """
        Get status of all optional integrations.

        Returns:
            Dictionary of integration_name -> is_available
        """
        return {name: client.is_available() for name, client in self.clients.items()}

    def enrich_ioc(self, ioc: str) -> Optional[Dict[str, Any]]:
        """
        Enrich IOC using fastmcp-threatintel (if available).

        Args:
            ioc: IP, domain, URL, or hash to enrich

        Returns:
            Enrichment data or None if integration not available
        """
        client = self.clients.get("fastmcp-threatintel")
        if not client or not client.is_available():
            return None

        return client.call_tool("analyze", {"ioc": ioc, "output_format": "json"})

    def check_existing_coverage(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """
        Check existing detection coverage using Security-Detections-MCP (if available).

        Args:
            technique_id: ATT&CK technique ID

        Returns:
            Coverage data or None if integration not available
        """
        client = self.clients.get("security-detections")
        if not client or not client.is_available():
            return None

        return client.call_tool("list_by_mitre", {"technique_id": technique_id})

    def get_behavioral_hunt(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """
        Get behavioral hunt hypothesis using threat-hunting-mcp (if available).

        Args:
            technique_id: ATT&CK technique ID

        Returns:
            Behavioral hunt data or None if integration not available
        """
        client = self.clients.get("threat-hunting")
        if not client or not client.is_available():
            return None

        return client.call_tool(
            "create_behavioral_hunt", {"technique_id": technique_id, "framework": "PEAK"}
        )

    def validate_spl_query(self, query: str) -> Optional[Dict[str, Any]]:
        """
        Validate SPL query using Splunk MCP (if available).

        Args:
            query: Splunk SPL query

        Returns:
            Validation result or None if integration not available
        """
        client = self.clients.get("splunk")
        if not client or not client.is_available():
            return None

        return client.call_tool("validate_spl", {"query": query})


# Global integration manager instance
_integration_manager: Optional[MCPIntegrationManager] = None


def get_integration_manager() -> MCPIntegrationManager:
    """Get or create the global integration manager."""
    global _integration_manager
    if _integration_manager is None:
        _integration_manager = MCPIntegrationManager()
    return _integration_manager


def is_integration_enabled(integration_name: str) -> bool:
    """
    Check if an optional integration is enabled and available.

    Args:
        integration_name: Name of the integration (fastmcp-threatintel, security-detections, etc.)

    Returns:
        True if integration is enabled and available
    """
    manager = get_integration_manager()
    return manager.get_available_integrations().get(integration_name, False)
