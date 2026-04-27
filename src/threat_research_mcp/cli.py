from __future__ import annotations


def main() -> None:
    """Start the threat-research-mcp MCP server (stdio transport)."""
    from threat_research_mcp import server  # noqa: PLC0415

    if server.mcp is None:
        raise SystemExit(
            "FastMCP not installed. Install with: pip install 'mcp>=1.8.0'"
        )
    server.mcp.run()
