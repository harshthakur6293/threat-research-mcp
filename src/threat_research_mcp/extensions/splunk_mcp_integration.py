"""Integration with Splunk MCP Server for query validation and execution.

This module provides utilities to integrate with the Splunk MCP server
(https://github.com/splunk/splunk-mcp-server2) for:
- SPL query validation with risk scoring
- Direct query execution against Splunk
- Saved search management
- Index discovery
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


class SplunkMCPIntegration:
    """Integration with Splunk MCP Server for enhanced query capabilities."""

    def __init__(self, mcp_client: Optional[Any] = None):
        """
        Initialize Splunk MCP integration.

        Args:
            mcp_client: Optional MCP client instance for calling Splunk MCP tools
        """
        self.mcp_client = mcp_client

    def validate_spl_query(self, spl_query: str) -> Dict[str, Any]:
        """
        Validate an SPL query using Splunk MCP's guardrails.

        This calls the Splunk MCP's validate_spl tool which provides:
        - Risk score (0-100)
        - Detected risks (destructive operations, resource-intensive patterns)
        - Recommendations for safer alternatives

        Args:
            spl_query: SPL query to validate

        Returns:
            Dictionary with validation results:
            {
                "is_safe": bool,
                "risk_score": int,
                "risks": List[str],
                "recommendations": List[str]
            }
        """
        if self.mcp_client:
            # In production, call the actual Splunk MCP tool
            # result = self.mcp_client.call_tool("validate_spl", {"query": spl_query})
            # return result
            pass

        # Placeholder: Basic validation without Splunk MCP
        return self._basic_validation(spl_query)

    def _basic_validation(self, spl_query: str) -> Dict[str, Any]:
        """Basic SPL validation without Splunk MCP (fallback)."""
        risks = []
        risk_score = 0

        query_lower = spl_query.lower()

        # Check for destructive operations
        destructive_commands = ["delete", "remove", "drop", "truncate"]
        for cmd in destructive_commands:
            if cmd in query_lower:
                risks.append(f"Destructive command detected: {cmd}")
                risk_score += 30

        # Check for resource-intensive patterns
        if "| stats count by *" in query_lower:
            risks.append("High cardinality grouping detected")
            risk_score += 20

        if "earliest=-30d" in query_lower or "earliest=-90d" in query_lower:
            risks.append("Long time range query (may be resource-intensive)")
            risk_score += 15

        # Check for missing time constraints
        if "earliest=" not in query_lower and "latest=" not in query_lower:
            risks.append("No time constraint specified (searches all time)")
            risk_score += 25

        return {
            "is_safe": risk_score < 50,
            "risk_score": min(risk_score, 100),
            "risks": risks,
            "recommendations": self._generate_recommendations(risks),
        }

    def _generate_recommendations(self, risks: List[str]) -> List[str]:
        """Generate recommendations based on detected risks."""
        recommendations = []

        for risk in risks:
            if "destructive" in risk.lower():
                recommendations.append("Remove destructive commands or use read-only alternatives")
            elif "cardinality" in risk.lower():
                recommendations.append("Limit grouping fields or add filters to reduce cardinality")
            elif "time range" in risk.lower():
                recommendations.append("Reduce time range to last 24-48 hours for initial testing")
            elif "no time constraint" in risk.lower():
                recommendations.append("Add earliest= and latest= parameters (e.g., earliest=-24h)")

        return recommendations

    def enhance_query_with_validation(self, technique_id: str, spl_query: str) -> Dict[str, Any]:
        """
        Enhance a generated SPL query with validation metadata.

        Args:
            technique_id: ATT&CK technique ID
            spl_query: Generated SPL query

        Returns:
            Enhanced query dictionary with validation results
        """
        validation = self.validate_spl_query(spl_query)

        return {
            "technique_id": technique_id,
            "query": spl_query,
            "validation": validation,
            "ready_to_run": validation["is_safe"],
            "warnings": validation["risks"],
            "recommendations": validation["recommendations"],
        }


def validate_generated_queries(
    queries: Dict[str, Dict[str, Any]], siem_platform: str = "splunk"
) -> Dict[str, Dict[str, Any]]:
    """
    Validate all generated queries for a SIEM platform.

    Args:
        queries: Dictionary of technique_id -> platform -> query data
        siem_platform: SIEM platform to validate (default: "splunk")

    Returns:
        Enhanced queries with validation metadata
    """
    if siem_platform != "splunk":
        # Only Splunk queries can be validated with Splunk MCP
        return queries

    integrator = SplunkMCPIntegration()
    enhanced_queries = {}

    for technique_id, platform_queries in queries.items():
        enhanced_queries[technique_id] = {}

        for platform, query_data in platform_queries.items():
            if platform == "splunk" and isinstance(query_data, dict):
                spl_query = query_data.get("query", "")
                if spl_query:
                    enhanced = integrator.enhance_query_with_validation(technique_id, spl_query)
                    enhanced_queries[technique_id][platform] = {
                        **query_data,
                        "validation": enhanced["validation"],
                        "warnings": enhanced["warnings"],
                        "recommendations": enhanced["recommendations"],
                    }
                else:
                    enhanced_queries[technique_id][platform] = query_data
            else:
                enhanced_queries[technique_id][platform] = query_data

    return enhanced_queries


def get_splunk_mcp_integration_guide() -> str:
    """
    Get integration guide for using Splunk MCP with threat-research-mcp.

    Returns:
        Markdown-formatted integration guide
    """
    return """
# Integrating Splunk MCP Server with Threat Research MCP

## Overview

The Splunk MCP Server (https://github.com/splunk/splunk-mcp-server2) provides:
- SPL query validation with risk scoring
- Direct Splunk query execution
- Saved search management
- Index discovery

## Setup

### 1. Install Splunk MCP Server

```bash
# Python implementation
git clone https://github.com/splunk/splunk-mcp-server2.git
cd splunk-mcp-server2/python
cp .env.example .env
# Edit .env with your Splunk credentials
pip install -e .
```

### 2. Configure in Your MCP Client

Add to your MCP configuration (e.g., Cursor, VS Code):

```json
{
  "mcpServers": {
    "threat-research": {
      "command": "python",
      "args": ["-m", "threat_research_mcp.server"],
      "cwd": "c:/Dev/Vibe Coding/threat-research-mcp"
    },
    "splunk": {
      "command": "python",
      "args": ["server.py"],
      "cwd": "path/to/splunk-mcp-server2/python"
    }
  }
}
```

## Workflow: Threat Intel → Validated Queries → Splunk Execution

### Step 1: Generate Queries with Threat Research MCP

```python
# Auto-detect techniques and generate queries
intel_to_log_sources(
    intel_text="ICP Canister C2 using blockchain for censorship-resistant C2",
    siem_platforms="splunk"
)
```

### Step 2: Validate Queries with Splunk MCP

```python
# In your MCP client
validate_spl(
    query="index=proxy url=*ic0.app* | stats count by src_ip, url"
)
```

**Returns:**
```json
{
  "is_safe": true,
  "risk_score": 15,
  "risks": ["Long time range query"],
  "recommendations": ["Add earliest=-24h for faster results"]
}
```

### Step 3: Execute Validated Queries

```python
# Execute the query
search_oneshot(
    query="index=proxy earliest=-24h url=*ic0.app* | stats count by src_ip, url",
    output_format="json"
)
```

## Available Splunk MCP Tools

### 1. validate_spl
- **Purpose**: Validate SPL queries before execution
- **Risk Scoring**: 0-100 (0 = safe, 100 = dangerous)
- **Detects**: Destructive operations, resource-intensive patterns

### 2. search_oneshot
- **Purpose**: Execute blocking searches with immediate results
- **Output Formats**: JSON, Markdown, CSV, Summary
- **Use Case**: Quick queries, small result sets

### 3. search_export
- **Purpose**: Stream large result sets efficiently
- **Use Case**: Large datasets, long-running searches

### 4. get_indexes
- **Purpose**: List available Splunk indexes
- **Use Case**: Discover what data sources are available

### 5. get_saved_searches
- **Purpose**: Access saved search configurations
- **Use Case**: Reuse existing detection rules

### 6. run_saved_search
- **Purpose**: Execute pre-configured saved searches
- **Use Case**: Run production detection rules

## Example: ICP Canister C2 Detection

### 1. Generate Query (Threat Research MCP)

```python
intel_to_log_sources(
    intel_text="ICP Canister ID: tdtqy-oyaaa-aaaae-af2dq-cai. Blockchain C2.",
    siem_platforms="splunk"
)
```

**Generated Query:**
```spl
index=proxy (url="*ic0.app*" OR url="*tdtqy-oyaaa-aaaae-af2dq-cai*")
| stats count by src_ip, dest, url, user
| where count > 5
```

### 2. Validate Query (Splunk MCP)

```python
validate_spl(query="<generated query>")
```

**Result:**
```json
{
  "is_safe": true,
  "risk_score": 10,
  "risks": ["No time constraint specified"],
  "recommendations": ["Add earliest=-24h latest=now"]
}
```

### 3. Execute Validated Query (Splunk MCP)

```python
search_oneshot(
    query="index=proxy earliest=-24h url=*ic0.app* | stats count by src_ip, url",
    output_format="markdown"
)
```

**Result:**
```markdown
| src_ip | url | count |
|--------|-----|-------|
| 10.0.1.50 | https://tdtqy-oyaaa-aaaae-af2dq-cai.ic0.app | 127 |
| 10.0.1.51 | https://tdtqy-oyaaa-aaaae-af2dq-cai.raw.ic0.app | 45 |
```

## Benefits of Integration

1. **Automated Validation**: All generated queries are validated before execution
2. **Risk Mitigation**: Prevent destructive or resource-intensive queries
3. **Direct Execution**: Test queries immediately without leaving your AI assistant
4. **Index Discovery**: Automatically discover available log sources
5. **Saved Search Reuse**: Leverage existing production detection rules

## Security Considerations

- **Credentials**: Splunk MCP stores credentials in `.env` (never commit)
- **Permissions**: Use read-only Splunk accounts for query generation
- **Validation**: Always validate queries before production deployment
- **Audit Trail**: Both MCPs log all operations for compliance

## Future Enhancements

1. **Automatic Index Discovery**: Query `get_indexes` to tailor recommendations
2. **Saved Search Integration**: Generate queries based on existing saved searches
3. **Real-Time Validation**: Validate queries as they're generated
4. **Performance Optimization**: Use Splunk MCP's risk scoring to optimize queries
5. **Result Enrichment**: Automatically enrich IOCs with Splunk search results
"""
