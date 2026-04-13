# Splunk MCP Integration Guide

## Overview

This guide shows how to integrate the [Splunk MCP Server](https://github.com/splunk/splunk-mcp-server2) with threat-research-mcp to create a complete threat intelligence → query generation → validation → execution pipeline.

## Why Integrate?

| Feature | Threat Research MCP | Splunk MCP | Combined Power |
|---------|-------------------|------------|----------------|
| **Technique Detection** | ✅ Auto-detect from intel | ❌ | Auto-detect techniques from threat intel |
| **Query Generation** | ✅ Templates for 20 techniques | ❌ | Generate queries automatically |
| **Query Validation** | ❌ | ✅ Risk scoring 0-100 | Validate before execution |
| **Query Execution** | ❌ | ✅ Direct Splunk access | Test queries immediately |
| **Index Discovery** | ❌ | ✅ List available indexes | Tailor recommendations to your environment |
| **Saved Searches** | ❌ | ✅ Access existing rules | Leverage production detections |

**Together:** Complete automation from raw threat intel to validated, executed queries.

## Setup

### 1. Install Both MCP Servers

#### Threat Research MCP (Already Installed)
```bash
cd c:\Dev\Vibe Coding\threat-research-mcp
pip install -e ".[dev]"
```

#### Splunk MCP Server
```bash
# Clone the repository
git clone https://github.com/splunk/splunk-mcp-server2.git
cd splunk-mcp-server2/python

# Configure Splunk credentials
cp .env.example .env
# Edit .env:
# SPLUNK_HOST=your-splunk-instance.com
# SPLUNK_PORT=8089
# SPLUNK_USERNAME=your-username
# SPLUNK_PASSWORD=your-password
# SPLUNK_SCHEME=https

# Install
pip install -e .
```

### 2. Configure Your MCP Client

#### For Cursor

Edit `%APPDATA%\Cursor\User\globalStorage\saoudrizwan.claude-dev\settings\cline_mcp_settings.json`:

```json
{
  "mcpServers": {
    "threat-research": {
      "command": "python",
      "args": ["-m", "threat_research_mcp.server"],
      "cwd": "c:\\Dev\\Vibe Coding\\threat-research-mcp",
      "env": {}
    },
    "splunk": {
      "command": "python",
      "args": ["server.py"],
      "cwd": "c:\\path\\to\\splunk-mcp-server2\\python",
      "env": {
        "SPLUNK_HOST": "your-splunk-instance.com",
        "SPLUNK_PORT": "8089",
        "SPLUNK_USERNAME": "your-username",
        "SPLUNK_PASSWORD": "your-password"
      }
    }
  }
}
```

#### For VS Code + Cline

Similar configuration in VS Code's MCP settings.

### 3. Verify Both Servers

Restart your MCP client and verify both servers are running:
- Threat Research MCP: 17 tools available
- Splunk MCP: 7 tools available

## Complete Workflow

### Scenario: ICP Canister C2 Detection

Let's use your real-world ICP Canister C2 case as an example.

#### Step 1: Auto-Detect Techniques (Threat Research MCP)

```python
# In your MCP client (Cursor, VS Code + Cline)
intel_to_log_sources(
    intel_text="""
    ICP Canister ID: tdtqy-oyaaa-aaaae-af2dq-cai
    
    Decentralized C2 using Internet Computer Protocol for censorship-resistant 
    command and control. Threat actor leveraging Web3/blockchain infrastructure.
    Encrypted communication channels. Proxy-like behavior through decentralized nodes.
    """,
    environment="hybrid",
    siem_platforms="splunk"
)
```

**Result:**
```json
{
  "detected_techniques": ["T1071.001", "T1090", "T1573.002"],
  "log_sources": {
    "network": {
      "proxy": {"priority": "high", "description": "Web proxy logs for C2 communication"}
    }
  },
  "hunt_queries": {
    "T1071.001": {
      "splunk": {
        "query": "index=proxy url=*ic0.app* OR url=*tdtqy-oyaaa-aaaae-af2dq-cai* | stats count by src_ip, dest, url",
        "ready_to_run": true
      }
    }
  }
}
```

#### Step 2: Discover Available Indexes (Splunk MCP)

Before running the query, check what indexes are actually available:

```python
get_indexes()
```

**Result:**
```json
{
  "indexes": [
    {"name": "proxy", "totalEventCount": "1234567", "currentDBSizeMB": "450"},
    {"name": "firewall", "totalEventCount": "9876543", "currentDBSizeMB": "1200"},
    {"name": "windows", "totalEventCount": "5555555", "currentDBSizeMB": "800"}
  ]
}
```

✅ Good! The `proxy` index exists, so our generated query will work.

#### Step 3: Validate Query (Splunk MCP)

```python
validate_spl(
    query="index=proxy url=*ic0.app* OR url=*tdtqy-oyaaa-aaaae-af2dq-cai* | stats count by src_ip, dest, url"
)
```

**Result:**
```json
{
  "is_safe": true,
  "risk_score": 25,
  "risks": [
    "No time constraint specified (searches all time)"
  ],
  "recommendations": [
    "Add earliest= and latest= parameters (e.g., earliest=-24h)"
  ]
}
```

⚠️ Warning detected! Let's improve the query.

#### Step 4: Refine Query Based on Validation

```spl
index=proxy earliest=-24h latest=now 
(url="*ic0.app*" OR url="*tdtqy-oyaaa-aaaae-af2dq-cai*")
| stats count by src_ip, dest, url, user
| where count > 5
| sort - count
```

Validate again:

```python
validate_spl(query="<refined query>")
```

**Result:**
```json
{
  "is_safe": true,
  "risk_score": 5,
  "risks": [],
  "recommendations": []
}
```

✅ Query is safe to run!

#### Step 5: Execute Query (Splunk MCP)

```python
search_oneshot(
    query="index=proxy earliest=-24h latest=now (url=\"*ic0.app*\" OR url=\"*tdtqy-oyaaa-aaaae-af2dq-cai*\") | stats count by src_ip, dest, url, user | where count > 5 | sort - count",
    output_format="markdown"
)
```

**Result:**
```markdown
| src_ip | dest | url | user | count |
|--------|------|-----|------|-------|
| 10.0.1.50 | 185.220.101.45 | https://tdtqy-oyaaa-aaaae-af2dq-cai.ic0.app | jdoe | 127 |
| 10.0.1.51 | 185.220.101.45 | https://tdtqy-oyaaa-aaaae-af2dq-cai.raw.ic0.app | msmith | 45 |
| 10.0.2.10 | 185.220.101.46 | https://tdtqy-oyaaa-aaaae-af2dq-cai.ic0.app | admin | 23 |
```

🎯 **Detection confirmed!** Three hosts are communicating with the malicious ICP Canister.

#### Step 6: Create Saved Search (Splunk MCP)

Now that you've validated the detection, save it for continuous monitoring:

```python
# This would be done via Splunk UI or API
# The saved search can then be accessed via get_saved_searches()
```

## Common Workflows

### Workflow 1: Phishing Incident Investigation

```python
# 1. Auto-detect techniques
intel_to_log_sources(
    intel_text="Phishing email with malicious PowerShell attachment",
    siem_platforms="splunk"
)

# 2. Get generated query for T1059.001 (PowerShell)
# Query: index=windows EventCode=4104 | search ScriptBlockText=*DownloadString*

# 3. Validate query
validate_spl(query="<generated query>")

# 4. Execute if safe
search_oneshot(query="<validated query>", output_format="json")

# 5. Analyze results and create detection rule
```

### Workflow 2: Ransomware Detection

```python
# 1. Auto-detect techniques
intel_to_log_sources(
    intel_text="Ransomware with file encryption and log clearing",
    siem_platforms="splunk"
)

# Detected: T1486 (Ransomware), T1070.001 (Clear Logs)

# 2. Check for existing saved searches
get_saved_searches()

# 3. If no existing detection, generate and validate new query
# 4. Execute to test
# 5. Save as production rule
```

### Workflow 3: Cloud Account Compromise

```python
# 1. Auto-detect techniques
intel_to_log_sources(
    intel_text="AWS account compromise with privilege escalation",
    environment="aws",
    siem_platforms="splunk"
)

# 2. Discover available AWS indexes
get_indexes()

# 3. Validate CloudTrail query
validate_spl(query="index=aws_cloudtrail eventName=AssumeRole...")

# 4. Execute and analyze
search_oneshot(query="<validated query>")
```

## Advanced Features

### 1. Streaming Large Results

For queries that return many results, use `search_export`:

```python
search_export(
    query="index=proxy earliest=-7d url=*ic0.app* | stats count by src_ip, url",
    output_format="csv"
)
```

This streams results instead of loading everything into memory.

### 2. Leveraging Saved Searches

```python
# Get all saved searches
saved_searches = get_saved_searches()

# Find relevant detections
for search in saved_searches:
    if "c2" in search["name"].lower() or "command" in search["name"].lower():
        print(f"Existing detection: {search['name']}")
        
# Run a saved search
run_saved_search(name="C2_Detection_Baseline")
```

### 3. Index-Aware Query Generation

```python
# 1. Discover indexes
indexes = get_indexes()

# 2. Generate queries only for available indexes
available_indexes = [idx["name"] for idx in indexes["indexes"]]

# 3. Customize query generation
if "proxy" in available_indexes:
    query = "index=proxy ..."
elif "firewall" in available_indexes:
    query = "index=firewall ..."
```

## Safety Features

### Splunk MCP Guardrails

The Splunk MCP automatically protects against:

1. **Destructive Operations**
   - `delete`, `remove`, `drop`, `truncate`
   - Risk score: +30

2. **Resource-Intensive Patterns**
   - High cardinality grouping: `| stats count by *`
   - Risk score: +20
   - Long time ranges: `earliest=-90d`
   - Risk score: +15

3. **Missing Constraints**
   - No time bounds
   - Risk score: +25

4. **Data Exposure**
   - Automatic sanitization of credit cards, SSNs
   - Masked in all outputs

### Risk Score Thresholds

- **0-25**: Safe (green light)
- **26-50**: Caution (review recommended)
- **51-75**: Risky (requires approval)
- **76-100**: Dangerous (blocked by default)

## Troubleshooting

### Issue: "Connection refused to Splunk"

**Cause**: Splunk MCP can't reach your Splunk instance

**Solution**:
1. Verify Splunk is running: `https://your-splunk:8089`
2. Check `.env` credentials
3. Verify network connectivity
4. Check firewall rules for port 8089

### Issue: "No indexes found"

**Cause**: Splunk account doesn't have read permissions

**Solution**:
1. Grant `search` role to the Splunk account
2. Verify index permissions: `| eventcount summarize=false index=*`

### Issue: "Query validation failed"

**Cause**: Query contains risky patterns

**Solution**:
1. Review the `risks` array in validation result
2. Apply recommended fixes
3. Add time constraints
4. Reduce cardinality

### Issue: "Generated query doesn't match my environment"

**Cause**: Query templates use generic index names

**Solution**:
1. Use `get_indexes()` to discover your index names
2. Customize the query template
3. Update index names (e.g., `index=proxy` → `index=your_proxy_logs`)

## Best Practices

### 1. Always Validate Before Execution

```python
# ❌ Bad
search_oneshot(query="<untested query>")

# ✅ Good
validation = validate_spl(query="<query>")
if validation["is_safe"]:
    search_oneshot(query="<query>")
else:
    print(f"Query is risky: {validation['risks']}")
```

### 2. Start with Short Time Ranges

```python
# ❌ Bad
query = "index=proxy url=*malicious*"  # Searches all time

# ✅ Good
query = "index=proxy earliest=-1h url=*malicious*"  # Last hour only
```

### 3. Use Saved Searches for Production

```python
# For ad-hoc investigation
search_oneshot(query="...")

# For continuous monitoring
# Create saved search in Splunk UI, then:
run_saved_search(name="ICP_Canister_C2_Detection")
```

### 4. Leverage Auto-Detection

```python
# ❌ Manual technique mapping
recommend_log_sources(technique_ids="T1071.001,T1090,T1573.002")

# ✅ Automatic detection
intel_to_log_sources(intel_text="<paste threat intel>")
```

### 5. Chain Multiple MCPs

```python
# 1. Threat Research MCP: Auto-detect techniques
intel_to_log_sources(intel_text="...")

# 2. Splunk MCP: Validate and execute
validate_spl(query="...")
search_oneshot(query="...")

# 3. fastmcp-threatintel: Enrich IOCs
# (if you have it installed)

# 4. Security-Detections-MCP: Find existing rules
# (if you have it installed)
```

## Performance Tips

### 1. Use `search_export` for Large Results

```python
# For > 10,000 events
search_export(query="...", output_format="csv")
```

### 2. Optimize Time Ranges

```python
# Start narrow, expand if needed
earliest=-1h  # 1 hour
earliest=-24h  # 1 day
earliest=-7d  # 1 week
```

### 3. Use Summary Indexing

```python
# For frequently-run queries, create summary indexes in Splunk
# Then query the summary instead of raw data
query = "index=summary_proxy ..."
```

## Security Considerations

1. **Credentials**: Never commit `.env` files
2. **Permissions**: Use read-only Splunk accounts for query generation
3. **Validation**: Always validate queries before production deployment
4. **Audit**: Both MCPs log all operations
5. **Network**: Use SSL/TLS for Splunk connections

## Future Enhancements

### Planned for v0.4

1. **Automatic Validation**: Validate all generated queries by default
2. **Index Discovery**: Auto-detect available indexes and tailor queries
3. **Saved Search Templates**: Generate saved search definitions
4. **Performance Optimization**: Use Splunk MCP's risk scoring to optimize queries
5. **Result Enrichment**: Automatically enrich IOCs with Splunk results

## References

- [Splunk MCP Server](https://github.com/splunk/splunk-mcp-server2)
- [Model Context Protocol](https://modelcontextprotocol.io/)
- [Splunk REST API](https://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTprolog)
- [SPL Reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/)
