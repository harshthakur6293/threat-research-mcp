# Integration Architecture

## Overview

This document describes the technical architecture of the optional MCP integration layer in `threat-research-mcp`.

## Design Principles

1. **Standalone First**: Core functionality works without any optional MCPs
2. **Graceful Degradation**: Helpful messages when integrations unavailable
3. **Environment-Based Config**: No hardcoded dependencies
4. **Runtime Detection**: Auto-detect available MCPs at startup
5. **Fail-Safe**: Return `None` instead of raising exceptions

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         MCP Client (Cursor/VS Code/Cline)               │
└─────────────────────────────────────────────────────────────────────────┘
                                      │
                                      │ JSON-RPC (stdio)
                                      ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         threat-research-mcp                             │
│                         (FastMCP Server)                                │
│                                                                         │
│  ┌───────────────────────────────────────────────────────────────────┐ │
│  │ MCP Tools (19 total)                                              │ │
│  │                                                                   │ │
│  │  Core Tools (Always Available):                                  │ │
│  │  - extract_iocs                                                   │ │
│  │  - intel_to_log_sources (auto-detect + log sources)              │ │
│  │  - recommend_log_sources (log sources for known techniques)      │ │
│  │  - analysis_product (full workflow)                              │ │
│  │  - attack_map, hunt, sigma, validate_sigma, etc.                 │ │
│  │                                                                   │ │
│  │  Enhanced Tools (Use Optional MCPs):                             │ │
│  │  - enhanced_intel_analysis (orchestrates all available MCPs)     │ │
│  │  - get_integration_status (check MCP availability)               │ │
│  └───────────────────────────────────────────────────────────────────┘ │
│                                                                         │
│  ┌───────────────────────────────────────────────────────────────────┐ │
│  │ Integration Layer                                                 │ │
│  │                                                                   │ │
│  │  MCPIntegrationManager:                                           │ │
│  │  - Singleton instance                                             │ │
│  │  - Reads environment variables                                    │ │
│  │  - Creates MCPClient instances                                    │ │
│  │  - Provides convenience methods                                   │ │
│  │                                                                   │ │
│  │  MCPClient (per external MCP):                                    │ │
│  │  - is_available() → bool                                          │ │
│  │  - call_tool(name, args) → Dict | None                            │ │
│  └───────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
                                      │
                    ┌─────────────────┼─────────────────┬─────────────────┐
                    │                 │                 │                 │
                    ▼                 ▼                 ▼                 ▼
          ┌──────────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
          │ fastmcp-         │ │ Security-    │ │ threat-      │ │ Splunk MCP   │
          │ threatintel      │ │ Detections-  │ │ hunting-mcp  │ │              │
          │                  │ │ MCP          │ │              │ │              │
          │ (optional)       │ │ (optional)   │ │ (optional)   │ │ (optional)   │
          │                  │ │              │ │              │ │              │
          │ Tools:           │ │ Tools:       │ │ Tools:       │ │ Tools:       │
          │ - analyze        │ │ - list_by_   │ │ - create_    │ │ - validate_  │
          │ - batch_analyze  │ │   mitre      │ │   behavioral │ │   spl        │
          │ - get_apt_info   │ │ - analyze_   │ │   _hunt      │ │ - execute_   │
          │                  │ │   procedure  │ │ - search_    │ │   query      │
          │                  │ │   _coverage  │ │   hearth     │ │ - list_      │
          │                  │ │              │ │              │ │   indexes    │
          └──────────────────┘ └──────────────┘ └──────────────┘ └──────────────┘
```

## Component Details

### 1. MCPClient

**Purpose**: Low-level client for calling individual MCP servers

**Key Methods**:
```python
class MCPClient:
    def __init__(self, server_name: str, command: str, args: List[str], env: Dict[str, str])
    def is_available() -> bool
    def call_tool(tool_name: str, arguments: Dict[str, Any]) -> Optional[Dict[str, Any]]
```

**Behavior**:
- `is_available()`: Checks if MCP server can be started (currently checks `--help`)
- `call_tool()`: Placeholder that returns `None` (full implementation in v0.4)
- No exceptions raised - returns `None` on failure

### 2. MCPIntegrationManager

**Purpose**: High-level manager for all optional integrations

**Key Methods**:
```python
class MCPIntegrationManager:
    def __init__()  # Reads env vars, creates clients
    def get_available_integrations() -> Dict[str, bool]
    def enrich_ioc(ioc: str) -> Optional[Dict[str, Any]]
    def check_existing_coverage(technique_id: str) -> Optional[Dict[str, Any]]
    def get_behavioral_hunt(technique_id: str) -> Optional[Dict[str, Any]]
    def validate_spl_query(query: str) -> Optional[Dict[str, Any]]
```

**Initialization**:
```python
# Reads environment variables
if os.getenv("ENABLE_FASTMCP_THREATINTEL") == "true":
    self.clients["fastmcp-threatintel"] = MCPClient(...)
```

**Singleton Pattern**:
```python
_integration_manager: Optional[MCPIntegrationManager] = None

def get_integration_manager() -> MCPIntegrationManager:
    global _integration_manager
    if _integration_manager is None:
        _integration_manager = MCPIntegrationManager()
    return _integration_manager
```

### 3. Enhanced Analysis Tools

**Purpose**: Orchestrate multiple MCPs for comprehensive analysis

**`enhanced_intel_analysis()`**:
```python
def enhanced_intel_analysis(
    intel_text: str,
    environment: str = "hybrid",
    siem_platforms: str = "splunk,sentinel,elastic",
    enrich_iocs: bool = True,
    check_coverage: bool = True,
    generate_behavioral_hunts: bool = True,
) -> str:
    manager = get_integration_manager()
    
    # Step 1: Core analysis (always available)
    core_analysis = intel_to_log_sources(intel_text, environment, siem_platforms)
    
    # Step 2: IOC enrichment (optional)
    if enrich_iocs and manager.clients.get("fastmcp-threatintel"):
        enriched_iocs = [manager.enrich_ioc(ioc) for ioc in iocs]
    
    # Step 3: Coverage check (optional)
    if check_coverage and manager.clients.get("security-detections"):
        coverage = [manager.check_existing_coverage(t) for t in techniques]
    
    # Step 4: Behavioral hunts (optional)
    if generate_behavioral_hunts and manager.clients.get("threat-hunting"):
        hunts = [manager.get_behavioral_hunt(t) for t in techniques]
    
    return json.dumps({
        "core_analysis": core_analysis,
        "enhanced_features": {
            "ioc_enrichment": enriched_iocs if available else {"enabled": False, "message": "..."},
            "coverage_check": coverage if available else {"enabled": False, "message": "..."},
            "behavioral_hunts": hunts if available else {"enabled": False, "message": "..."},
        }
    })
```

**`get_integration_status()`**:
```python
def get_integration_status() -> str:
    manager = get_integration_manager()
    available = manager.get_available_integrations()
    
    return json.dumps({
        "integrations": {
            "fastmcp-threatintel": {
                "available": available.get("fastmcp-threatintel", False),
                "purpose": "IOC enrichment",
                "install": "pip install fastmcp-threatintel",
                "env_vars": ["VIRUSTOTAL_API_KEY", "OTX_API_KEY"],
            },
            # ... other integrations
        },
        "summary": {
            "available_count": sum(1 for v in available.values() if v),
            "standalone_mode": sum(1 for v in available.values() if v) == 0,
        }
    })
```

## Configuration Flow

```
1. User sets environment variables
   ├─ ENABLE_FASTMCP_THREATINTEL=true
   ├─ VIRUSTOTAL_API_KEY=xxx
   └─ ...

2. MCPIntegrationManager.__init__() reads env vars
   ├─ Creates MCPClient for each enabled integration
   └─ Stores in self.clients dict

3. Tool calls get_integration_manager()
   └─ Returns singleton instance

4. Tool calls manager.enrich_ioc(ioc)
   ├─ Checks if client exists and is available
   ├─ Calls client.call_tool("analyze", {"ioc": ioc})
   └─ Returns result or None

5. Tool includes result in output
   ├─ If result: Include enrichment data
   └─ If None: Include helpful message
```

## Error Handling

**Philosophy**: Never raise exceptions for missing integrations

**Pattern**:
```python
# BAD - raises exception
def enrich_ioc(ioc: str) -> Dict[str, Any]:
    if not self.clients.get("fastmcp-threatintel"):
        raise ValueError("fastmcp-threatintel not available")
    return self.clients["fastmcp-threatintel"].call_tool("analyze", {"ioc": ioc})

# GOOD - returns None
def enrich_ioc(ioc: str) -> Optional[Dict[str, Any]]:
    client = self.clients.get("fastmcp-threatintel")
    if not client or not client.is_available():
        return None
    return client.call_tool("analyze", {"ioc": ioc})
```

**Caller handles None**:
```python
enrichment = manager.enrich_ioc("1.2.3.4")
if enrichment:
    result["ioc_enrichment"] = {"enabled": True, "data": enrichment}
else:
    result["ioc_enrichment"] = {
        "enabled": False,
        "message": "fastmcp-threatintel not available. Install: pip install fastmcp-threatintel"
    }
```

## Testing Strategy

**Unit Tests** (`tests/test_mcp_integrations.py`):
- Test client initialization
- Test manager initialization with mocked env vars
- Test availability checks (with non-existent commands)
- Test tool calls return None when unavailable
- Test enhanced analysis with all combinations of available/unavailable MCPs
- Test graceful degradation messages

**No External Dependencies**:
- All tests use mocks or non-existent commands
- No actual MCP servers required
- Fast execution (< 1 second)

**Coverage**: 20 tests covering all integration scenarios

## Future Enhancements (v0.4)

### Full MCP Protocol Implementation

**Current** (placeholder):
```python
def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    # Placeholder - returns None
    return None
```

**Future** (full implementation):
```python
def call_tool(self, tool_name: str, arguments: Dict[str, Any], timeout: int = 30) -> Optional[Dict[str, Any]]:
    # 1. Start MCP server process
    proc = subprocess.Popen(
        [self.command] + self.args,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=self.env,
    )
    
    # 2. Send JSON-RPC request via stdin
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": arguments,
        }
    }
    proc.stdin.write(json.dumps(request).encode() + b"\n")
    proc.stdin.flush()
    
    # 3. Read JSON-RPC response from stdout
    response_line = proc.stdout.readline()
    response = json.loads(response_line)
    
    # 4. Parse and return result
    if "result" in response:
        return response["result"]
    return None
```

### Additional Features
- Retry logic with exponential backoff
- Circuit breakers for failing MCPs
- Response caching (avoid duplicate calls)
- Parallel MCP calls (asyncio)
- Custom MCP plugin system

## Performance Considerations

**Current**:
- Sequential calls to each MCP
- No caching
- No retry logic
- Synchronous execution

**Future Optimizations**:
1. **Parallel calls**: Use `asyncio` to call multiple MCPs concurrently
2. **Caching**: Cache MCP responses for identical inputs (e.g., same IOC enrichment)
3. **Connection pooling**: Reuse MCP server processes instead of starting new ones
4. **Lazy loading**: Only start MCP servers when first tool call is made

## Security Considerations

1. **Environment variables**: Sensitive data (API keys) stored in env vars
2. **Subprocess execution**: Validate command and args before execution
3. **Timeout**: Prevent hanging on unresponsive MCPs
4. **Input validation**: Sanitize inputs before passing to external MCPs
5. **Output validation**: Validate MCP responses before returning to user

## Summary

The integration layer provides:
- ✅ Standalone operation (no mandatory dependencies)
- ✅ Runtime detection of available MCPs
- ✅ Graceful degradation with helpful messages
- ✅ Environment-based configuration
- ✅ Singleton manager for efficiency
- ✅ Fail-safe error handling (no exceptions)
- ✅ Comprehensive test coverage
- ⏳ Full MCP protocol implementation (v0.4)
- ⏳ Performance optimizations (v0.4)
