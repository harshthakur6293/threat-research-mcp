# Threat Hunting MCP Integration Guide

## Overview

The [threat-hunting-mcp-server](https://github.com/THORCollective/threat-hunting-mcp-server) brings **behavioral hunting** capabilities that perfectly complement your threat-research-mcp. While you focus on technique detection and log sources, threat-hunting-mcp focuses on **hunting for behaviors at the top of the Pyramid of Pain**.

## Why Integrate?

| Capability | threat-research-mcp | threat-hunting-mcp | Combined Power |
|------------|-------------------|-------------------|----------------|
| **Technique Detection** | ✅ Auto-detect from intel | ❌ | Auto-detect techniques from threat intel |
| **Log Source Recommendations** | ✅ Specific logs + queries | ❌ | Know which logs to collect |
| **Behavioral Hunt Hypotheses** | ❌ | ✅ TTP-focused hunts | Hunt for behaviors that persist across tool changes |
| **HEARTH Community Hunts** | ❌ | ✅ 50+ curated hunts | Access real-world hunt scenarios |
| **Cognitive Bias Detection** | ❌ | ✅ ACH methodology | Avoid confirmation bias in investigations |
| **Graph-Based Attack Analysis** | ❌ | ✅ Attack paths, LOLBins | Identify multi-stage attacks |
| **Deception Technology** | ❌ | ✅ Honeytokens, decoys | High-confidence threat detection |

**Together:** Complete pipeline from threat intel → techniques → log sources → behavioral hunts → execution

## Philosophy: Pyramid of Pain

### threat-hunting-mcp's Core Philosophy

```
                            ▲
                           / \
                          /   \ 🎯 TOUGH (Hunt Here!)
                         / TTPs\ ← threat-hunting-mcp focuses here
                        /———————\
                       /         \
                      / 🛠️  Tools \
                     /—————————————\
                    /               \
                   / 📊 Host/Network \
                  /———————————————————\
                 /                     \
                /  🌐 Domain Names      \
               /—————————————————————————\
              /                           \
             /     🔢 IP Addresses         \
            /———————————————————————————————\
           /                                 \
          /       #️⃣  Hash Values             \
         /—————————————————————————————————————\
```

**Key Insight:** Hunt for behaviors (TTPs) that are **hard for adversaries to change**, not indicators that change hourly.

### How This Complements Your Project

**threat-research-mcp:** Detects techniques and provides log sources  
**threat-hunting-mcp:** Provides behavioral hunt hypotheses for those techniques  

**Example for T1071.001 (Web Protocols):**
- **Your MCP:** "Enable proxy logs, monitor HTTP/HTTPS traffic"
- **threat-hunting-mcp:** "Hunt for C2 beaconing patterns: regular intervals, consistent payload sizes, regardless of specific domains/IPs"

## Setup

### 1. Install threat-hunting-mcp

```bash
# Clone the repository
git clone https://github.com/THORCollective/threat-hunting-mcp-server
cd threat-hunting-mcp-server

# Clone HEARTH (community hunt repository)
git clone https://github.com/THORCollective/HEARTH ../HEARTH

# Install dependencies
pip install -r requirements.txt

# Optional: Install spaCy for NLP
python -m spacy download en_core_web_lg

# Configure
cp .env.example .env
# Edit .env (minimal config works for HEARTH features)
```

### 2. Configure in Your MCP Client

Add to your MCP configuration:

```json
{
  "mcpServers": {
    "threat-research": {
      "command": "python",
      "args": ["-m", "threat_research_mcp.server"],
      "cwd": "c:\\Dev\\Vibe Coding\\threat-research-mcp"
    },
    "threat-hunting": {
      "command": "python",
      "args": ["-u", "run_server.py"],
      "cwd": "c:\\path\\to\\threat-hunting-mcp-server"
    }
  }
}
```

## Complete Workflow: ICP Canister C2 Behavioral Hunt

### Step 1: Auto-Detect Techniques (threat-research-mcp)

```python
intel_to_log_sources(
    intel_text="ICP Canister C2 using blockchain for censorship-resistant command and control",
    siem_platforms="splunk"
)
```

**Result:**
- Detected: T1071.001, T1090, T1573.002
- Log sources: Proxy, firewall, network logs
- Splunk query generated

### Step 2: Get Behavioral Hunt Hypothesis (threat-hunting-mcp)

```python
# Search for C2 behavioral hunts
search_community_hunts(
    tactic="Command and Control",
    keyword="beaconing"
)
```

**Result from HEARTH:**
```json
{
  "hunt_id": "FLAME-042",
  "title": "C2 Beaconing Pattern Detection",
  "hypothesis": "Adversaries establish persistent C2 channels with regular beaconing patterns, regardless of infrastructure",
  "behavioral_indicators": [
    "Regular connection intervals (e.g., every 60 seconds)",
    "Consistent payload sizes",
    "Long-lived connections to external IPs",
    "Traffic during off-hours"
  ],
  "detection_logic": "Hunt for network connections with statistical regularity, not specific domains/IPs",
  "technique_ids": ["T1071.001", "T1071.004"],
  "data_sources": ["Network Traffic", "Proxy Logs", "Firewall Logs"]
}
```

### Step 3: Generate Behavioral Hunt Query (threat-hunting-mcp)

```python
# Create behavioral hunt for ICP C2
create_behavioral_hunt(
    technique_id="T1071.001",
    hypothesis="ICP Canister C2 exhibits regular beaconing patterns to blockchain nodes",
    data_sources=["proxy", "firewall"]
)
```

**Generated Behavioral Hunt Query (Splunk):**
```spl
index=proxy earliest=-24h
| stats count, avg(bytes_out), stdev(bytes_out), dc(url) as unique_urls by src_ip, dest
| eval regularity_score = if(stdev < 100 AND count > 20, 1, 0)
| eval beacon_pattern = if(regularity_score=1 AND unique_urls < 5, "likely_c2", "normal")
| where beacon_pattern="likely_c2"
| eval hunt_hypothesis="Regular beaconing to limited destinations (behavioral, not IOC-based)"
| table src_ip, dest, count, avg_bytes, stdev_bytes, unique_urls, beacon_pattern
```

**Key Difference from IOC-Based Detection:**
- ❌ IOC-based: `url="*tdtqy-oyaaa-aaaae-af2dq-cai*"` (breaks when Canister ID changes)
- ✅ Behavioral: Statistical regularity + limited destinations (persists across infrastructure changes)

### Step 4: Validate and Execute (Splunk MCP)

```python
# Validate behavioral query
validate_spl(query="<behavioral hunt query>")

# Execute
search_oneshot(query="<validated query>")
```

**Result:**
```markdown
| src_ip | dest | count | avg_bytes | stdev_bytes | unique_urls | beacon_pattern |
|--------|------|-------|-----------|-------------|-------------|----------------|
| 10.0.1.50 | 185.220.101.45 | 127 | 2456 | 45 | 2 | likely_c2 |
| 10.0.1.51 | 185.220.101.45 | 45 | 2401 | 38 | 1 | likely_c2 |
| 10.0.2.10 | 185.220.101.46 | 23 | 2478 | 52 | 2 | likely_c2 |
```

🎯 **Behavioral detection works even if the Canister ID changes!**

## Key Integration Patterns

### Pattern 1: IOC → Behavioral Hunt

**Problem:** IOCs change rapidly (ICP Canister IDs can be rotated)

**Solution:** Pivot from IOC to behavioral hunt

```python
# 1. Extract IOC (threat-research-mcp)
extract_iocs(text="ICP Canister ID: tdtqy-oyaaa-aaaae-af2dq-cai")

# 2. Pivot to behavioral hunt (threat-hunting-mcp)
suggest_behavioral_hunt_from_ioc(
    ioc="tdtqy-oyaaa-aaaae-af2dq-cai.ic0.app",
    ioc_type="domain"
)

# Returns: Hunt for blockchain C2 beaconing patterns, not specific Canister IDs
```

### Pattern 2: Technique → Behavioral Hunt

**Problem:** Need hunt hypotheses for detected techniques

**Solution:** Get community-curated behavioral hunts

```python
# 1. Auto-detect techniques (threat-research-mcp)
intel_to_log_sources(intel_text="...")
# → Detects: T1071.001, T1090

# 2. Get behavioral hunts (threat-hunting-mcp)
search_community_hunts(tactic="Command and Control")
# → Returns: 8 behavioral hunt hypotheses for C2 detection

# 3. Get log sources (threat-research-mcp)
recommend_log_sources(technique_ids="T1071.001,T1090")
# → Returns: Proxy, firewall logs needed

# 4. Execute behavioral hunt (threat-hunting-mcp + Splunk MCP)
hunt_threats(query="Hunt for C2 beaconing patterns", framework="PEAK")
```

### Pattern 3: Incident → Behavioral Investigation

**Problem:** Need to investigate incident with behavioral lens

**Solution:** Use incident-driven hunt suggestions

```python
# 1. Analyze incident (threat-research-mcp)
analysis_product(text="ICP Canister C2 incident...")

# 2. Get hunt suggestions (threat-hunting-mcp)
suggest_hunts_for_incident(
    description="Blockchain-based C2 with encrypted channels"
)

# Returns:
# - Hunt for statistical beaconing patterns
# - Hunt for encrypted channel behaviors
# - Hunt for proxy-like traffic patterns
```

### Pattern 4: Coverage Gap → Behavioral Hunt

**Problem:** Security-Detections-MCP found a gap, need to hunt for it

**Solution:** Generate behavioral hunt hypothesis

```python
# 1. Find gap (Security-Detections-MCP)
analyze_procedure_coverage(technique_id="T1003.001")
# → Gap: NanoDump not covered

# 2. Generate behavioral hunt (threat-hunting-mcp)
create_behavioral_hunt(
    technique_id="T1003.001",
    hypothesis="Hunt for LSASS memory access patterns, regardless of dumping tool"
)

# 3. Get log sources (threat-research-mcp)
recommend_log_sources(technique_ids="T1003.001")
# → Sysmon Event ID 10, Security Event ID 4656
```

## Complete 5-MCP Ecosystem

### The Full Stack

```
Threat Intel
    ↓
[threat-research-mcp] → Techniques + Log Sources + Queries
    ↓
[threat-hunting-mcp] → Behavioral Hunt Hypotheses + HEARTH Community Hunts
    ↓
[fastmcp-threatintel] → IOC Enrichment + Reputation
    ↓
[Security-Detections-MCP] → Existing Coverage + Gaps + Templates
    ↓
[Splunk MCP] → Validation + Execution + Results
```

### Tool Count: 123+ Total Tools

| MCP | Tools | Key Focus |
|-----|-------|-----------|
| **threat-research-mcp** | 17 | Technique detection, log sources |
| **threat-hunting-mcp** | 20+ | Behavioral hunts, HEARTH community |
| **fastmcp-threatintel** | 7 | IOC enrichment, reputation |
| **Security-Detections-MCP** | 71+ | 8,200+ existing rules, coverage gaps |
| **Splunk MCP** | 7 | Query validation, execution |
| **TOTAL** | **123+ tools** | **Complete threat intelligence + hunting platform** |

## Real-World Example: ICP Canister C2

### Complete Investigation Workflow

**Step 1: Threat Intel Analysis** (threat-research-mcp)
```python
intel_to_log_sources(
    intel_text="ICP Canister C2 using blockchain...",
    siem_platforms="splunk"
)
# → T1071.001, T1090, T1573.002 detected
# → Proxy/firewall logs recommended
```

**Step 2: Behavioral Hunt Generation** (threat-hunting-mcp)
```python
# Search HEARTH for C2 behavioral hunts
search_community_hunts(
    tactic="Command and Control",
    tags=["beaconing", "encrypted"]
)

# Generate custom behavioral hunt
create_behavioral_hunt(
    technique_id="T1071.001",
    hypothesis="Blockchain C2 exhibits regular beaconing patterns regardless of Canister ID rotation"
)
```

**Step 3: IOC Enrichment** (fastmcp-threatintel)
```python
analyze(ioc="185.220.101.45")
# → 85% abuse confidence
# → Amsterdam, Netherlands
# → OVH hosting
```

**Step 4: Coverage Check** (Security-Detections-MCP)
```python
list_by_mitre(technique_id="T1071.001")
# → 109 existing detections
# → Gap: Blockchain/Web3 C2 behavioral patterns
```

**Step 5: Execute Behavioral Hunt** (Splunk MCP)
```python
# Validate behavioral query
validate_spl(query="<behavioral hunt query>")

# Execute
search_oneshot(query="<validated query>")
# → 3 hosts with beaconing patterns detected
```

**Step 6: Cognitive Analysis** (threat-hunting-mcp)
```python
# Check for cognitive biases
# threat-hunting-mcp automatically:
# - Detects confirmation bias (only looking for known Canister IDs)
# - Suggests competing hypotheses (legitimate blockchain apps?)
# - Provides stopping criteria (when to conclude hunt)
```

## Unique Features for Your Use Cases

### 1. Behavioral Detection for Web3/Blockchain C2

**Your Challenge:** ICP Canister IDs can be rotated, domain-based blocking fails

**threat-hunting-mcp Solution:**
```python
# Instead of hunting for specific Canister IDs
# Hunt for behavioral patterns:

hunt_threats(
    query="Hunt for blockchain C2 beaconing patterns with regular intervals",
    framework="PEAK"
)
```

**Behavioral Indicators:**
- Regular connection intervals (statistical analysis)
- Consistent payload sizes (beaconing behavior)
- Limited unique destinations (focused C2 communication)
- Traffic to blockchain infrastructure (*.ic0.app patterns)

**Benefit:** Detection survives Canister ID rotation

### 2. Living-off-the-Land Detection

**Your Challenge:** Detecting legitimate tools used maliciously

**threat-hunting-mcp Solution:**
```python
# Graph-based LOLBin detection
# Analyzes process relationships and behavioral context
```

**Example:** PowerShell downloading from blockchain C2
- Not just "PowerShell executed" (too noisy)
- But "PowerShell → Network connection → Blockchain domain → File write" (behavioral chain)

### 3. Deception Technology for High-Confidence Detection

**Your Challenge:** Reducing false positives in blockchain traffic

**threat-hunting-mcp Solution:**
```python
# Deploy honeytokens
# If fake AWS keys/passwords are used, 95-99% confidence it's malicious
```

**For ICP C2:**
- Deploy fake Canister IDs in decoy configs
- Monitor for access attempts
- High-confidence detection with minimal false positives

### 4. HEARTH Community Hunts

**Your Challenge:** Need proven hunt hypotheses

**threat-hunting-mcp Solution:**
```python
# Access 50+ community-curated hunts
search_community_hunts(tactic="Command and Control")

# Get recommendations for your environment
recommend_hunts(
    environment="hybrid cloud",
    keywords=["c2", "encrypted"]
)
```

**Benefit:** Learn from community's behavioral hunting experience

## Integration Opportunities

### Opportunity 1: Behavioral Hunt Library

**Add to threat-research-mcp:**
- Link each technique to behavioral hunt hypotheses
- When generating log sources, also suggest behavioral hunts
- Example: T1071.001 → proxy logs + "hunt for beaconing patterns"

### Opportunity 2: IOC → Behavior Pivot

**Workflow:**
```python
# 1. Extract IOCs (threat-research-mcp)
iocs = extract_iocs(text="...")

# 2. Pivot to behavioral hunt (threat-hunting-mcp)
for ioc in iocs:
    behavioral_hunt = suggest_behavioral_hunt_from_ioc(ioc=ioc, ioc_type="domain")
    # Returns: Hunt for behaviors, not the specific IOC
```

### Opportunity 3: Cognitive Bias Detection

**Add to your analysis workflow:**
```python
# After generating detections, check for biases
# threat-hunting-mcp can detect:
# - Confirmation bias (only looking for known patterns)
# - Anchoring bias (fixating on first hypothesis)
# - Availability bias (overweighting recent incidents)
```

### Opportunity 4: Graph-Based Attack Correlation

**For multi-stage attacks:**
```python
# threat-hunting-mcp can correlate:
# Initial Access (phishing) → Execution (PowerShell) → C2 (blockchain) → Exfiltration
# Identifies attack paths and pivot points
```

### Opportunity 5: Hunt Stopping Criteria

**Prevent endless investigations:**
```python
# threat-hunting-mcp provides objective stopping criteria:
# - Hypothesis confirmed/rejected
# - All data sources exhausted
# - Diminishing returns threshold reached
```

## Comparison: IOC-Based vs Behavioral Hunting

### Your ICP Canister C2 Case

#### IOC-Based Detection (Traditional)
```spl
index=proxy url="*tdtqy-oyaaa-aaaae-af2dq-cai*"
| stats count by src_ip, url
```

**Pros:** Fast, specific  
**Cons:** Breaks when Canister ID changes (minutes/hours)

#### Behavioral Detection (threat-hunting-mcp)
```spl
index=proxy earliest=-24h
| stats count, avg(bytes_out), stdev(bytes_out), dc(dest) as unique_dests by src_ip
| eval regularity_score = if(stdev < 100 AND count > 20, 1, 0)
| eval limited_dests = if(unique_dests < 5, 1, 0)
| where regularity_score=1 AND limited_dests=1
| eval hunt_type="behavioral_c2_beaconing"
```

**Pros:** Survives infrastructure changes, detects unknown C2  
**Cons:** Requires baseline, may have more false positives initially

#### Combined Approach (Best)
```spl
# 1. IOC-based for immediate response
index=proxy url="*tdtqy-oyaaa-aaaae-af2dq-cai*" OR url="*ic0.app*"

# 2. Behavioral for durable detection
| append [search index=proxy earliest=-24h
  | stats count, stdev(bytes_out) by src_ip, dest
  | where stdev < 100 AND count > 20]

# 3. Combine results
| eval detection_type=if(match(url, "tdtqy-oyaaa"), "ioc_match", "behavioral_pattern")
| table src_ip, dest, url, count, detection_type
```

**Benefit:** Immediate IOC detection + long-term behavioral detection

## Best Practices

### 1. Start with Techniques, Add Behavioral Hunts

```python
# ❌ Don't just hunt for IOCs
search(query="tdtqy-oyaaa-aaaae-af2dq-cai")

# ✅ Detect techniques, then hunt for behaviors
intel_to_log_sources(intel_text="...")  # threat-research-mcp
search_community_hunts(tactic="Command and Control")  # threat-hunting-mcp
```

### 2. Use HEARTH for Proven Hypotheses

```python
# ✅ Leverage community knowledge
search_community_hunts(tactic="Credential Access")
# → 50+ proven behavioral hunt hypotheses
```

### 3. Combine IOC and Behavioral Detection

```python
# ✅ Use both approaches
# IOC-based: Immediate response
# Behavioral: Long-term resilience
```

### 4. Check for Cognitive Biases

```python
# ✅ Avoid tunnel vision
# threat-hunting-mcp detects:
# - Confirmation bias
# - Anchoring bias
# - Availability bias
```

### 5. Use Hunt Frameworks

```python
# ✅ Structure your hunts
create_behavioral_hunt(
    technique_id="T1071.001",
    framework="PEAK"  # or "TaHiTI", "SQRRL"
)
```

## Tool Reference

### threat-hunting-mcp Key Tools

**Core Hunting:**
- `hunt_threats` - Natural language behavioral hunting
- `create_behavioral_hunt` - Create PEAK hunt reports
- `suggest_behavioral_hunt_from_ioc` - Pivot IOC → behavior

**HEARTH Community:**
- `search_community_hunts` - Search 50+ curated hunts
- `recommend_hunts` - AI-powered hunt recommendations
- `suggest_hunts_for_incident` - Incident-driven suggestions

**Cognitive:**
- Automatic bias detection in hunt analysis
- Competing hypotheses generation
- Hunt stopping criteria

**Graph Analysis:**
- Attack path identification
- LOLBin detection
- Pivot point analysis

**Deception:**
- Honeytoken deployment
- Decoy system management
- Canary file deployment

## Future Enhancements

### Planned for threat-research-mcp v0.4

1. **Behavioral Hunt Integration**
   - Link each technique to HEARTH community hunts
   - Generate behavioral hunt hypotheses automatically
   - Provide both IOC and behavioral detection options

2. **Cognitive Bias Detection**
   - Add bias detection to analysis workflow
   - Suggest competing hypotheses
   - Provide objective stopping criteria

3. **Graph-Based Correlation**
   - Multi-stage attack detection
   - Attack path visualization
   - Pivot point identification

## References

- [threat-hunting-mcp-server](https://github.com/THORCollective/threat-hunting-mcp-server)
- [HEARTH Community Hunts](https://github.com/THORCollective/HEARTH)
- [Pyramid of Pain](https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html)
- [PEAK Framework](https://www.splunk.com/en_us/blog/security/peak-threat-hunting-framework.html)
- [TaHiTI Framework](https://www.betaalvereniging.nl/en/safety/tahiti/)
