# Graph Features: Visual Quick Reference

## 🎯 The Big Picture

### Current (v0.4): Linear Analysis
```
┌─────────────┐     ┌──────────┐     ┌───────────┐     ┌────────────┐
│ Threat Intel│────→│Extract   │────→│Map to     │────→│Generate    │
│   (Text)    │     │IOCs      │     │ATT&CK     │     │Detections  │
└─────────────┘     └──────────┘     └───────────┘     └────────────┘
```

### Future (v0.5+): Graph-Based Intelligence
```
                    ╔═══════════════════════════════╗
                    ║   THREAT INTELLIGENCE GRAPH   ║
                    ╚═══════════════════════════════╝
                                  │
        ┌─────────────────────────┼─────────────────────────┐
        │                         │                         │
        ▼                         ▼                         ▼
  ┌──────────┐              ┌──────────┐              ┌──────────┐
  │Attribution│              │Prediction│              │  Pivot   │
  │"Who did   │              │"What's   │              │"Show me  │
  │ this?"    │              │ next?"   │              │everything│
  └──────────┘              └──────────┘              └──────────┘
```

---

## 🗺️ Graph Data Model

```mermaid
graph TD
    subgraph "Entities (Nodes)"
        TA[🕵️ Threat Actor<br/>APT29, Lazarus]
        CAMP[🎯 Campaign<br/>SolarWinds, WannaCry]
        IOC[🚩 IOC<br/>IP, Domain, Hash]
        TECH[⚙️ Technique<br/>ATT&CK T1566.001]
        MAL[🦠 Malware<br/>SUNBURST, Cobalt Strike]
        TOOL[🔧 Tool<br/>Mimikatz, PowerShell]
        VIC[🏢 Victim<br/>Sector, Geography]
        DET[🛡️ Detection<br/>Sigma, KQL]
    end
    
    subgraph "Relationships (Edges)"
        TA -->|ATTRIBUTED_TO| CAMP
        CAMP -->|USES| TECH
        TA -->|CONTROLS| IOC
        IOC -->|INDICATES| CAMP
        MAL -->|IMPLEMENTS| TECH
        TECH -->|PRECEDES| TECH
        DET -->|DETECTS| TECH
        TA -->|TARGETS| VIC
    end
    
    style TA fill:#ff6b6b
    style CAMP fill:#4ecdc4
    style IOC fill:#ffe66d
    style TECH fill:#95e1d3
    style MAL fill:#f38181
    style TOOL fill:#ffd93d
    style VIC fill:#c7ceea
    style DET fill:#a8e6cf
```

---

## 🔍 Key Use Cases

### 1. Threat Actor Attribution
**Question:** "Who's behind this attack?"

```mermaid
graph LR
    IOC1[🚩 185.220.101.45] -->|INDICATES| CAMP1[🎯 SolarWinds]
    IOC2[🚩 avsvmcloud.com] -->|INDICATES| CAMP1
    TECH1[⚙️ T1566.001] -->|USED_IN| CAMP1
    TECH2[⚙️ T1059.001] -->|USED_IN| CAMP1
    CAMP1 -->|ATTRIBUTED_TO| APT29[🕵️ APT29<br/>Confidence: 85%]
    
    style IOC1 fill:#ffe66d
    style IOC2 fill:#ffe66d
    style TECH1 fill:#95e1d3
    style TECH2 fill:#95e1d3
    style CAMP1 fill:#4ecdc4
    style APT29 fill:#ff6b6b
```

**Result:** "85% confidence APT29 based on IOC/technique overlap"

---

### 2. Attack Chain Prediction
**Question:** "What technique comes next?"

```mermaid
graph LR
    T1[✅ T1566.001<br/>Phishing<br/>OBSERVED] -->|PRECEDES<br/>89%| T2[⚠️ T1059.001<br/>PowerShell<br/>OBSERVED]
    T2 -->|PRECEDES<br/>89%| T3[❓ T1027<br/>Obfuscation<br/>PREDICTED]
    T3 -->|PRECEDES<br/>67%| T4[❓ T1053.005<br/>Scheduled Task<br/>PREDICTED]
    T3 -->|PRECEDES<br/>54%| T5[❓ T1071.001<br/>Web C2<br/>PREDICTED]
    
    style T1 fill:#a8e6cf
    style T2 fill:#a8e6cf
    style T3 fill:#ffe66d
    style T4 fill:#ffcccc
    style T5 fill:#ffcccc
```

**Result:** "89% chance of obfuscation next, then persistence or C2"

---

### 3. Campaign Tracking
**Question:** "What campaigns used this IOC?"

```mermaid
graph TD
    IOC[🚩 185.220.101.45<br/>Investigate This] -->|INDICATES| C1[🎯 SolarWinds<br/>2020]
    IOC -->|INDICATES| C2[🎯 NOBELIUM<br/>2021]
    IOC -->|INDICATES| C3[🎯 Cloud Targeting<br/>2022]
    
    C1 -->|ATTRIBUTED_TO| APT29[🕵️ APT29]
    C2 -->|ATTRIBUTED_TO| APT29
    C3 -->|ATTRIBUTED_TO| APT29
    
    C1 -->|USES| T1[⚙️ T1195.002<br/>Supply Chain]
    C2 -->|USES| T2[⚙️ T1566.001<br/>Phishing]
    C3 -->|USES| T3[⚙️ T1078.004<br/>Cloud Accounts]
    
    style IOC fill:#ffe66d
    style C1 fill:#4ecdc4
    style C2 fill:#4ecdc4
    style C3 fill:#4ecdc4
    style APT29 fill:#ff6b6b
    style T1 fill:#95e1d3
    style T2 fill:#95e1d3
    style T3 fill:#95e1d3
```

**Result:** "IOC linked to 3 APT29 campaigns spanning 2020-2022"

---

### 4. Detection Gap Analysis
**Question:** "What techniques lack detections?"

```mermaid
graph TD
    APT29[🕵️ APT29] -->|USES| T1[⚙️ T1566.001<br/>Phishing]
    APT29 -->|USES| T2[⚙️ T1059.001<br/>PowerShell]
    APT29 -->|USES| T3[⚙️ T1027<br/>Obfuscation]
    APT29 -->|USES| T4[⚙️ T1550.001<br/>App Token]
    APT29 -->|USES| T5[⚙️ T1078.004<br/>Cloud Accounts]
    
    D1[🛡️ Sigma Rule] -->|DETECTS| T1
    D2[🛡️ KQL Query] -->|DETECTS| T2
    D3[🛡️ SPL Query] -->|DETECTS| T3
    
    T4 -.->|NO DETECTION| GAP1[❌ GAP]
    T5 -.->|NO DETECTION| GAP2[❌ GAP]
    
    style APT29 fill:#ff6b6b
    style T1 fill:#a8e6cf
    style T2 fill:#a8e6cf
    style T3 fill:#a8e6cf
    style T4 fill:#ffcccc
    style T5 fill:#ffcccc
    style D1 fill:#a8e6cf
    style D2 fill:#a8e6cf
    style D3 fill:#a8e6cf
    style GAP1 fill:#ff6b6b
    style GAP2 fill:#ff6b6b
```

**Result:** "2/5 techniques lack detections (T1550.001, T1078.004)"

---

## 🛠️ New MCP Tools (v0.5)

### Tool 1: `attribute_threat_actor`
```python
Input:
  iocs: ["185.220.101.45", "avsvmcloud.com"]
  techniques: ["T1566.001", "T1059.001"]

Output:
  {
    "APT29": 0.85,
    "APT28": 0.10,
    "UNC2452": 0.05
  }
```

### Tool 2: `predict_next_techniques`
```python
Input:
  observed_techniques: ["T1566.001", "T1059.001"]

Output:
  {
    "T1027": 0.89,      # Obfuscation
    "T1053.005": 0.67,  # Scheduled Task
    "T1071.001": 0.54   # Web C2
  }
```

### Tool 3: `find_related_campaigns`
```python
Input:
  ioc: "185.220.101.45"
  max_distance: 2

Output:
  {
    "campaigns": ["SolarWinds", "NOBELIUM"],
    "threat_actors": ["APT29", "UNC2452"],
    "graph": "mermaid syntax..."
  }
```

### Tool 4: `find_detection_gaps`
```python
Input:
  threat_actor: "APT29"

Output:
  {
    "coverage": {"total": 47, "covered": 32, "uncovered": 15},
    "gaps": ["T1550.001", "T1078.004", "T1199"],
    "recommendations": [...]
  }
```

### Tool 5: `visualize_threat_landscape`
```python
Input:
  center_entity: "APT29"
  depth: 2

Output:
  "graph TD\n    APT29 --> T1566.001\n    ..."
```

---

## 📊 Real-World Example

### Scenario: SOC Analyst Investigating Alert

**Step 1: Initial Alert**
```
Alert: Suspicious PowerShell execution
Host: WORKSTATION-42
User: jdoe
Command: powershell -enc <base64>
```

**Step 2: Extract Context**
```
IOCs Found:
- IP: 185.220.101.45
- Domain: avsvmcloud.com
- Hash: a1b2c3d4...

Techniques Detected:
- T1059.001 (PowerShell)
- T1027 (Obfuscation)
```

**Step 3: Graph Analysis**

```mermaid
graph TD
    ALERT[🚨 Alert<br/>PowerShell -enc] -->|EXTRACT| IOC1[🚩 185.220.101.45]
    ALERT -->|EXTRACT| IOC2[🚩 avsvmcloud.com]
    ALERT -->|DETECT| T1[⚙️ T1059.001]
    ALERT -->|DETECT| T2[⚙️ T1027]
    
    IOC1 -->|INDICATES| CAMP[🎯 SolarWinds<br/>Campaign]
    IOC2 -->|INDICATES| CAMP
    
    CAMP -->|ATTRIBUTED_TO| APT29[🕵️ APT29<br/>85% confidence]
    
    T1 -->|PRECEDES| T3[⚠️ T1071.001<br/>Web C2<br/>PREDICTED]
    T2 -->|PRECEDES| T3
    T3 -->|PRECEDES| T4[⚠️ T1041<br/>Exfiltration<br/>PREDICTED]
    
    style ALERT fill:#ff6b6b
    style IOC1 fill:#ffe66d
    style IOC2 fill:#ffe66d
    style T1 fill:#a8e6cf
    style T2 fill:#a8e6cf
    style T3 fill:#ffcccc
    style T4 fill:#ffcccc
    style CAMP fill:#4ecdc4
    style APT29 fill:#ff6b6b
```

**Step 4: Actionable Intelligence**
```
Attribution: APT29 (85% confidence)
Campaign: Likely SolarWinds-related activity
Next Steps:
  1. Monitor for Web C2 (T1071.001) - 89% probability
  2. Watch for exfiltration attempts (T1041)
  3. Check for lateral movement to other hosts
  4. Review cloud account activity (T1078.004)
  
Recommended Detections:
  - Deploy Sigma rule for APT29 PowerShell patterns
  - Alert on connections to known APT29 infrastructure
  - Monitor for scheduled task creation (T1053.005)
```

---

## 🎨 Visualization Styles

### Style 1: Threat Actor Landscape
```mermaid
graph TD
    APT29[🕵️ APT29<br/>Cozy Bear] -->|USES| T1[⚙️ T1566.001]
    APT29 -->|USES| T2[⚙️ T1059.001]
    APT29 -->|CONTROLS| IOC1[🚩 185.220.101.45]
    APT29 -->|TARGETS| VIC1[🏢 Government]
    APT29 -->|TARGETS| VIC2[🏢 Healthcare]
    
    style APT29 fill:#ff6b6b,stroke:#333,stroke-width:3px
    style T1 fill:#95e1d3
    style T2 fill:#95e1d3
    style IOC1 fill:#ffe66d
    style VIC1 fill:#c7ceea
    style VIC2 fill:#c7ceea
```

### Style 2: Attack Timeline
```mermaid
gantt
    title APT29 Attack Chain Timeline
    dateFormat HH:mm
    section Initial Access
    Spearphishing Email    :done, 09:00, 09:15
    section Execution
    PowerShell -enc        :done, 09:15, 09:20
    section Defense Evasion
    Obfuscation            :done, 09:20, 09:25
    section C2
    Web Protocol C2        :active, 09:25, 09:45
    section Exfiltration
    Data Staging           :crit, 09:45, 10:00
    C2 Channel Exfil       :crit, 10:00, 10:15
```

### Style 3: Detection Coverage Heatmap
```
APT29 Technique Coverage:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Initial Access    ████████░░ 80% (4/5)
Execution         ██████████ 100% (5/5)
Persistence       ██████░░░░ 60% (3/5)
Defense Evasion   ████░░░░░░ 40% (2/5)
Credential Access ██████████ 100% (3/3)
Discovery         ████████░░ 75% (3/4)
Lateral Movement  ██████░░░░ 67% (2/3)
Collection        ████████░░ 80% (4/5)
C2                ████░░░░░░ 50% (2/4)
Exfiltration      ██████░░░░ 67% (2/3)
Impact            ██░░░░░░░░ 20% (1/5)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Overall Coverage: 68% (31/46 techniques)
```

---

## 🚀 Getting Started (When Released)

### 1. Build Initial Graph
```bash
# Auto-populate from threat actor profiles
python scripts/build_threat_graph.py

# Output: data/threat_intel_graph.graphml
# 500+ nodes, 2000+ edges
```

### 2. Use in MCP Client
```
User: "Attribute this attack: IOCs [185.220.101.45, avsvmcloud.com], 
       techniques [T1566.001, T1059.001]"