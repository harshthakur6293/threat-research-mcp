# Graph Features Summary (v0.5 Planning)

## 🎯 What Are We Building?

Transform `threat-research-mcp` from **linear intelligence analysis** to **relationship-aware threat intelligence** using graph data structures.

## 📊 The Problem Today

```
Current: Intel → Extract IOCs → Map Techniques → Generate Detections
         (each step is isolated, no memory of relationships)
```

**Limitations:**
- Can't answer "Who's behind this attack?"
- Can't predict "What technique comes next?"
- Can't track "Are these 3 incidents related?"
- Can't identify "Which techniques lack detections?"

## 🚀 The Solution: Graph Intelligence

```
Future: All entities (actors, campaigns, IOCs, techniques) in a graph
        Query relationships, predict patterns, track campaigns
```

**New Capabilities:**
1. **Attribution**: "85% confidence APT29 based on IOC/technique overlap"
2. **Prediction**: "89% chance of T1027 (obfuscation) next"
3. **Campaign Tracking**: "This IOC links to 3 APT29 campaigns (2020-2022)"
4. **Gap Analysis**: "15/47 APT29 techniques lack detections"

## 🛠️ Technical Approach

### Core Technology: NetworkX (Python)
- ✅ Zero external dependencies (works standalone)
- ✅ Rich graph algorithms (shortest path, centrality)
- ✅ Fast for medium graphs (<100K nodes)
- ✅ Easy serialization (GraphML, JSON)

### Optional: Neo4j (Enterprise)
- For users needing millions of nodes
- Cypher query language
- Built-in visualization

### Data Model
```
Nodes (Entities):
- ThreatActor (APT29, Lazarus)
- Campaign (SolarWinds, WannaCry)
- IOC (IP, domain, hash)
- Technique (ATT&CK T1566.001)
- Malware, Tool, Victim, Detection

Edges (Relationships):
- ATTRIBUTED_TO (Campaign → ThreatActor)
- USES (ThreatActor → Technique)
- INDICATES (IOC → Campaign)
- PRECEDES (Technique → Technique)
- DETECTS (Detection → Technique)
```

## 🎨 Visual Examples

### Example 1: Threat Actor Attribution
```
Found IOCs: 185.220.101.45, avsvmcloud.com
Found Techniques: T1566.001, T1059.001

Graph Analysis:
  IOCs → INDICATES → SolarWinds Campaign
  Campaign → ATTRIBUTED_TO → APT29
  Techniques → USED_BY → APT29

Result: 85% confidence APT29
```

### Example 2: Attack Chain Prediction
```
Observed: T1566.001 (Phishing) → T1059.001 (PowerShell)

Graph Lookup (PRECEDES relationships):
  T1059.001 → T1027 (89% probability)
  T1027 → T1053.005 (67% probability)
  T1027 → T1071.001 (54% probability)

Result: Watch for obfuscation next, then persistence or C2
```

## 🔧 New MCP Tools (5 Total)

1. **`attribute_threat_actor`**
   - Input: IOCs + techniques
   - Output: Top 3 threat actors with confidence scores

2. **`predict_next_techniques`**
   - Input: Observed techniques
   - Output: Likely next techniques with probabilities

3. **`find_related_campaigns`**
   - Input: IOC
   - Output: Related campaigns, actors, graph visualization

4. **`find_detection_gaps`**
   - Input: Threat actor
   - Output: Techniques lacking detection coverage

5. **`visualize_threat_landscape`**
   - Input: Entity + depth
   - Output: Mermaid graph for rendering

## 📁 Implementation Files

```
src/threat_research_mcp/
├── graph/
│   ├── manager.py          # Core graph engine (NetworkX)
│   ├── entities.py         # Entity models
│   ├── builder.py          # Auto-populate from analysis
│   └── visualization.py    # Mermaid/D3.js export
├── tools/
│   └── graph_tools.py      # 5 new MCP tools
└── integrations/
    └── neo4j/              # Optional Neo4j connector

scripts/
└── build_threat_graph.py   # Initialize graph from profiles

tests/
└── test_graph.py           # 20+ graph tests

docs/
├── GRAPH-FEATURE-PLAN.md   # Complete plan (this doc)
└── GRAPH-QUICK-VISUAL.md   # Visual examples
```

## 📈 Success Metrics

- **Graph Size**: 500+ nodes, 2000+ edges by v0.5.0
- **Attribution Accuracy**: >80% on known APT scenarios
- **Prediction Accuracy**: >70% for next-technique
- **Performance**: <100ms for 2-hop queries
- **Tests**: 20+ graph-specific tests

## 🗓️ Timeline

### v0.5.0 (Q2 2026) - Core Graph Engine
- NetworkX graph manager
- 5 new MCP tools
- Auto-populate from threat actor profiles
- Mermaid visualization
- 20+ tests

### v0.5.1 (Q2 2026) - Visualization
- Interactive D3.js export
- Enhanced Mermaid styling
- GraphML/JSON export

### v0.5.2 (Q3 2026) - Enterprise
- Optional Neo4j connector
- Graph persistence
- Bulk STIX/MISP import

### v0.6.0 (Q3 2026) - Advanced Intelligence
- ML-based campaign clustering
- Temporal analysis
- Similarity scoring

## 🎯 Why This Matters

### For SOC Analysts
- **Faster Attribution**: "Is this APT29?" answered in seconds
- **Predictive Defense**: Know what's coming next
- **Campaign Tracking**: Connect the dots across incidents

### For Threat Hunters
- **Pivot Analysis**: "Show me everything related to this IOC"
- **Pattern Recognition**: Identify similar attack patterns
- **Coverage Gaps**: Focus hunting where detections are weak

### For Detection Engineers
- **Gap Analysis**: Prioritize detection development
- **Context-Aware Detections**: Build detections for attack chains
- **Validation**: Test detections against known actor TTPs

## 📚 Documentation

- **[GRAPH-FEATURE-PLAN.md](GRAPH-FEATURE-PLAN.md)** - Complete implementation plan (20+ pages)
- **[GRAPH-QUICK-VISUAL.md](GRAPH-QUICK-VISUAL.md)** - Visual examples and diagrams
- **[ROADMAP.md](../.github/ROADMAP.md)** - Updated project roadmap

## 🤝 Contributing

Graph features are **high priority** for v0.5. We welcome:
- Graph algorithm implementations
- Visualization improvements
- Real-world attack chain data
- Neo4j connector contributions

See `CONTRIBUTING.md` for guidelines.

## 🔗 Related Features

- **Current (v0.4)**: Threat actor profiles, log source recommendations
- **Next (v0.5)**: Graph intelligence (this plan)
- **Future (v0.6)**: ML clustering, temporal analysis
- **Future (v0.7+)**: MISP/OpenCTI integration, semantic search

---

**Questions?** Open an issue with the `graph` label or see the full plan in `GRAPH-FEATURE-PLAN.md`.
