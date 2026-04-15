# threat-research-mcp v2.0: Complete Roadmap

**Transform from Pipeline to Multi-Agent Threat Intelligence Platform**

---

## 📋 Table of Contents

1. [Executive Summary](#executive-summary)
2. [Current State Analysis](#current-state-analysis)
3. [Vision: v2.0 Architecture](#vision-v20-architecture)
4. [Technology Stack](#technology-stack)
5. [Implementation Phases](#implementation-phases)
6. [Key Principles](#key-principles)
7. [Success Metrics](#success-metrics)
8. [User Journey Examples](#user-journey-examples)
9. [Next Steps](#next-steps)

---

## Executive Summary

### The Transformation

**From:** Sequential pipeline with named stages (v0.4)  
**To:** True multi-agent threat intelligence platform (v2.0)

### What We're Building

A comprehensive threat intelligence platform with:
- ✅ **LangGraph-based multi-agent system** with autonomous collaboration
- ✅ **CRADLE integration** for visualization and team collaboration
- ✅ **Multi-source intelligence enrichment** (15+ sources, BYOK)
- ✅ **Framework-based threat hunting** (PEAK, TaHiTI, SQRRL, Pyramid of Pain)
- ✅ **Multi-schema detection generation** (Sigma, KQL, SPL, EQL, CloudTrail, Azure, GCP)
- ✅ **Confidence scoring & attribution assessment** (transparent, with caveats)
- ✅ **Validation loops & human-in-the-loop** (automatic refinement)
- ✅ **Graph-based intelligence** (NetworkX → Neo4j for scale)

### Target Users

- **SOC Analysts**: Fast incident analysis with confidence scoring
- **Threat Hunters**: Framework-based hunt planning with community knowledge
- **Detection Engineers**: Multi-platform detection rules with validation

### Timeline

- **v0.5.0**: LangGraph Multi-Agent (6-8 weeks)
- **v0.5.1**: CRADLE Integration (3-4 weeks)
- **v0.5.2**: Graph Intelligence (3-4 weeks)
- **v0.6.0**: Advanced Features (6+ months, optional)

---

## Current State Analysis

### What We Have (v0.4)

```python
# Current "multi-agent" system (actually a sequential pipeline)
def run_workflow(workflow, text):
    state.research = run_research(text)      # Step 1
    state.hunting = run_hunting(text)        # Step 2 (doesn't use Step 1!)
    state.detection = run_detection(text, state.research)  # Step 3
    state.review = run_review(state.research, state.hunting, state.detection)  # Step 4
    return format_output(state)
```

**Current Capabilities:**
- ✅ 19 MCP tools
- ✅ IOC extraction (basic regex)
- ✅ ATT&CK mapping (keyword-based)
- ✅ Sigma rule generation
- ✅ 6 threat actor profiles
- ✅ 100 passing tests

**Critical Gaps:**
- ❌ **No agent autonomy** (hard-coded workflow)
- ❌ **No agent communication** (hunting doesn't use research output!)
- ❌ **No feedback loops** (one-way flow)
- ❌ **No shared memory** (each agent processes independently)
- ❌ **No confidence scoring** (all outputs treated equally)
- ❌ **No validation loops** (no refinement)
- ❌ **No multi-source enrichment** (only local text analysis)
- ❌ **Limited detection schemas** (only Sigma)
- ❌ **No hunting frameworks** (basic hypothesis generation)
- ❌ **No attribution assessment** (no confidence transparency)

### Why This Matters

**Current system is 6/10 for security researchers.**  
**v2.0 will be 9/10.**

---

## Vision: v2.0 Architecture

### Complete System Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         CRADLE Platform                                  │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │  React/Electron UI                                               │  │
│  │  - Graph visualization                                           │  │
│  │  - Collaborative workspace (multi-user)                          │  │
│  │  - Report generation (PDF, STIX, JSON)                           │  │
│  │  - Investigation tracking                                        │  │
│  └────────────────────────────┬─────────────────────────────────────┘  │
│                                │                                         │
│  ┌────────────────────────────▼─────────────────────────────────────┐  │
│  │  Django Backend + Postgres                                       │  │
│  │  - REST API                                                      │  │
│  │  - Users, Investigations, Entities, Relationships                │  │
│  │  - Reports, Audit logs                                           │  │
│  └────────────────────────────┬─────────────────────────────────────┘  │
└─────────────────────────────────┼──────────────────────────────────────┘
                                  │ MCP Protocol
                                  │
┌─────────────────────────────────▼──────────────────────────────────────┐
│              threat-research-mcp v2 (LangGraph)                         │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │  LangGraph Orchestrator                                          │  │
│  │  ┌────────────────────────────────────────────────────────────┐ │  │
│  │  │  LangGraph State (In-Memory)                               │ │  │
│  │  │  - Current analysis state                                  │ │  │
│  │  │  - Agent outputs                                           │ │  │
│  │  │  - Confidence scores                                       │ │  │
│  │  │  - Memory: Last 10 analyses, learned patterns             │ │  │
│  │  │  - Validation status                                       │ │  │
│  │  └────────────────────────────────────────────────────────────┘ │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │  Multi-Agent System                                              │  │
│  │                                                                  │  │
│  │  ┌─────────────────────────────────────────────────────────┐   │  │
│  │  │ Research Agent (Multi-Source Intelligence)              │   │  │
│  │  │ ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ │   │  │
│  │  │ Tier 1: Essential (Always)                              │   │  │
│  │  │   ✅ VirusTotal, AlienVault OTX, AbuseIPDB              │   │  │
│  │  │   ✅ URLhaus, ThreatFox                                 │   │  │
│  │  │                                                         │   │  │
│  │  │ Tier 2: Advanced (BYOK)                                 │   │  │
│  │  │   🔑 Shodan, Censys, GreyNoise, IPinfo                  │   │  │
│  │  │                                                         │   │  │
│  │  │ Tier 3: Specialized                                     │   │  │
│  │  │   ✅ C2 Trackers, Phishing Feeds, Malware Sandboxes    │   │  │
│  │  │                                                         │   │  │
│  │  │ Tier 4: LOLBins                                         │   │  │
│  │  │   ✅ LOLBAS, GTFOBins, WADComs                          │   │  │
│  │  │                                                         │   │  │
│  │  │ Output: IOCs + Enrichment + Confidence (0.0-1.0)       │   │  │
│  │  └─────────────────────────────────────────────────────────┘   │  │
│  │                                                                  │  │
│  │  ┌─────────────────────────────────────────────────────────┐   │  │
│  │  │ Hunting Agent (Framework-Based Strategy)                │   │  │
│  │  │ ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ │   │  │
│  │  │ Frameworks:                                             │   │  │
│  │  │   🔥 PEAK (Prepare → Execute → Act)                     │   │  │
│  │  │   🎯 TaHiTI (Initialize → Hunt → Finalize)              │   │  │
│  │  │   📊 SQRRL (HMM0-HMM4 maturity model)                   │   │  │
│  │  │   ⚠️ Pyramid of Pain (Behavioral focus)                 │   │  │
│  │  │                                                         │   │  │
│  │  │ Hunt Types:                                             │   │  │
│  │  │   🔥 Hypothesis-Driven (Flames)                         │   │  │
│  │  │   🪵 Baseline (Embers)                                  │   │  │
│  │  │   🔮 Model-Assisted (Alchemy)                           │   │  │
│  │  │                                                         │   │  │
│  │  │ HEARTH Integration: 50+ community hunts                 │   │  │
│  │  │                                                         │   │  │
│  │  │ Output: Hunt Plan + Queries + Expected Behaviors        │   │  │
│  │  └─────────────────────────────────────────────────────────┘   │  │
│  │                                                                  │  │
│  │  ┌─────────────────────────────────────────────────────────┐   │  │
│  │  │ Detection Agent (Multi-Schema Generator)                │   │  │
│  │  │ ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ │   │  │
│  │  │ Schemas:                                                │   │  │
│  │  │   📄 Sigma (Universal)                                  │   │  │
│  │  │   🔵 KQL (Microsoft Sentinel/Defender)                  │   │  │
│  │  │   🟢 SPL (Splunk)                                       │   │  │
│  │  │   🟡 EQL (Elastic)                                      │   │  │
│  │  │   ☁️ CloudTrail (AWS Athena SQL)                        │   │  │
│  │  │   ☁️ Azure KQL (Activity Logs)                          │   │  │
│  │  │   ☁️ GCP LogQL (Cloud Logging)                          │   │  │
│  │  │                                                         │   │  │
│  │  │ Features:                                               │   │  │
│  │  │   ✅ Schema validation                                  │   │  │
│  │  │   ✅ False positive mitigation                          │   │  │
│  │  │   ✅ Tuning recommendations                             │   │  │
│  │  │                                                         │   │  │
│  │  │ Output: Rules + Validation + Confidence + Tuning        │   │  │
│  │  └─────────────────────────────────────────────────────────┘   │  │
│  │                                                                  │  │
│  │  ┌─────────────────────────────────────────────────────────┐   │  │
│  │  │ Reviewer Agent (Quality Assurance)                      │   │  │
│  │  │ ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ │   │  │
│  │  │ Validation:                                             │   │  │
│  │  │   ✅ Research findings (IOC format, enrichment)         │   │  │
│  │  │   ✅ Hunt strategy (testable hypothesis)                │   │  │
│  │  │   ✅ Detection rules (schema compliance)                │   │  │
│  │  │                                                         │   │  │
│  │  │ Confidence Analysis:                                    │   │  │
│  │  │   📊 Multi-factor scoring                               │   │  │
│  │  │   ⚠️ Attribution assessment (NOT confirmation)          │   │  │
│  │  │   🔄 Validation loops (if confidence < threshold)       │   │  │
│  │  │                                                         │   │  │
│  │  │ Human-in-the-Loop:                                      │   │  │
│  │  │   👤 Prompts when confidence < 70%                      │   │  │
│  │  │   👤 Requests additional context                        │   │  │
│  │  │   👤 Suggests manual verification                       │   │  │
│  │  │                                                         │   │  │
│  │  │ Output: Review Report + Issues + Refinement Plan        │   │  │
│  │  └─────────────────────────────────────────────────────────┘   │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │  Graph Intelligence Layer (v0.5.2)                               │  │
│  │  ┌────────────────────────────────────────────────────────────┐ │  │
│  │  │  NetworkX (In-Memory Graph)                                │ │  │
│  │  │  - Threat actor attribution (with caveats!)                │ │  │
│  │  │  - Campaign tracking                                       │ │  │
│  │  │  - Attack chain prediction                                 │ │  │
│  │  │  - Detection gap analysis                                  │ │  │
│  │  │  - Export to CRADLE Postgres for visualization            │ │  │
│  │  └────────────────────────────────────────────────────────────┘ │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │  Storage Layer                                                   │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │  │
│  │  │   Postgres   │  │   NetworkX   │  │  LangGraph   │          │  │
│  │  │  (CRADLE)    │  │  (In-Memory) │  │    State     │          │  │
│  │  │              │  │              │  │ (In-Memory)  │          │  │
│  │  │ - Users      │  │ - Graph      │  │ - Current    │          │  │
│  │  │ - Entities   │  │   Analysis   │  │   Analysis   │          │  │
│  │  │ - Relations  │  │ - Attribution│  │ - Memory     │          │  │
│  │  │ - Reports    │  │ - Campaigns  │  │ - Context    │          │  │
│  │  └──────────────┘  └──────────────┘  └──────────────┘          │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │  Optional Components (v0.6+)                                     │  │
│  │  ┌──────────────┐  ┌──────────────┐                             │  │
│  │  │   Chroma     │  │    Neo4j     │                             │  │
│  │  │ (VectorDB)   │  │  (GraphDB)   │                             │  │
│  │  │ - Semantic   │  │ - Persistent │                             │  │
│  │  │   search     │  │   graph      │                             │  │
│  │  │ - 1000+      │  │ - 100K+      │                             │  │
│  │  │   reports    │  │   nodes      │                             │  │
│  │  └──────────────┘  └──────────────┘                             │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Technology Stack

### Core Technologies (v0.5)

| Component | Technology | Purpose | Status |
|-----------|-----------|---------|--------|
| **Multi-Agent Framework** | LangGraph + LangChain | Agent orchestration, state management | ✅ Required |
| **Frontend** | CRADLE (React/Electron) | Visualization, collaboration | ✅ Required |
| **Backend** | CRADLE (Django + Postgres) | API, persistence | ✅ Required |
| **MCP Server** | threat-research-mcp (Python) | Intelligence engine | ✅ Current |
| **Graph Engine** | NetworkX (in-memory) | Graph analysis | ✅ Required |
| **State Management** | LangGraph State | Agent memory, context | ✅ Required |

### Optional Technologies (v0.6+)

| Component | Technology | When to Use | Status |
|-----------|-----------|-------------|--------|
| **VectorDB** | Chroma | Semantic search over 1000+ reports | ⚠️ Optional |
| **GraphDB** | Neo4j | Persistent graph storage (100K+ nodes) | ⚠️ Optional |
| **ML Platform** | scikit-learn, TensorFlow | Campaign clustering, temporal analysis | ⚠️ Future |

### Integration Technologies

| Category | Technologies | Count |
|----------|-------------|-------|
| **Threat Intel Sources** | VirusTotal, OTX, AbuseIPDB, Shodan, GreyNoise, etc. | 15+ |
| **Hunting Frameworks** | PEAK, TaHiTI, SQRRL, Pyramid of Pain | 4 |
| **Detection Schemas** | Sigma, KQL, SPL, EQL, CloudTrail, Azure, GCP | 7 |
| **Community Hunts** | HEARTH database | 50+ |

---

## Implementation Phases

### Phase 1: v0.5.0 - LangGraph Multi-Agent Migration (6-8 weeks)

#### Week 1-2: Foundation

**Goal:** Set up LangGraph infrastructure and base agent framework

**Tasks:**
- [ ] Install dependencies
  ```bash
  pip install langgraph langchain langchain-core
  pip install langchain-openai  # or other LLM provider
  ```
- [ ] Design `ThreatAnalysisState` schema
  ```python
  class ThreatAnalysisState(TypedDict):
      # Input
      intel_text: str
      api_keys: Dict[str, str]
      target_platforms: List[str]
      framework: str
      
      # Agent outputs
      research_findings: Optional[Dict]
      hunt_plan: Optional[Dict]
      detections: Optional[Dict]
      review_report: Optional[Dict]
      
      # Control flow
      iteration: int
      needs_refinement: bool
      human_feedback: Optional[str]
  ```
- [ ] Create base agent classes
  ```python
  class BaseAgent(ABC):
      @abstractmethod
      def execute(self, state: ThreatAnalysisState) -> ThreatAnalysisState:
          pass
  ```
- [ ] Set up LangGraph workflow
  ```python
  workflow = StateGraph(ThreatAnalysisState)
  workflow.add_node("research", research_agent_node)
  workflow.add_node("hunting", hunting_agent_node)
  workflow.add_node("detection", detection_agent_node)
  workflow.add_node("reviewer", reviewer_agent_node)
  ```
- [ ] Add memory/checkpointing
  ```python
  from langgraph.checkpoint.memory import MemorySaver
  memory = MemorySaver()
  app = workflow.compile(checkpointer=memory)
  ```

**Deliverables:**
- ✅ LangGraph orchestrator working
- ✅ Basic agent communication
- ✅ State persistence
- ✅ Test: Simple workflow execution

**Files to Create:**
- `src/threat_research_mcp/orchestrator/langgraph_orchestrator.py`
- `src/threat_research_mcp/agents/base_agent.py`
- `src/threat_research_mcp/schemas/workflow_state.py`
- `tests/test_langgraph_orchestrator.py`

---

#### Week 3-4: Research Agent v2

**Goal:** Build multi-source intelligence aggregator with BYOK support

**Tasks:**
- [ ] Create enrichment framework
  ```python
  class EnrichmentSource(ABC):
      @abstractmethod
      def enrich(self, iocs: List[IOC], api_key: str) -> Dict:
          pass
      
      @abstractmethod
      def requires_api_key(self) -> bool:
          pass
  ```
- [ ] Implement Tier 1 integrations (Essential - Always available)
  - [ ] VirusTotal enricher
  - [ ] AlienVault OTX enricher
  - [ ] AbuseIPDB enricher
  - [ ] URLhaus enricher
  - [ ] ThreatFox enricher
- [ ] Implement Tier 2 integrations (Advanced - BYOK)
  - [ ] Shodan enricher
  - [ ] Censys enricher
  - [ ] GreyNoise enricher
  - [ ] IPinfo enricher
- [ ] Implement Tier 3 integrations (Specialized)
  - [ ] C2 tracker aggregator (Feodotracker, SSL Blacklist)
  - [ ] Phishing feed aggregator (PhishTank, OpenPhish)
  - [ ] Malware sandbox aggregator (ANY.RUN, Hybrid Analysis)
- [ ] Implement Tier 4 integrations (LOLBins)
  - [ ] LOLBAS checker
  - [ ] GTFOBins checker
  - [ ] WADComs checker
- [ ] Implement confidence scoring
  ```python
  def calculate_confidence(self, enrichment_results: Dict) -> float:
      # Multi-factor confidence calculation
      factors = {
          "source_count": len(enrichment_results),
          "source_agreement": self._calculate_agreement(enrichment_results),
          "source_reputation": self._calculate_reputation(enrichment_results),
          "data_freshness": self._calculate_freshness(enrichment_results)
      }
      return weighted_average(factors)
  ```
- [ ] Implement graceful degradation (missing API keys)
- [ ] Add API key management (environment variables, config file)

**Deliverables:**
- ✅ 15+ threat intel source integrations
- ✅ BYOK support
- ✅ Confidence scoring (0.0-1.0)
- ✅ Graceful degradation
- ✅ Test: Enrichment with/without API keys

**Files to Create:**
- `src/threat_research_mcp/agents/research_agent_v2.py`
- `src/threat_research_mcp/enrichment/base.py`
- `src/threat_research_mcp/enrichment/tier1/` (VT, OTX, AbuseIPDB, etc.)
- `src/threat_research_mcp/enrichment/tier2/` (Shodan, Censys, etc.)
- `src/threat_research_mcp/enrichment/tier3/` (C2 trackers, phishing, etc.)
- `src/threat_research_mcp/enrichment/tier4/` (LOLBAS, GTFOBins, etc.)
- `src/threat_research_mcp/enrichment/confidence_scorer.py`
- `tests/test_research_agent_v2.py`
- `tests/test_enrichment_sources.py`

---

#### Week 5-6: Hunting & Detection Agents v2

**Goal:** Implement framework-based hunting and multi-schema detection

**Hunting Agent Tasks:**
- [ ] Implement PEAK framework
  ```python
  class PEAKFramework:
      def create_hunt_plan(self, hypothesis, techniques, environment):
          return {
              "prepare": self._prepare_phase(hypothesis, techniques),
              "execute": self._execute_phase(techniques, environment),
              "act": self._act_phase(techniques)
          }
  ```
- [ ] Implement TaHiTI framework
- [ ] Implement SQRRL framework
- [ ] Implement Pyramid of Pain behavioral focus
- [ ] Integrate HEARTH community hunts
  ```python
  class HEARTHDatabase:
      def search(self, tactics, environment, tags):
          # Search 50+ community hunts
          return matching_hunts
  ```
- [ ] Generate hunt queries (Splunk, KQL, Elastic)

**Detection Agent Tasks:**
- [ ] Implement schema generators
  - [ ] Sigma generator (universal)
  - [ ] KQL generator (Microsoft Sentinel/Defender)
  - [ ] SPL generator (Splunk)
  - [ ] EQL generator (Elastic)
  - [ ] CloudTrail generator (AWS Athena SQL)
  - [ ] Azure KQL generator (Activity Logs)
  - [ ] GCP LogQL generator (Cloud Logging)
- [ ] Implement schema validators
  ```python
  class SigmaValidator:
      def validate(self, rule: str) -> Dict:
          # Check required fields, syntax, etc.
          return {"valid": True, "errors": []}
  ```
- [ ] Implement false positive mitigation
- [ ] Generate tuning recommendations

**Deliverables:**
- ✅ 4 hunting frameworks
- ✅ 50+ HEARTH community hunts
- ✅ 7 detection schemas
- ✅ Schema validation
- ✅ FP mitigation
- ✅ Test: Hunt plan generation, detection rule generation

**Files to Create:**
- `src/threat_research_mcp/agents/hunting_agent_v2.py`
- `src/threat_research_mcp/frameworks/peak.py`
- `src/threat_research_mcp/frameworks/tahiti.py`
- `src/threat_research_mcp/frameworks/sqrrl.py`
- `src/threat_research_mcp/frameworks/pyramid_of_pain.py`
- `src/threat_research_mcp/hunting/hearth_integration.py`
- `src/threat_research_mcp/agents/detection_agent_v2.py`
- `src/threat_research_mcp/detection/generators/` (sigma, kql, spl, eql, etc.)
- `src/threat_research_mcp/detection/validators/` (sigma, kql, spl validators)
- `tests/test_hunting_agent_v2.py`
- `tests/test_detection_agent_v2.py`

---

#### Week 7-8: Reviewer Agent & Validation Loops

**Goal:** Implement quality assurance and validation loops

**Tasks:**
- [ ] Implement multi-factor validation
  ```python
  class ReviewerAgentV2:
      def review(self, research, hunt, detections):
          validation = {
              "research": self._validate_research(research),
              "hunting": self._validate_hunting(hunt),
              "detection": self._validate_detection(detections)
          }
          return self._aggregate_validation(validation)
  ```
- [ ] Implement attribution confidence engine
  ```python
  class AttributionEngine:
      def calculate_attribution_confidence(self, iocs, techniques, infrastructure):
          factors = {
              "ioc_matching": 0.25,
              "ttp_matching": 0.25,
              "infrastructure": 0.15,
              "timing": 0.10,
              "unique_indicators": 0.25  # CRITICAL
          }
          # Cap at 85% without unique indicators
          if unique_score < 0.5:
              max_confidence = 0.85
          return confidence
  ```
- [ ] Generate alternative hypotheses
  ```python
  def generate_alternatives(self, primary_confidence):
      return [
          {"actor": "APT29 Copycat", "confidence": 1.0 - primary_confidence * 0.9},
          {"actor": "Different APT", "confidence": 0.03},
          {"actor": "Script Kiddie", "confidence": 0.02}
      ]
  ```
- [ ] Implement confidence threshold logic
- [ ] Create human-in-the-loop prompts
  ```python
  def generate_human_prompts(self, issues):
      prompts = []
      for issue in issues:
          if issue["severity"] == "high":
              prompts.append(f"⚠️ {issue['message']}. {issue['recommendation']}")
      return prompts
  ```
- [ ] Implement refinement workflow
- [ ] Add validation loops (conditional edges)
  ```python
  workflow.add_conditional_edges(
      "reviewer",
      should_refine_or_complete,
      {
          "refine": "refine_research",  # Loop back
          "human_review": "human_review",  # Needs human input
          "complete": END
      }
  )
  ```

**Deliverables:**
- ✅ Reviewer agent working
- ✅ Attribution assessment (NOT confirmation)
- ✅ Validation loops
- ✅ Human-in-the-loop
- ✅ Confidence transparency
- ✅ Test: Validation loop execution, human prompts

**Files to Create:**
- `src/threat_research_mcp/agents/reviewer_agent_v2.py`
- `src/threat_research_mcp/validation/research_validator.py`
- `src/threat_research_mcp/validation/hunting_validator.py`
- `src/threat_research_mcp/validation/detection_validator.py`
- `src/threat_research_mcp/attribution/attribution_engine.py`
- `src/threat_research_mcp/attribution/alternative_hypotheses.py`
- `tests/test_reviewer_agent_v2.py`
- `tests/test_attribution_engine.py`

---

### Phase 2: v0.5.1 - CRADLE Integration (3-4 weeks)

#### Week 1-2: CRADLE Setup & API Integration

**Goal:** Deploy CRADLE and create MCP → CRADLE bridge

**Tasks:**
- [ ] Deploy CRADLE
  ```bash
  git clone https://github.com/prodaft/cradle.git
  cd cradle
  docker compose -f docker-compose.demo.yml up -d
  ```
- [ ] Configure Postgres
- [ ] Set up Django backend
- [ ] Create MCP → CRADLE API bridge
  ```python
  class CRADLEClient:
      def __init__(self, base_url, api_key):
          self.base_url = base_url
          self.api_key = api_key
      
      def create_investigation(self, title, description):
          # POST /api/investigations/
          pass
      
      def add_entity(self, investigation_id, entity):
          # POST /api/investigations/{id}/entities/
          pass
      
      def add_relationship(self, investigation_id, source, target, rel_type):
          # POST /api/investigations/{id}/relationships/
          pass
  ```
- [ ] Design entity/relationship schema mapping
  ```python
  # threat-research-mcp → CRADLE mapping
  {
      "IOC": "indicator",
      "Technique": "technique",
      "ThreatActor": "threat_actor",
      "Campaign": "campaign"
  }
  ```

**Deliverables:**
- ✅ CRADLE deployed
- ✅ API integration working
- ✅ Entity mapping defined
- ✅ Test: Create investigation via API

**Files to Create:**
- `src/threat_research_mcp/integrations/cradle_client.py`
- `src/threat_research_mcp/integrations/cradle_mapper.py`
- `tests/test_cradle_integration.py`

---

#### Week 3-4: Export & Visualization

**Goal:** Enable one-click export and graph visualization

**Tasks:**
- [ ] Implement export tool
  ```python
  @mcp.tool()
  def export_to_cradle(analysis_product_id: str, cradle_url: str) -> str:
      """Export analysis product to CRADLE"""
      product = get_analysis_product(analysis_product_id)
      cradle_data = convert_to_cradle_format(product)
      
      # Create investigation
      investigation = cradle_client.create_investigation(
          title=f"Analysis: {product['title']}",
          description=product['narrative_summary']
      )
      
      # Add entities
      for ioc in product['iocs']:
          cradle_client.add_entity(investigation.id, {
              "type": "indicator",
              "value": ioc['value'],
              "confidence": ioc['confidence']
          })
      
      # Add relationships
      for ioc in product['iocs']:
          for technique in product['techniques']:
              cradle_client.add_relationship(
                  investigation.id,
                  source=ioc['value'],
                  target=technique['technique_id'],
                  rel_type="indicates"
              )
      
      return json.dumps({"status": "success", "cradle_id": investigation.id})
  ```
- [ ] Implement entity conversion
- [ ] Implement relationship mapping
- [ ] Test graph visualization in CRADLE UI
- [ ] Implement report generation
- [ ] Enable multi-user collaboration

**Deliverables:**
- ✅ One-click export to CRADLE
- ✅ Graph visualization working
- ✅ Collaborative workspace
- ✅ Report generation (PDF, STIX, JSON)
- ✅ Test: Full workflow (analysis → export → visualize)

**Files to Create:**
- `src/threat_research_mcp/tools/cradle_export.py`
- `src/threat_research_mcp/integrations/cradle_formatter.py`
- `examples/demo_cradle_export.py`
- `tests/test_cradle_export.py`

---

### Phase 3: v0.5.2 - Graph Intelligence (3-4 weeks)

#### Week 1-2: NetworkX Graph Engine

**Goal:** Implement graph-based intelligence analysis

**Tasks:**
- [ ] Implement graph manager
  ```python
  class ThreatIntelGraph:
      def __init__(self):
          self.graph = nx.MultiDiGraph()
      
      def add_threat_actor(self, actor: ThreatActorNode):
          self.graph.add_node(actor.id, node_type="threat_actor", **actor.__dict__)
      
      def add_relationship(self, rel: Relationship):
          self.graph.add_edge(
              rel.source_id,
              rel.target_id,
              rel_type=rel.rel_type,
              confidence=rel.confidence
          )
  ```
- [ ] Define entity models
  ```python
  @dataclass
  class ThreatActorNode:
      id: str
      aliases: List[str]
      attribution: str
      confidence: float
      metadata: Dict
  ```
- [ ] Define relationship types
  ```python
  RELATIONSHIP_TYPES = [
      "ATTRIBUTED_TO",  # Campaign → ThreatActor
      "USES",           # ThreatActor → Technique
      "INDICATES",      # IOC → Campaign
      "PRECEDES",       # Technique → Technique
      "DETECTS",        # Detection → Technique
      "TARGETS",        # ThreatActor → Victim
      "SIMILAR_TO",     # ThreatActor → ThreatActor
      "EVOLVES_FROM"    # Malware → Malware
  ]
  ```
- [ ] Implement graph builder (auto-populate from analysis)
  ```python
  class GraphBuilder:
      def ingest_analysis_product(self, product: AnalysisProduct):
          # Add IOCs as nodes
          for ioc in product.iocs:
              self.graph.add_node(ioc.value, node_type="ioc", ...)
          
          # Add techniques as nodes
          for technique in product.attack_techniques:
              self.graph.add_node(technique.technique_id, node_type="technique", ...)
          
          # Create relationships
          for ioc in product.iocs:
              for technique in product.attack_techniques:
                  self.graph.add_edge(ioc.value, technique.technique_id, rel_type="INDICATES")
  ```
- [ ] Implement attribution engine
  ```python
  def attribute_to_actor(self, iocs: List[str], techniques: List[str]) -> Dict:
      """Probabilistic threat actor attribution"""
      actor_scores = {}
      for actor_id in self._get_all_actors():
          score = 0.0
          # IOC overlap
          actor_iocs = self._get_actor_iocs(actor_id)
          ioc_overlap = len(set(iocs) & set(actor_iocs))
          score += ioc_overlap * 0.4
          
          # Technique overlap
          actor_techniques = self._get_actor_techniques(actor_id)
          tech_overlap = len(set(techniques) & set(actor_techniques))
          score += tech_overlap * 0.6
          
          if score > 0:
              actor_scores[actor_id] = score
      
      # Normalize and return top 3
      return self._normalize_scores(actor_scores)
  ```
- [ ] Implement campaign tracking
- [ ] Implement attack chain prediction
  ```python
  def get_attack_chain(self, start_technique: str) -> List[str]:
      """Get likely technique sequence using PRECEDES relationships"""
      chain = []
      current = start_technique
      while True:
          chain.append(current)
          next_techniques = [
              n for n in self.graph.neighbors(current)
              if self.graph.get_edge_data(current, n).get('rel_type') == 'PRECEDES'
          ]
          if not next_techniques:
              break
          current = max(next_techniques, key=lambda t: self._get_edge_confidence(current, t))
      return chain
  ```

**Deliverables:**
- ✅ NetworkX graph engine
- ✅ Entity/relationship models
- ✅ Graph builder
- ✅ Attribution engine (with caveats!)
- ✅ Campaign tracking
- ✅ Attack chain prediction
- ✅ Test: Graph analysis algorithms

**Files to Create:**
- `src/threat_research_mcp/graph/manager.py`
- `src/threat_research_mcp/graph/entities.py`
- `src/threat_research_mcp/graph/relationships.py`
- `src/threat_research_mcp/graph/builder.py`
- `src/threat_research_mcp/graph/attribution.py`
- `src/threat_research_mcp/graph/campaign_tracker.py`
- `src/threat_research_mcp/graph/attack_chain.py`
- `tests/test_graph_manager.py`
- `tests/test_graph_attribution.py`

---

#### Week 3-4: Graph Visualization & MCP Tools

**Goal:** Create graph tools and visualization

**Tasks:**
- [ ] Implement 5 new MCP tools
  ```python
  @mcp.tool()
  def attribute_threat_actor(iocs: List[str], techniques: List[str]) -> str:
      """Probabilistic threat actor attribution"""
      graph = get_threat_intel_graph()
      attribution = graph.attribute_to_actor(iocs, techniques)
      return json.dumps({
          "attribution": attribution,
          "caveats": [
              "Attribution is ASSESSED, not confirmed",
              "Could be copycat or false flag",
              "Treat as APT-level threat regardless"
          ]
      })
  
  @mcp.tool()
  def predict_next_techniques(observed_techniques: List[str]) -> str:
      """Predict likely next techniques in attack chain"""
      graph = get_threat_intel_graph()
      predictions = graph.predict_next_techniques(observed_techniques)
      return json.dumps({"predictions": predictions})
  
  @mcp.tool()
  def find_related_campaigns(ioc: str, max_distance: int = 2) -> str:
      """Find campaigns related to an IOC via graph traversal"""
      graph = get_threat_intel_graph()
      campaigns = graph.find_related_campaigns(ioc, max_distance)
      return json.dumps({"campaigns": campaigns})
  
  @mcp.tool()
  def find_detection_gaps(threat_actor: str) -> str:
      """Find techniques used by actor that lack detections"""
      graph = get_threat_intel_graph()
      gaps = graph.find_detection_gaps(threat_actor)
      return json.dumps({"gaps": gaps})
  
  @mcp.tool()
  def visualize_threat_landscape(center_entity: str, depth: int = 2) -> str:
      """Generate Mermaid graph visualization"""
      graph = get_threat_intel_graph()
      mermaid = graph.generate_mermaid(center_entity, depth)
      return mermaid
  ```
- [ ] Implement Mermaid graph generation
- [ ] Implement subgraph extraction
- [ ] Export to CRADLE format
- [ ] Test visualization in CRADLE

**Deliverables:**
- ✅ 5 new MCP tools
- ✅ Mermaid visualization
- ✅ CRADLE integration
- ✅ Test: All graph tools working

**Files to Create:**
- `src/threat_research_mcp/tools/graph_tools.py`
- `src/threat_research_mcp/graph/visualization.py`
- `examples/demo_graph_analysis.py`
- `tests/test_graph_tools.py`

---

### Phase 4: v0.6.0 - Advanced Features (Future - 6+ months)

#### Optional Enhancements

**Chroma VectorDB** (if semantic search needed)
- Semantic search over 1000+ reports
- "Find similar incidents"
- Embedding-based retrieval
- When: User base grows, report volume > 1000

**Neo4j GraphDB** (if graph > 100K nodes)
- Persistent graph storage
- Cypher queries
- Enterprise-scale graph analytics
- When: Graph size exceeds NetworkX capacity

**ML-Based Features**
- Campaign clustering (unsupervised learning)
- Temporal analysis (time-series)
- Similarity scoring (embeddings)
- Automated pattern learning
- When: Sufficient data for training

**Advanced Integrations**
- MISP connector
- OpenCTI connector
- Synapse connector
- Direct SIEM integrations
- SOAR platform integrations
- When: Enterprise customers request

---

## Key Principles

### 1. Attribution Honesty

**The Problem:** Attribution is never 100% certain.

**The Solution:** Transparent confidence scoring with caveats.

#### Attribution Confidence Spectrum

```
0-30%: Unknown/Generic
"Adversary using common techniques"

30-60%: Possible Attribution
"Behavioral patterns SIMILAR to APT29"

60-85%: Likely Attribution
"Multiple IOCs + TTPs match APT29"
"Recommend treating as APT29-level threat"

85-95%: High Confidence Attribution
"Strong evidence, but not definitive"
"Very likely APT29, but attribution is never 100%"

95-100%: Near-Certain Attribution
"Confirmed by multiple intelligence sources"
"Still use 'assessed' not 'confirmed'"
```

#### Language Guidelines

**❌ NEVER SAY:**
- "APT29 campaign confirmed"
- "This is definitely APT29"
- "Confirmed attribution to APT29"

**✅ ALWAYS SAY:**
- "Potential APT29 activity (85% confidence)"
- "Behavioral patterns consistent with APT29"
- "Assessed to be APT29-related (not confirmed)"
- "Likely APT29, but attribution is not definitive"

#### Confidence Factors

```python
confidence_factors = {
    "ioc_matching": 0.25,        # IOCs match known infrastructure
    "ttp_matching": 0.25,        # TTPs match behavioral patterns
    "infrastructure": 0.15,      # Infrastructure patterns
    "timing": 0.10,              # Operational hours, campaign timing
    "unique_indicators": 0.25    # CRITICAL - unique malware/infrastructure
}

# Cap confidence at 85% without unique indicators
if unique_indicators_score < 0.5:
    max_confidence = 0.85
```

#### Attribution Output Format

```json
{
  "primary_hypothesis": {
    "threat_actor": "APT29",
    "confidence": 0.85,
    "confidence_level": "HIGH (NOT CONFIRMED)"
  },
  "assessment_basis": [
    "IOC 185.220.101.45 linked to APT29 in 3+ sources",
    "TTPs match APT29 behavioral patterns",
    "Timing aligns with APT29 operational hours"
  ],
  "caveats": [
    "Attribution is ASSESSED, not confirmed",
    "No unique APT29 malware detected",
    "Public IOCs could be used by copycats",
    "Could be false flag operation",
    "Treat as APT-level threat regardless"
  ],
  "alternative_hypotheses": [
    {"actor": "APT29 Copycat", "confidence": 0.10},
    {"actor": "Different APT", "confidence": 0.03},
    {"actor": "Script Kiddie", "confidence": 0.02}
  ],
  "what_would_increase_confidence": [
    "Detection of unique APT29 malware (SUNBURST, TEARDROP)",
    "APT29-specific C2 infrastructure patterns",
    "Correlation with known APT29 campaigns",
    "Government/vendor attribution statement"
  ]
}
```

---

### 2. Behavioral Focus (Pyramid of Pain)

**The Problem:** IOCs change constantly, detections break.

**The Solution:** Hunt for behaviors (TTPs), not indicators.

#### Pyramid of Pain

```
                            ▲
                           ╱ ╲
                          ╱   ╲ 🎯 TOUGH
                         ╱ TTPs╲ ← HUNT FOR THESE!
                        ╱———————╲
                       ╱         ╲
                      ╱ 🛠️  Tools ╲
                     ╱—————————————╲
                    ╱               ╲
                   ╱ 📊 Host/Network ╲
                  ╱———————————————————╲
                 ╱                     ╲
                ╱  🌐 Domain Names      ╲
               ╱—————————————————————————╲
              ╱                           ╲
             ╱     🔢 IP Addresses         ╲
            ╱———————————————————————————————╲
           ╱                                 ╲
          ╱       #️⃣  Hash Values             ╲
         ╱—————————————————————————————————————╲
```

**Why Behavioral Hunting?**
- **Hash values** → Adversaries change in seconds
- **IP addresses** → Adversaries change in minutes
- **Domain names** → Adversaries change in hours
- **Network/Host artifacts** → Adversaries change in days
- **Tools** → Adversaries change in weeks
- **TTPs (Behaviors)** → Adversaries change in months/years ✅

#### Examples

**❌ BAD: IOC-Based Detection**
```
Hunt for: Mimikatz hash 1234567890abcdef
Problem: Hash changes with every compile
Lifespan: Hours
```

**✅ GOOD: Behavioral Detection**
```
Hunt for: Any process accessing LSASS memory (T1003.001)
Why: This behavior is required for credential theft
Tools that use it: Mimikatz, ProcDump, custom malware
Lifespan: Years (fundamental OS behavior)
```

---

### 3. Transparency

**The Problem:** Users don't know what to trust.

**The Solution:** Show confidence breakdown and explain reasoning.

#### Confidence Transparency

Always show:
- ✅ Confidence score (0.85)
- ✅ Confidence level ("HIGH, NOT CONFIRMED")
- ✅ Factor breakdown (what contributed to score)
- ✅ Alternative hypotheses (copycats, false flags)
- ✅ Caveats (what's missing for higher confidence)
- ✅ What would increase confidence

#### Example Output

```
⚠️ POTENTIAL THREAT DETECTED - HIGH CONFIDENCE (89%)

Potential Attribution: APT29 (Cozy Bear) - 85% confidence
⚠️ Note: Attribution is ASSESSED, not confirmed

Confidence Breakdown:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
IOC Matching          ████████░░ 92%
TTP Matching          ████████░░ 85%
Infrastructure        ███████░░░ 78%
Timing                ████████░░ 82%
Unique Indicators     ████░░░░░░ 40% ⚠️ LOW
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Alternative Hypotheses:
- APT29 Copycat (10% confidence)
- Different APT group (3% confidence)
- Script kiddie using public tools (2% confidence)

What Would Increase Confidence:
□ Detection of unique APT29 malware (SUNBURST, TEARDROP)
□ APT29-specific C2 infrastructure patterns
□ Correlation with known APT29 campaigns
```

---

### 4. Collaboration

**The Problem:** Analysts work in silos.

**The Solution:** CRADLE collaborative workspace.

#### Features
- ✅ Multi-user workspace
- ✅ Graph visualization
- ✅ Real-time collaboration
- ✅ Comments and tagging
- ✅ Report generation
- ✅ Investigation tracking

---

### 5. Extensibility

**The Problem:** Every org has different tools/sources.

**The Solution:** BYOK (Bring Your Own Keys) + modular design.

#### Features
- ✅ BYOK (users provide API keys)
- ✅ Modular agent design
- ✅ Plugin architecture
- ✅ Easy to add new sources/schemas
- ✅ Graceful degradation (missing keys)

---

## Success Metrics

### v0.5 Goals

| Metric | Target | How to Measure |
|--------|--------|----------------|
| **Agent Collaboration** | Research → Hunting → Detection → Reviewer | Workflow execution logs |
| **Confidence Scoring** | All outputs have 0.0-1.0 confidence | Output validation |
| **Attribution Assessment** | Transparent, with caveats | User feedback |
| **Validation Loops** | Automatic refinement when confidence < 70% | Loop execution count |
| **Multi-Source Enrichment** | 15+ threat intel sources | Integration tests |
| **Framework-Based Hunting** | 4 frameworks implemented | Framework usage logs |
| **Multi-Schema Detection** | 7 schemas supported | Schema generation tests |
| **CRADLE Integration** | One-click export working | Export success rate |
| **Graph Intelligence** | 5 graph tools working | Tool usage logs |

### Quality Targets

| Metric | Target | How to Measure |
|--------|--------|----------------|
| **Attribution Accuracy** | >80% on known APT scenarios | Test against known campaigns |
| **Detection Quality** | <10% false positive rate | User feedback, tuning iterations |
| **Hunt Effectiveness** | >70% of hunts find new threats | Hunt success rate |
| **User Satisfaction** | 9/10 for security researchers | User surveys |
| **Performance** | <5s for full analysis | Performance benchmarks |
| **Uptime** | 99.9% availability | Monitoring logs |

---

## User Journey Examples

### Persona 1: SOC Analyst (Sarah)

#### Scenario: Investigating Suspicious Alert

**9:00 AM - Alert comes in**
```
Alert: Suspicious PowerShell execution on WORKSTATION-42
User: jdoe
Command: powershell -enc <base64>
```

**Step 1: Sarah opens Cursor and pastes alert**
```
Sarah: "Analyze this alert and tell me what's happening:

Alert: Suspicious PowerShell execution
Host: WORKSTATION-42
User: jdoe
Command: powershell -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0A...
Process: powershell.exe
Parent: outlook.exe
Network: Connected to 185.220.101.45:443
"
```

**Step 2: threat-research-mcp analyzes (5-15 seconds)**

Behind the scenes:
1. **Research Agent** (5s):
   - Decodes base64 command
   - Extracts IOC: `185.220.101.45`
   - Checks VirusTotal: "Malicious, APT29 infrastructure"
   - Checks AlienVault OTX: "Known C2, SolarWinds campaign"
   - Maps to ATT&CK: T1059.001 (PowerShell), T1071.001 (Web C2)
   - Confidence: 0.92

2. **Hunting Agent** (3s):
   - Generates hypothesis: "Outlook spawning encoded PowerShell suggests phishing-based initial access"
   - Framework: PEAK
   - Searches HEARTH: Found 3 similar hunts
   - Recommends: Hunt for other hosts with same pattern

3. **Detection Agent** (4s):
   - Generates Sigma rule for "Outlook → PowerShell -enc"
   - Generates KQL query for Microsoft Sentinel
   - Generates SPL query for Splunk
   - Validates all rules: ✅ Pass
   - Confidence: 0.87

4. **Reviewer Agent** (2s):
   - Overall confidence: 0.89 (HIGH)
   - Attribution: APT29 (85% confidence, ASSESSED not confirmed)
   - Validation: ✅ All checks pass
   - Recommendation: "Deploy detection immediately"

**Step 3: Sarah gets results**
```
Cursor responds:

⚠️ POTENTIAL THREAT DETECTED - HIGH CONFIDENCE (89%)

Potential Attribution: APT29 (Cozy Bear) - 85% confidence
⚠️ Note: Attribution is ASSESSED, not confirmed

What Happened:
- User jdoe received phishing email
- Clicked malicious link in Outlook
- Outlook spawned PowerShell with encoded command
- PowerShell connected to known APT29 infrastructure: 185.220.101.45

ATT&CK Techniques:
- T1566.001: Spearphishing Attachment
- T1059.001: PowerShell
- T1071.001: Web Protocol C2

IOC Reputation:
✅ VirusTotal: 45/70 vendors flagged as malicious
✅ AlienVault OTX: Known APT29 infrastructure
✅ AbuseIPDB: Reported 127 times in last 30 days

Recommended Actions:
1. Isolate WORKSTATION-42 immediately
2. Hunt for other hosts with same pattern (see hunt query below)
3. Deploy detection rules (Sigma/KQL/SPL provided)
4. Check for lateral movement from jdoe's account

Detection Rules Ready:
- Sigma: outlook_powershell_encoded.yml
- KQL: DeviceProcessEvents query
- SPL: Splunk search

Export to CRADLE? [Yes/No]
```

**Step 4: Sarah exports to CRADLE**
```
Sarah: "Yes, export to CRADLE"
Cursor: "✅ Exported to CRADLE investigation #1247"
```

**Step 5: Sarah opens CRADLE**

CRADLE shows:
- Graph visualization (jdoe → Outlook → PowerShell → 185.220.101.45 → APT29)
- Timeline of events
- Entities and relationships
- Detection rules ready to deploy
- Hunt queries ready to run

**Step 6: Sarah collaborates with team**
- Tags @mike (Senior Analyst)
- Mike reviews graph
- Mike adds note: "Check if jdoe clicked links in other emails"
- Sarah runs hunt query across all hosts
- Finds 2 more infected hosts!

**Step 7: Sarah deploys detections**
- Clicks "Deploy Rules" in CRADLE
- Sigma → Pushed to SIEM
- KQL → Added to Sentinel
- SPL → Saved as Splunk alert
- Result: Future attacks blocked automatically

---

### Persona 2: Threat Hunter (Mike)

#### Scenario: Proactive Hunt for APT29 Activity

**Step 1: Mike requests hunt plan**
```
Mike (in Cursor): "I want to hunt for APT29 activity in our environment. 
We're a Windows AD environment with Splunk SIEM. 
Generate a hunt plan using the PEAK framework."
```

**Step 2: threat-research-mcp generates hunt plan**
```
Cursor responds:

🔍 PEAK HUNT PLAN: APT29 Behavioral Detection

PREPARE Phase:
Hypothesis: "APT29 uses Outlook → PowerShell chains for initial access, 
followed by WMI lateral movement and Kerberoasting"

Data Sources Required:
✅ Windows Security Event Logs (Event ID 4688)
✅ Sysmon (Event ID 1, 3, 10)
✅ PowerShell logs (Event ID 4104)

EXECUTE Phase:
Hunt Query 1: Outlook → PowerShell Chains
index=windows EventCode=4688 
| search ParentImage="*outlook.exe" Image="*powershell.exe"
| stats count by ComputerName, User, CommandLine

Expected Behaviors:
- Office apps spawning PowerShell (not normal)
- WMI remote process creation (lateral movement)

False Positive Mitigation:
- Whitelist known admin scripts
- Exclude service accounts

ACT WITH KNOWLEDGE Phase:
- Record findings in CRADLE
- Deploy Sigma rules for confirmed behaviors

Confidence: 0.82 (HIGH)
Framework: PEAK
Hunt Type: Hypothesis-Driven (Flame 🔥)

Export to CRADLE? [Yes/No]
```

**Step 3: Mike executes hunt**
- Exports to CRADLE
- Runs Query 1 in Splunk
- Finds 12 hosts with Outlook → PowerShell pattern
- 3 hosts with suspicious encoded commands
- 2 NEW hosts discovered (not previously known)

**Step 4: Mike documents in CRADLE**
- CRADLE shows campaign graph
- 4 hosts compromised
- Timeline of compromise
- Impact assessment

---

### Persona 3: Detection Engineer (Alex)

#### Scenario: Building Detection Rules

**Step 1: Alex reviews hunt findings in CRADLE**
- 4 hosts compromised
- APT29 campaign confirmed
- Need detection rules

**Step 2: Alex requests detection rules**
```
Alex (in Cursor): "Generate production-ready detection rules for this APT29 campaign. 
I need Sigma, KQL for Sentinel, and SPL for Splunk. 
Include false positive mitigation and tuning recommendations."
```

**Step 3: threat-research-mcp generates rules**
```
Cursor responds:

🛡️ DETECTION RULES: APT29 Outlook → PowerShell Chain

Rule 1: Sigma (Universal)
[Sigma rule with proper schema]

Rule 2: KQL (Microsoft Sentinel)
[KQL query with proper syntax]

Rule 3: SPL (Splunk)
[SPL search with proper syntax]

Validation Results:
✅ Sigma: Valid
✅ KQL: Valid
✅ SPL: Valid

Confidence Scores:
- Detection accuracy: 0.91 (HIGH)
- False positive rate: 0.08 (LOW)

Tuning Recommendations:
1. Whitelist known admin scripts
2. Add time-based logic (after hours = higher severity)
3. Monitor for 7 days, adjust thresholds

Export to CRADLE? [Yes/No]
```

**Step 4: Alex tests and deploys**
- Exports to CRADLE
- Tests in dev Splunk for 7 days
- 2 true positives, 1 false positive
- Tunes rule to exclude false positive
- Deploys to production via CRADLE
- Rules active, monitoring for 30 days

---

## Next Steps

### Immediate (This Week)

1. ✅ **Review and approve this roadmap**
   - Read through entire document
   - Identify any concerns or questions
   - Get team alignment

2. ✅ **Set up development environment**
   ```bash
   cd threat-research-mcp
   python -m venv .venv
   source .venv/bin/activate  # Windows: .venv\Scripts\activate
   pip install -e ".[dev]"
   ```

3. ✅ **Install LangGraph + LangChain**
   ```bash
   pip install langgraph langchain langchain-core langchain-openai
   ```

4. ✅ **Create project structure**
   ```bash
   mkdir -p src/threat_research_mcp/orchestrator
   mkdir -p src/threat_research_mcp/agents
   mkdir -p src/threat_research_mcp/enrichment/{tier1,tier2,tier3,tier4}
   mkdir -p src/threat_research_mcp/frameworks
   mkdir -p src/threat_research_mcp/detection/generators
   mkdir -p src/threat_research_mcp/detection/validators
   mkdir -p src/threat_research_mcp/validation
   mkdir -p src/threat_research_mcp/attribution
   mkdir -p src/threat_research_mcp/graph
   mkdir -p src/threat_research_mcp/integrations
   ```

### Short-Term (Next 2 Months)

1. ✅ **Implement v0.5.0 (LangGraph multi-agent)**
   - Week 1-2: Foundation
   - Week 3-4: Research Agent v2
   - Week 5-6: Hunting & Detection Agents v2
   - Week 7-8: Reviewer Agent & Validation Loops

2. ✅ **Test thoroughly**
   - Unit tests for each agent
   - Integration tests for workflow
   - End-to-end tests for full pipeline

3. ✅ **Document as you go**
   - API documentation
   - Architecture diagrams
   - User guides

### Medium-Term (3-4 Months)

1. ✅ **Integrate with CRADLE (v0.5.1)**
   - Deploy CRADLE
   - Build API bridge
   - Test export and visualization

2. ✅ **Add graph intelligence (v0.5.2)**
   - Implement NetworkX graph engine
   - Build graph tools
   - Test attribution and prediction

3. ✅ **Deploy to production**
   - Set up monitoring
   - Configure alerting
   - Train users

4. ✅ **Gather user feedback**
   - User surveys
   - Usage analytics
   - Feature requests

### Long-Term (6+ Months)

1. ⚠️ **Consider optional enhancements (v0.6.0)**
   - Chroma (if semantic search needed)
   - Neo4j (if graph > 100K nodes)
   - ML features (clustering, temporal analysis)
   - Advanced integrations (MISP, OpenCTI)

2. ⚠️ **Scale based on usage**
   - Monitor performance
   - Optimize bottlenecks
   - Add capacity as needed

3. ⚠️ **Continuous improvement**
   - Regular user feedback sessions
   - Feature prioritization
   - Technical debt management

---

## Appendix

### A. Reference Links

- **LangGraph**: https://github.com/langchain-ai/langgraph
- **LangChain**: https://python.langchain.com/
- **CRADLE**: https://github.com/prodaft/cradle
- **ThreatHunter-Playbook**: https://github.com/OTRF/ThreatHunter-Playbook
- **threat-hunting-mcp-server**: https://github.com/THORCollective/threat-hunting-mcp-server
- **HEARTH**: https://github.com/THORCollective/HEARTH
- **LOLBAS**: https://lolbas-project.github.io/
- **GTFOBins**: https://gtfobins.github.io/

### B. Threat Intel Sources

**Tier 1 (Essential):**
- VirusTotal: https://www.virustotal.com/
- AlienVault OTX: https://otx.alienvault.com/
- AbuseIPDB: https://www.abuseipdb.com/
- URLhaus: https://urlhaus.abuse.ch/
- ThreatFox: https://threatfox.abuse.ch/

**Tier 2 (Advanced):**
- Shodan: https://www.shodan.io/
- Censys: https://censys.io/
- GreyNoise: https://www.greynoise.io/
- IPinfo: https://ipinfo.io/

**Tier 3 (Specialized):**
- Feodotracker: https://feodotracker.abuse.ch/
- SSL Blacklist: https://sslbl.abuse.ch/
- PhishTank: https://phishtank.org/
- OpenPhish: https://openphish.com/

**Tier 4 (LOLBins):**
- LOLBAS: https://lolbas-project.github.io/
- GTFOBins: https://gtfobins.github.io/
- WADComs: https://wadcoms.github.io/

### C. Detection Schemas

- **Sigma**: https://github.com/SigmaHQ/sigma
- **KQL**: https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/
- **SPL**: https://docs.splunk.com/Documentation/Splunk/latest/SearchReference
- **EQL**: https://eql.readthedocs.io/

### D. Hunting Frameworks

- **PEAK**: https://www.sans.org/white-papers/peak-framework/
- **TaHiTI**: https://www.betaalvereniging.nl/en/safety/tahiti/
- **SQRRL**: https://www.threathunting.net/sqrrl-archive
- **Pyramid of Pain**: https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html

---

## Document Version

- **Version**: 2.0
- **Date**: 2026-04-13
- **Status**: APPROVED
- **Next Review**: After v0.5.0 completion

---

**This is the complete roadmap for threat-research-mcp v2.0!** 🎯
