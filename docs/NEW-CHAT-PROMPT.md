# Context-Rich Prompt for New Chat

**Copy this entire prompt into your new chat to get started with Phase 1 implementation:**

---

## Project Context

I'm working on **threat-research-mcp v2.0**, a multi-agent threat intelligence platform for security researchers (SOC analysts, threat hunters, detection engineers).

### Current State (v0.4)
- Sequential pipeline (not true multi-agent)
- 19 MCP tools
- Basic IOC extraction and ATT&CK mapping
- 6 threat actor profiles
- 100 passing tests

### Goal (v2.0)
Transform into a true multi-agent system with:
- LangGraph-based multi-agent orchestration
- Multi-source intelligence enrichment (15+ sources, BYOK)
- Framework-based threat hunting (PEAK, TaHiTI, SQRRL)
- Multi-schema detection generation (Sigma, KQL, SPL, EQL, CloudTrail, Azure, GCP)
- Confidence scoring & attribution assessment (transparent, with caveats)
- Validation loops & human-in-the-loop
- CRADLE integration for visualization
- Graph-based intelligence (NetworkX)

### Complete Roadmap
See `docs/ROADMAP-V2-PLAN.md` for full details (150+ page comprehensive plan).

---

## Current Task: Phase 1 - LangGraph Multi-Agent Migration

**Timeline:** 6-8 weeks  
**Current Week:** Week 1-2 (Foundation)

### Week 1-2 Goals: Foundation

**Objective:** Set up LangGraph infrastructure and base agent framework

**Tasks to Complete:**

1. **Install Dependencies**
   ```bash
   pip install langgraph langchain langchain-core langchain-openai
   ```

2. **Design State Schema**
   Create `src/threat_research_mcp/schemas/workflow_state.py`:
   ```python
   from typing import TypedDict, Optional, Dict, List
   
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

3. **Create Base Agent Class**
   Create `src/threat_research_mcp/agents/base_agent.py`:
   ```python
   from abc import ABC, abstractmethod
   from threat_research_mcp.schemas.workflow_state import ThreatAnalysisState
   
   class BaseAgent(ABC):
       @abstractmethod
       def execute(self, state: ThreatAnalysisState) -> ThreatAnalysisState:
           """Execute agent logic and update state"""
           pass
   ```

4. **Set Up LangGraph Workflow**
   Create `src/threat_research_mcp/orchestrator/langgraph_orchestrator.py`:
   ```python
   from langgraph.graph import StateGraph, END
   from langgraph.checkpoint.memory import MemorySaver
   from threat_research_mcp.schemas.workflow_state import ThreatAnalysisState
   
   def create_workflow():
       workflow = StateGraph(ThreatAnalysisState)
       
       # Add nodes (agents)
       workflow.add_node("research", research_agent_node)
       workflow.add_node("hunting", hunting_agent_node)
       workflow.add_node("detection", detection_agent_node)
       workflow.add_node("reviewer", reviewer_agent_node)
       
       # Define flow
       workflow.set_entry_point("research")
       workflow.add_edge("research", "hunting")
       workflow.add_edge("research", "detection")
       workflow.add_edge("hunting", "reviewer")
       workflow.add_edge("detection", "reviewer")
       
       # Conditional edges for validation loop
       workflow.add_conditional_edges(
           "reviewer",
           should_refine_or_complete,
           {
               "refine": "research",
               "human_review": "human_review",
               "complete": END
           }
       )
       
       # Add memory
       memory = MemorySaver()
       app = workflow.compile(checkpointer=memory)
       
       return app
   ```

5. **Add Memory/Checkpointing**
   Implement memory for context retention across analyses.

6. **Create Tests**
   Create `tests/test_langgraph_orchestrator.py`:
   - Test workflow creation
   - Test state updates
   - Test agent communication
   - Test validation loops

### Deliverables for Week 1-2

- ✅ LangGraph orchestrator working
- ✅ Basic agent communication
- ✅ State persistence
- ✅ Test: Simple workflow execution

### Files to Create

```
src/threat_research_mcp/
├── orchestrator/
│   └── langgraph_orchestrator.py
├── agents/
│   └── base_agent.py
├── schemas/
│   └── workflow_state.py
tests/
└── test_langgraph_orchestrator.py
```

---

## Key Principles to Follow

### 1. Attribution Honesty
- NEVER say "confirmed attribution"
- ALWAYS use "assessed" or "potential"
- Show confidence scores with caveats
- Cap confidence at 85% without unique indicators

### 2. Behavioral Focus (Pyramid of Pain)
- Hunt for TTPs (behaviors), not IOCs
- TTPs are at the top of Pyramid of Pain (hardest to change)
- IOCs are at the bottom (easy to change)

### 3. Transparency
- Show confidence breakdown
- Explain assessment basis
- Highlight what's missing
- Alternative hypotheses

### 4. Collaboration
- Multi-user workspace (CRADLE integration later)
- Graph visualization
- Report generation

### 5. Extensibility
- BYOK (Bring Your Own Keys)
- Modular agent design
- Plugin architecture
- Graceful degradation

---

## Project Structure

```
threat-research-mcp/
├── src/threat_research_mcp/
│   ├── orchestrator/           # LangGraph workflow
│   ├── agents/                 # Multi-agent system
│   │   ├── base_agent.py
│   │   ├── research_agent_v2.py
│   │   ├── hunting_agent_v2.py
│   │   ├── detection_agent_v2.py
│   │   └── reviewer_agent_v2.py
│   ├── enrichment/             # Threat intel sources
│   │   ├── tier1/              # Essential (VT, OTX, etc.)
│   │   ├── tier2/              # Advanced (Shodan, etc.)
│   │   ├── tier3/              # Specialized (C2, phishing)
│   │   └── tier4/              # LOLBins
│   ├── frameworks/             # Hunting frameworks
│   │   ├── peak.py
│   │   ├── tahiti.py
│   │   ├── sqrrl.py
│   │   └── pyramid_of_pain.py
│   ├── detection/              # Detection generation
│   │   ├── generators/         # Sigma, KQL, SPL, etc.
│   │   └── validators/
│   ├── validation/             # Quality assurance
│   ├── attribution/            # Attribution engine
│   ├── graph/                  # Graph intelligence
│   ├── integrations/           # CRADLE, etc.
│   └── schemas/                # Data models
├── tests/                      # Test suite
├── docs/                       # Documentation
│   ├── ROADMAP-V2-PLAN.md     # Complete roadmap
│   └── NEW-CHAT-PROMPT.md     # This file
└── examples/                   # Demo scripts
```

---

## What I Need Help With

**Start with Week 1-2: Foundation**

Please help me:
1. Set up LangGraph infrastructure
2. Create base agent framework
3. Design state schema
4. Implement basic workflow
5. Add memory/checkpointing
6. Write tests

Let's start with task #1: Install dependencies and verify LangGraph is working.

---

## Additional Context

- **Python version**: 3.10+ (for MCP server)
- **Current tests**: 100 passing
- **Current tools**: 19 MCP tools
- **Target**: 9/10 for security researchers
- **Timeline**: v0.5.0 in 6-8 weeks

---

## References

- Full roadmap: `docs/ROADMAP-V2-PLAN.md`
- Current codebase: `src/threat_research_mcp/`
- Tests: `tests/`
- Examples: `examples/`

---

**Let's build this! Start with Week 1-2: Foundation.**
