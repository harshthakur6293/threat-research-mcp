# LangGraph Multi-Agent System - Quick Start

**Version:** v0.5.0-dev (Phase 1: Foundation)

This guide will help you get started with the new LangGraph-based multi-agent system for threat-research-mcp v2.0.

---

## 🎯 What's New in v0.5.0

### True Multi-Agent System

v0.4 was a **sequential pipeline** (agents didn't communicate):
```python
# v0.4: Sequential pipeline
research → hunting → detection → reviewer
(each agent processes independently)
```

v0.5.0 is a **true multi-agent system** (agents collaborate):
```python
# v0.5.0: Multi-agent collaboration
research → [hunting + detection] → reviewer
           ↓                          ↓
           ← ← ← ← validation loop ← ←
```

### Key Features

- ✅ **Agent Communication** — Agents share state and build on each other's findings
- ✅ **Validation Loops** — Automatic refinement when confidence < threshold
- ✅ **Human-in-the-Loop** — Prompts for feedback when needed
- ✅ **Memory/Checkpointing** — Context retention across analyses
- ✅ **Conditional Routing** — Dynamic workflow based on confidence scores

---

## 📋 Prerequisites

### Python Version

**LangGraph requires Python 3.9+** (preferably 3.10+ for MCP server compatibility)

Check your Python version:
```bash
python --version
```

If you have Python 3.8, you need to upgrade:

#### Windows
1. Download Python 3.10 or 3.11 from [python.org](https://www.python.org/downloads/)
2. Install (check "Add Python to PATH")
3. Verify: `python --version`

#### Linux/Mac
```bash
# Using pyenv (recommended)
pyenv install 3.10.12
pyenv local 3.10.12

# Or using system package manager
# Ubuntu/Debian
sudo apt install python3.10

# Mac
brew install python@3.10
```

---

## 🚀 Installation

### Step 1: Create Virtual Environment with Python 3.9+

```bash
cd threat-research-mcp

# Create new virtual environment with Python 3.10+
python3.10 -m venv .venv

# Activate virtual environment
# Windows
.venv\Scripts\activate

# Linux/Mac
source .venv/bin/activate
```

### Step 2: Install Dependencies

```bash
# Install project with LangGraph dependencies
pip install -e ".[dev]"

# Or install LangGraph separately
pip install langgraph langchain langchain-core langchain-openai
```

### Step 3: Verify Installation

```bash
python -c "from threat_research_mcp.orchestrator.langgraph_orchestrator import LangGraphOrchestrator; print('✅ LangGraph installed successfully')"
```

---

## 🎓 Basic Usage

### Example 1: Simple Workflow

```python
from threat_research_mcp.orchestrator.langgraph_orchestrator import create_orchestrator
from threat_research_mcp.schemas.workflow_state import create_initial_state

# Create orchestrator
orchestrator = create_orchestrator(enable_memory=True)

# Create initial state
state = create_initial_state(
    intel_text="""
    APT29 campaign detected using PowerShell for initial access.
    IOCs: 185.220.101.45, malicious-c2.com
    Techniques: T1059.001 (PowerShell), T1071.001 (Web C2)
    """,
    target_platforms=["splunk", "sentinel"],
    framework="PEAK",
)

# Run workflow
result = orchestrator.run(state)

# Access results
print("Research Findings:", result["research_findings"])
print("Hunt Plan:", result["hunt_plan"])
print("Detections:", result["detections"])
print("Review Report:", result["review_report"])
```

### Example 2: With Custom Agents

```python
from threat_research_mcp.agents.base_agent import BaseAgent
from threat_research_mcp.schemas.workflow_state import ThreatAnalysisState

# Create custom agent
class CustomResearchAgent(BaseAgent):
    def execute(self, state: ThreatAnalysisState) -> ThreatAnalysisState:
        # Your custom logic here
        intel_text = state["intel_text"]
        
        # Extract IOCs, enrich, etc.
        findings = {
            "iocs": ["185.220.101.45"],
            "techniques": ["T1059.001"],
            "confidence": 0.85
        }
        
        # Update state
        state["research_findings"] = self._create_output(
            findings=findings,
            confidence=0.85
        )
        
        return self._record_execution(state)

# Use custom agent
research_agent = CustomResearchAgent("My Research Agent")
orchestrator = create_orchestrator(research_agent=research_agent)

state = create_initial_state(intel_text="...")
result = orchestrator.run(state)
```

### Example 3: Async Execution

```python
import asyncio

async def analyze_threat():
    orchestrator = create_orchestrator()
    state = create_initial_state(intel_text="...")
    
    result = await orchestrator.arun(state)
    return result

# Run async
result = asyncio.run(analyze_threat())
```

---

## 🧪 Running Tests

### Run All Tests

```bash
# Run all tests
pytest tests/test_langgraph_orchestrator.py -v

# Run with coverage
pytest tests/test_langgraph_orchestrator.py --cov=src/threat_research_mcp -v
```

### Run Specific Tests

```bash
# Test workflow execution
pytest tests/test_langgraph_orchestrator.py::TestLangGraphOrchestrator::test_simple_workflow_execution -v

# Test validation loops
pytest tests/test_langgraph_orchestrator.py::TestLangGraphOrchestrator::test_validation_loop_trigger -v

# Test agent communication
pytest tests/test_langgraph_orchestrator.py::TestLangGraphOrchestrator::test_agent_communication -v
```

---

## 🔧 Configuration

### State Configuration

```python
state = create_initial_state(
    intel_text="...",
    api_keys={
        "virustotal": "your_vt_key",
        "shodan": "your_shodan_key",
    },
    target_platforms=["splunk", "sentinel", "elastic"],
    framework="PEAK",  # or "TaHiTI", "SQRRL"
    environment="aws",  # or "azure", "gcp", "on-prem", "hybrid"
    max_iterations=3,  # Max refinement loops
)
```

### Memory Configuration

```python
# With memory (recommended)
orchestrator = create_orchestrator(enable_memory=True)

# Run with thread_id for persistent memory
config = {"configurable": {"thread_id": "analysis-123"}}
result = orchestrator.run(state, config=config)

# Without memory
orchestrator = create_orchestrator(enable_memory=False)
```

---

## 📊 Understanding the Workflow

### Workflow Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    LangGraph Workflow                        │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  START                                                       │
│    │                                                         │
│    ▼                                                         │
│  ┌──────────────┐                                           │
│  │   Research   │  Extract IOCs, enrich, map to ATT&CK      │
│  │    Agent     │                                           │
│  └──────┬───────┘                                           │
│         │                                                    │
│         ├────────────────┬─────────────────┐                │
│         ▼                ▼                 ▼                │
│  ┌──────────┐     ┌──────────┐     ┌──────────┐            │
│  │ Hunting  │     │Detection │     │ (Parallel)│            │
│  │  Agent   │     │  Agent   │     │           │            │
│  └────┬─────┘     └────┬─────┘     └───────────┘            │
│       │                │                                     │
│       └────────┬───────┘                                     │
│                ▼                                             │
│         ┌──────────────┐                                     │
│         │   Reviewer   │  Validate, score confidence        │
│         │    Agent     │                                     │
│         └──────┬───────┘                                     │
│                │                                             │
│         ┌──────┴──────┐                                      │
│         │             │                                      │
│    Confidence    Confidence                                  │
│      < 0.7         < 0.5                                     │
│         │             │                                      │
│         ▼             ▼                                      │
│    ┌────────┐   ┌────────────┐                              │
│    │ Refine │   │   Human    │                              │
│    │  Loop  │   │   Review   │                              │
│    └───┬────┘   └─────┬──────┘                              │
│        │              │                                      │
│        └──────┬───────┘                                      │
│               │                                              │
│               ▼                                              │
│            END (Complete)                                    │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### State Flow

1. **Research Agent** extracts IOCs and enriches them
2. **Hunting Agent** uses research findings to create hunt hypotheses
3. **Detection Agent** uses research findings to generate detection rules
4. **Reviewer Agent** validates all outputs and calculates confidence
5. **Conditional Routing**:
   - Confidence ≥ 0.7 → Complete
   - Confidence < 0.7 → Refine (loop back to Research)
   - Confidence < 0.5 → Human Review

---

## 🎯 Next Steps

### Phase 1 Complete ✅

You've completed Phase 1, Week 1-2: Foundation!

**Deliverables:**
- ✅ LangGraph orchestrator working
- ✅ Basic agent communication
- ✅ State persistence
- ✅ Test: Simple workflow execution

### Phase 1, Week 3-4: Research Agent v2

Next, we'll implement the Research Agent with:
- Multi-source intelligence enrichment (15+ sources)
- BYOK (Bring Your Own Keys) support
- Confidence scoring
- Graceful degradation

See [`docs/ROADMAP-V2-PLAN.md`](ROADMAP-V2-PLAN.md) for the complete roadmap.

---

## 🐛 Troubleshooting

### ImportError: No module named 'langgraph'

**Problem:** LangGraph not installed or Python version < 3.9

**Solution:**
```bash
# Check Python version
python --version

# If < 3.9, upgrade Python first
# Then reinstall dependencies
pip install langgraph langchain langchain-core
```

### Tests Skipped: "LangGraph not installed"

**Problem:** Tests are skipped because LangGraph is not available

**Solution:** Install LangGraph dependencies:
```bash
pip install langgraph langchain langchain-core langchain-openai
```

### ModuleNotFoundError: No module named 'threat_research_mcp.schemas'

**Problem:** Project not installed in editable mode

**Solution:**
```bash
pip install -e .
```

---

## 📚 Additional Resources

- **Complete Roadmap:** [`docs/ROADMAP-V2-PLAN.md`](ROADMAP-V2-PLAN.md)
- **Architecture:** [`docs/TRUE-MULTI-AGENT-DESIGN.md`](TRUE-MULTI-AGENT-DESIGN.md)
- **LangGraph Docs:** https://langchain-ai.github.io/langgraph/
- **LangChain Docs:** https://python.langchain.com/

---

## 💡 Tips

1. **Start with mock agents** to understand the workflow
2. **Enable memory** for production use
3. **Set appropriate max_iterations** (default: 3)
4. **Monitor confidence scores** to tune validation thresholds
5. **Use thread_id** for persistent memory across analyses

---

**Ready to build v2.0!** 🚀
