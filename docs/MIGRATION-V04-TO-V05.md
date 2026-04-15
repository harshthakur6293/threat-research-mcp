# Migration Guide: v0.4 → v0.5.0

**From:** Sequential Pipeline (v0.4)  
**To:** LangGraph Multi-Agent System (v0.5.0)

---

## 🎯 What's Changing

### Architecture

**v0.4 (Sequential Pipeline):**
```python
# Hard-coded sequential execution
def run_workflow(text):
    research = run_research(text)
    hunting = run_hunting(text)  # Doesn't use research!
    detection = run_detection(text, research)
    review = run_review(research, hunting, detection)
    return format_output(...)
```

**v0.5.0 (Multi-Agent System):**
```python
# Dynamic multi-agent collaboration
orchestrator = create_orchestrator()
state = create_initial_state(intel_text=text)
result = orchestrator.run(state)  # Agents communicate via state
```

### Key Differences

| Feature | v0.4 | v0.5.0 |
|---------|------|--------|
| **Agent Communication** | ❌ No | ✅ Yes (via shared state) |
| **Validation Loops** | ❌ No | ✅ Yes (automatic refinement) |
| **Human-in-the-Loop** | ❌ No | ✅ Yes (low confidence prompts) |
| **Memory/Context** | ❌ No | ✅ Yes (checkpointing) |
| **Conditional Routing** | ❌ No | ✅ Yes (dynamic workflow) |
| **Python Version** | 3.8+ | 3.9+ (LangGraph requirement) |

---

## 🔄 Breaking Changes

### 1. Python Version Requirement

**v0.4:** Python 3.8+  
**v0.5.0:** Python 3.9+ (required for LangGraph)

**Action Required:**
```bash
# Check your Python version
python --version

# If < 3.9, upgrade Python first
# Then create new virtual environment
python3.10 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

### 2. New Dependencies

**Added:**
- `langgraph>=0.2.0`
- `langchain>=0.3.0`
- `langchain-core>=0.3.0`
- `langchain-openai>=0.2.0`

**Installation:**
```bash
pip install -e ".[dev]"
```

### 3. Orchestrator API

**v0.4 (Old):**
```python
from threat_research_mcp.orchestrator import Orchestrator

orchestrator = Orchestrator()
result = orchestrator.run(intel_text="...")
```

**v0.5.0 (New):**
```python
from threat_research_mcp.orchestrator.langgraph_orchestrator import create_orchestrator
from threat_research_mcp.schemas.workflow_state import create_initial_state

orchestrator = create_orchestrator()
state = create_initial_state(intel_text="...")
result = orchestrator.run(state)
```

---

## 📦 Migration Steps

### Step 1: Backup Current Setup

```bash
# Backup your current environment
cp pyproject.toml pyproject.toml.backup
pip freeze > requirements-v04.txt
```

### Step 2: Upgrade Python (if needed)

```bash
# Check current version
python --version

# If < 3.9, install Python 3.10+
# Windows: Download from python.org
# Linux: sudo apt install python3.10
# Mac: brew install python@3.10
```

### Step 3: Create New Virtual Environment

```bash
# Deactivate old environment
deactivate

# Create new environment with Python 3.10+
python3.10 -m venv .venv-v05

# Activate new environment
# Windows
.venv-v05\Scripts\activate

# Linux/Mac
source .venv-v05/bin/activate
```

### Step 4: Install v0.5.0 Dependencies

```bash
# Install project with new dependencies
pip install -e ".[dev]"

# Verify LangGraph installation
python -c "from langgraph.graph import StateGraph; print('✅ LangGraph installed')"
```

### Step 5: Update Your Code

#### Example: Simple Analysis

**v0.4 Code:**
```python
from threat_research_mcp.orchestrator import Orchestrator

orchestrator = Orchestrator()
result = orchestrator.run(
    intel_text="APT29 campaign...",
    workflow="full"
)

print(result["research"])
print(result["hunting"])
print(result["detection"])
```

**v0.5.0 Code:**
```python
from threat_research_mcp.orchestrator.langgraph_orchestrator import create_orchestrator
from threat_research_mcp.schemas.workflow_state import create_initial_state

orchestrator = create_orchestrator(enable_memory=True)
state = create_initial_state(
    intel_text="APT29 campaign...",
    target_platforms=["splunk", "sentinel"],
    framework="PEAK"
)

result = orchestrator.run(state)

print(result["research_findings"])
print(result["hunt_plan"])
print(result["detections"])
print(result["review_report"])
```

#### Example: Custom Agents

**v0.4 Code:**
```python
class CustomResearchAgent:
    def analyze(self, text):
        # Your logic
        return {"iocs": [...]}

orchestrator = Orchestrator(research_agent=CustomResearchAgent())
```

**v0.5.0 Code:**
```python
from threat_research_mcp.agents.base_agent import BaseAgent
from threat_research_mcp.schemas.workflow_state import ThreatAnalysisState

class CustomResearchAgent(BaseAgent):
    def execute(self, state: ThreatAnalysisState) -> ThreatAnalysisState:
        # Your logic
        state["research_findings"] = self._create_output(
            findings={"iocs": [...]},
            confidence=0.85
        )
        return self._record_execution(state)

orchestrator = create_orchestrator(research_agent=CustomResearchAgent("My Agent"))
```

### Step 6: Update Tests

**v0.4 Tests:**
```python
def test_orchestrator():
    orchestrator = Orchestrator()
    result = orchestrator.run(intel_text="test")
    assert "research" in result
```

**v0.5.0 Tests:**
```python
def test_orchestrator():
    orchestrator = create_orchestrator(enable_memory=False)
    state = create_initial_state(intel_text="test")
    result = orchestrator.run(state)
    assert result["research_findings"] is not None
```

### Step 7: Run Tests

```bash
# Run new LangGraph tests
pytest tests/test_langgraph_orchestrator.py -v

# Run all tests
pytest tests/ -v
```

---

## 🔧 Configuration Changes

### State Configuration

**v0.5.0 introduces rich state configuration:**

```python
state = create_initial_state(
    intel_text="...",
    api_keys={
        "virustotal": "your_key",
        "shodan": "your_key",
    },
    target_platforms=["splunk", "sentinel", "elastic"],
    framework="PEAK",  # or "TaHiTI", "SQRRL"
    environment="aws",  # or "azure", "gcp", "on-prem", "hybrid"
    max_iterations=3,  # Max refinement loops
)
```

### Memory Configuration

**New in v0.5.0:**

```python
# Enable memory for context retention
orchestrator = create_orchestrator(enable_memory=True)

# Use thread_id for persistent memory
config = {"configurable": {"thread_id": "analysis-123"}}
result = orchestrator.run(state, config=config)
```

---

## 🆕 New Features

### 1. Validation Loops

Automatic refinement when confidence is low:

```python
# Workflow automatically loops back if confidence < 0.7
state = create_initial_state(
    intel_text="...",
    max_iterations=3  # Limit refinement loops
)

result = orchestrator.run(state)
print(f"Iterations: {result['iteration']}")
```

### 2. Human-in-the-Loop

Prompts for human feedback when confidence is very low:

```python
# If confidence < 0.5, workflow requests human review
# (Automatic in v0.5.0)
```

### 3. Agent Communication

Agents now share findings via state:

```python
# Hunting Agent can use Research Agent's IOCs
research_findings = state["research_findings"]
iocs = research_findings["findings"]["iocs"]

# Use IOCs in hunt queries
hunt_queries = [f"search {ioc}" for ioc in iocs]
```

### 4. Async Execution

New async support:

```python
import asyncio

async def analyze():
    orchestrator = create_orchestrator()
    state = create_initial_state(intel_text="...")
    result = await orchestrator.arun(state)
    return result

result = asyncio.run(analyze())
```

---

## 🐛 Troubleshooting

### Issue: ImportError: No module named 'langgraph'

**Cause:** LangGraph not installed or Python < 3.9

**Solution:**
```bash
# Check Python version
python --version  # Must be 3.9+

# Install LangGraph
pip install langgraph langchain langchain-core
```

### Issue: Tests Skipped

**Cause:** LangGraph not available

**Solution:**
```bash
# Install dependencies
pip install -e ".[dev]"

# Verify
python -c "from langgraph.graph import StateGraph; print('OK')"
```

### Issue: Old orchestrator not found

**Cause:** API changed in v0.5.0

**Solution:** Update imports and code (see migration examples above)

---

## 📚 Resources

### Documentation
- [`docs/LANGGRAPH-QUICKSTART.md`](LANGGRAPH-QUICKSTART.md) - Quick start guide
- [`docs/PHASE1-WEEK1-2-COMPLETE.md`](PHASE1-WEEK1-2-COMPLETE.md) - What's new
- [`docs/ROADMAP-V2-PLAN.md`](ROADMAP-V2-PLAN.md) - Complete roadmap

### Examples
- [`examples/demo_langgraph_workflow.py`](../examples/demo_langgraph_workflow.py) - Interactive demos

### Code
- [`src/threat_research_mcp/orchestrator/langgraph_orchestrator.py`](../src/threat_research_mcp/orchestrator/langgraph_orchestrator.py)
- [`src/threat_research_mcp/agents/base_agent.py`](../src/threat_research_mcp/agents/base_agent.py)
- [`src/threat_research_mcp/schemas/workflow_state.py`](../src/threat_research_mcp/schemas/workflow_state.py)

---

## 🎯 Compatibility

### Backward Compatibility

**v0.4 orchestrator is still available** (for now):
- Old code will continue to work
- Deprecated in v0.5.0
- Will be removed in v0.6.0

**Migration timeline:**
- v0.5.0: Both old and new orchestrators available
- v0.5.1: Old orchestrator deprecated warnings
- v0.6.0: Old orchestrator removed

### Forward Compatibility

v0.5.0 is designed for future enhancements:
- Research Agent v2 (Week 3-4)
- Hunting & Detection Agents v2 (Week 5-6)
- Reviewer Agent v2 (Week 7-8)
- CRADLE integration (v0.5.1)
- Graph intelligence (v0.5.2)

---

## ✅ Migration Checklist

- [ ] Backup current setup
- [ ] Upgrade to Python 3.9+ (preferably 3.10+)
- [ ] Create new virtual environment
- [ ] Install v0.5.0 dependencies
- [ ] Update imports and code
- [ ] Update tests
- [ ] Run test suite
- [ ] Test with your data
- [ ] Update documentation
- [ ] Deploy to production

---

## 💬 Support

**Issues?** Open a GitHub issue with:
- Python version
- Error message
- Code snippet
- Expected vs actual behavior

**Questions?** See:
- [`docs/LANGGRAPH-QUICKSTART.md`](LANGGRAPH-QUICKSTART.md)
- [`docs/ROADMAP-V2-PLAN.md`](ROADMAP-V2-PLAN.md)
- GitHub Discussions

---

**Happy migrating!** 🚀
