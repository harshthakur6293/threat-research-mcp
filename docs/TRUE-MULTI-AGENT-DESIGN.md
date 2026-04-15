# True Multi-Agent System Design

## Current State vs. True Multi-Agent

### Current Implementation (v0.4)
```
User Input → Research Agent → Hunting Agent → Detection Agent → Reviewer → Output
              (extract IOCs)   (gen hunts)     (gen detections)  (validate)
              
- Sequential pipeline
- Minimal agent communication
- No autonomy
- No feedback loops
```

### True Multi-Agent System
```
                    ┌─────────────────┐
                    │ Orchestrator    │
                    │ (Task Planner)  │
                    └────────┬────────┘
                             │
        ┌────────────────────┼────────────────────┐
        │                    │                    │
        ▼                    ▼                    ▼
  ┌──────────┐         ┌──────────┐        ┌──────────┐
  │Research  │◄───────►│ Hunting  │◄──────►│Detection │
  │ Agent    │         │  Agent   │        │  Agent   │
  └────┬─────┘         └────┬─────┘        └────┬─────┘
       │                    │                    │
       └────────────────────┼────────────────────┘
                            │
                            ▼
                    ┌─────────────┐
                    │Shared Memory│
                    │  (Context)  │
                    └─────────────┘
```

---

## Key Differences

### 1. Agent Communication

**Current (v0.4):**
```python
# Agents don't talk to each other
research = run_research(text)
hunting = run_hunting(text)  # Doesn't use research output!
detection = run_detection(text, research)  # Only detection uses research
```

**True Multi-Agent:**
```python
class Agent:
    def send_message(self, to_agent: str, message: dict):
        """Send message to another agent"""
        
    def receive_message(self, from_agent: str, message: dict):
        """Receive and process message from another agent"""

# Example flow:
research_agent.analyze(text)
research_agent.send_message("hunting", {
    "type": "iocs_found",
    "iocs": [...],
    "techniques": [...]
})

hunting_agent.receive_message("research", msg)
hunting_agent.generate_hunts_for_techniques(msg["techniques"])
hunting_agent.send_message("detection", {
    "type": "hunt_hypotheses",
    "hypotheses": [...]
})
```

### 2. Autonomy & Decision Making

**Current (v0.4):**
```python
# Hard-coded workflow
if routed in {"hunt_generation", ...}:
    state.hunting = run_hunting(text)
```

**True Multi-Agent:**
```python
class Orchestrator:
    def plan_tasks(self, input_text: str) -> List[Task]:
        """Dynamically decide which agents to invoke"""
        tasks = []
        
        # Analyze input
        if self._contains_iocs(input_text):
            tasks.append(Task("research", "extract_iocs"))
        
        if self._mentions_techniques(input_text):
            tasks.append(Task("hunting", "generate_hypotheses"))
            tasks.append(Task("detection", "draft_rules"))
        
        # Agents can request more tasks
        for task in tasks:
            result = self.execute_task(task)
            if result.needs_followup:
                tasks.extend(result.followup_tasks)
        
        return tasks
```

### 3. Feedback Loops

**Current (v0.4):**
```python
# One-way flow, no feedback
research → detection → output
```

**True Multi-Agent:**
```python
# Agents can request clarification or more work
detection_agent.generate_rule(...)
if detection_agent.confidence < 0.7:
    detection_agent.request_more_context("research", {
        "question": "Need more IOCs for this technique",
        "technique": "T1566.001"
    })
    
    research_agent.receive_request(...)
    research_agent.deep_dive_on_technique("T1566.001")
    research_agent.send_response("detection", {...})
```

### 4. Shared Memory/Context

**Current (v0.4):**
```python
# State is just a dict passed around
state = init_state(routed, text)
state.research = ...
state.hunting = ...
```

**True Multi-Agent:**
```python
class SharedMemory:
    """Persistent context all agents can read/write"""
    
    def __init__(self):
        self.facts = {}  # Known facts
        self.hypotheses = []  # Working hypotheses
        self.confidence_scores = {}
        self.agent_observations = defaultdict(list)
    
    def add_fact(self, agent: str, fact_type: str, data: dict):
        """Agent adds a fact to shared memory"""
        self.facts[f"{agent}:{fact_type}"] = {
            "data": data,
            "confidence": data.get("confidence", 1.0),
            "timestamp": datetime.now()
        }
    
    def query(self, query: str) -> List[dict]:
        """Agents query shared memory"""
        # Semantic search over facts
        return self._search(query)

# Usage:
research_agent.observe("Found IOC: 185.220.101.45")
memory.add_fact("research", "ioc", {"value": "185.220.101.45", "type": "ipv4"})

hunting_agent.query("What IOCs did research find?")
# Returns: [{"value": "185.220.101.45", "type": "ipv4"}]
```

---

## Implementation Example: True Multi-Agent

### Architecture

```python
# src/threat_research_mcp/agents/base_agent.py
from abc import ABC, abstractmethod
from typing import Dict, List, Optional

class BaseAgent(ABC):
    def __init__(self, name: str, orchestrator: 'Orchestrator'):
        self.name = name
        self.orchestrator = orchestrator
        self.inbox = []  # Messages from other agents
        self.memory = orchestrator.shared_memory
    
    @abstractmethod
    def can_handle(self, task: 'Task') -> bool:
        """Can this agent handle this task?"""
        pass
    
    @abstractmethod
    def execute(self, task: 'Task') -> 'TaskResult':
        """Execute the task"""
        pass
    
    def send_message(self, to_agent: str, message: Dict):
        """Send message to another agent"""
        self.orchestrator.route_message(
            from_agent=self.name,
            to_agent=to_agent,
            message=message
        )
    
    def receive_message(self, from_agent: str, message: Dict):
        """Receive message from another agent"""
        self.inbox.append({
            "from": from_agent,
            "message": message,
            "timestamp": datetime.now()
        })
    
    def request_help(self, from_agent: str, request: Dict) -> Dict:
        """Request help from another agent"""
        self.send_message(from_agent, {
            "type": "help_request",
            "request": request
        })
        # Wait for response (with timeout)
        return self._wait_for_response(from_agent, timeout=30)


# src/threat_research_mcp/agents/research_agent_v2.py
class ResearchAgentV2(BaseAgent):
    def can_handle(self, task: Task) -> bool:
        return task.type in ["extract_iocs", "summarize", "map_attack", "deep_dive"]
    
    def execute(self, task: Task) -> TaskResult:
        if task.type == "extract_iocs":
            return self._extract_iocs(task.data["text"])
        elif task.type == "deep_dive":
            # Another agent requested more detail
            return self._deep_dive(task.data["technique"])
    
    def _extract_iocs(self, text: str) -> TaskResult:
        iocs = extract_iocs_from_text(text)
        
        # Add to shared memory
        self.memory.add_fact(self.name, "iocs", iocs)
        
        # Notify other agents
        if iocs["ips"] or iocs["domains"]:
            self.send_message("hunting", {
                "type": "iocs_available",
                "iocs": iocs
            })
            self.send_message("detection", {
                "type": "iocs_available",
                "iocs": iocs
            })
        
        return TaskResult(
            agent=self.name,
            task=task,
            result=iocs,
            confidence=0.9,
            followup_tasks=[]
        )


# src/threat_research_mcp/agents/detection_agent_v2.py
class DetectionAgentV2(BaseAgent):
    def can_handle(self, task: Task) -> bool:
        return task.type in ["generate_detection", "validate_detection"]
    
    def execute(self, task: Task) -> TaskResult:
        # Check shared memory for context
        iocs = self.memory.query("iocs")
        techniques = self.memory.query("techniques")
        
        if not techniques:
            # Request more context from research agent
            response = self.request_help("research", {
                "action": "map_attack",
                "text": task.data["text"]
            })
            techniques = response["techniques"]
        
        # Generate detection
        detection = self._generate_sigma(techniques, iocs)
        
        # Validate with reviewer
        validation = self.request_help("reviewer", {
            "action": "validate",
            "detection": detection
        })
        
        if validation["score"] < 0.7:
            # Low confidence, request more context
            return TaskResult(
                agent=self.name,
                task=task,
                result=detection,
                confidence=validation["score"],
                followup_tasks=[
                    Task("research", "deep_dive", {"technique": techniques[0]})
                ]
            )
        
        return TaskResult(
            agent=self.name,
            task=task,
            result=detection,
            confidence=validation["score"],
            followup_tasks=[]
        )


# src/threat_research_mcp/orchestrator/orchestrator_v2.py
class Orchestrator:
    def __init__(self):
        self.agents = {}
        self.shared_memory = SharedMemory()
        self.task_queue = []
        self.message_bus = MessageBus()
    
    def register_agent(self, agent: BaseAgent):
        """Register an agent"""
        self.agents[agent.name] = agent
    
    def run(self, input_text: str, workflow: str = "auto") -> Dict:
        """Run multi-agent workflow"""
        
        # 1. Plan initial tasks
        tasks = self._plan_tasks(input_text, workflow)
        self.task_queue.extend(tasks)
        
        # 2. Execute tasks (agents can add more tasks)
        results = []
        while self.task_queue:
            task = self.task_queue.pop(0)
            
            # Find agent that can handle this task
            agent = self._find_agent_for_task(task)
            if not agent:
                continue
            
            # Execute task
            result = agent.execute(task)
            results.append(result)
            
            # Add followup tasks
            if result.followup_tasks:
                self.task_queue.extend(result.followup_tasks)
        
        # 3. Build final output
        return self._build_output(results)
    
    def route_message(self, from_agent: str, to_agent: str, message: Dict):
        """Route message between agents"""
        if to_agent in self.agents:
            self.agents[to_agent].receive_message(from_agent, message)
    
    def _plan_tasks(self, text: str, workflow: str) -> List[Task]:
        """Dynamically plan tasks based on input"""
        tasks = []
        
        # Always start with research
        tasks.append(Task("research", "extract_iocs", {"text": text}))
        tasks.append(Task("research", "summarize", {"text": text}))
        tasks.append(Task("research", "map_attack", {"text": text}))
        
        # Add workflow-specific tasks
        if workflow in ["threat_research", "auto"]:
            tasks.append(Task("hunting", "generate_hypotheses", {"text": text}))
            tasks.append(Task("detection", "generate_detection", {"text": text}))
        
        return tasks
    
    def _find_agent_for_task(self, task: Task) -> Optional[BaseAgent]:
        """Find agent that can handle this task"""
        for agent in self.agents.values():
            if agent.can_handle(task):
                return agent
        return None
```

### Usage Comparison

**Current (v0.4):**
```python
# User calls MCP tool
result = analysis_product(text="APT29 using PowerShell...")

# Behind the scenes: sequential pipeline
# research → hunting → detection → reviewer → output
```

**True Multi-Agent:**
```python
# Initialize orchestrator
orchestrator = Orchestrator()
orchestrator.register_agent(ResearchAgentV2("research", orchestrator))
orchestrator.register_agent(HuntingAgentV2("hunting", orchestrator))
orchestrator.register_agent(DetectionAgentV2("detection", orchestrator))
orchestrator.register_agent(ReviewerAgentV2("reviewer", orchestrator))

# Run workflow
result = orchestrator.run(text="APT29 using PowerShell...", workflow="auto")

# Behind the scenes:
# 1. Orchestrator plans tasks
# 2. Research agent extracts IOCs, notifies hunting/detection
# 3. Detection agent requests more context from research
# 4. Research agent does deep dive
# 5. Detection agent generates rule, asks reviewer to validate
# 6. Reviewer validates, detection agent refines
# 7. All results merged into final output
```

---

## Benefits of True Multi-Agent

### 1. Flexibility
- Agents can handle unexpected situations
- Dynamic task allocation
- Adaptive workflows

### 2. Collaboration
- Agents work together, not in isolation
- Share context and findings
- Request help when needed

### 3. Quality
- Feedback loops improve output
- Validation and refinement
- Higher confidence results

### 4. Extensibility
- Easy to add new agents
- Agents can specialize
- Plug-and-play architecture

---

## Recommendation

### For v0.5 (Graph Intelligence)
**Keep current pipeline** - it works well for the use case

### For v0.6+ (Advanced Intelligence)
**Consider true multi-agent** if you need:
- Complex reasoning workflows
- Adaptive behavior
- Agent specialization
- Real-time collaboration

### Hybrid Approach (Best of Both)
```python
# Keep simple pipeline for common cases
if workflow == "simple":
    return run_pipeline(text)

# Use multi-agent for complex cases
elif workflow == "complex":
    return orchestrator.run(text)
```

---

## Summary

**Current State:**
- ✅ Works well for structured workflows
- ✅ Fast and predictable
- ✅ Easy to understand and debug
- ❌ Not truly "multi-agent"
- ❌ Limited flexibility
- ❌ No agent collaboration

**True Multi-Agent:**
- ✅ Autonomous agents
- ✅ Dynamic collaboration
- ✅ Adaptive workflows
- ❌ More complex
- ❌ Harder to debug
- ❌ Potential for unpredictable behavior

**Verdict:** Your current "multi-agent" system is really a **modular pipeline with named stages**. That's perfectly fine for your use case! True multi-agent would add complexity without clear benefits for v0.4-v0.5.
