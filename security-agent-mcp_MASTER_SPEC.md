
# security-agent-mcp_MASTER_SPEC.md

FULL MASTER SPEC FOR CURSOR / CLINE

PROJECT NAME:
security-agent-mcp

GOAL:
Build an open-source defensive-security MCP server + multi-agent orchestration system that converts messy threat intel into structured outputs such as:

- IOCs
- ATT&CK mappings
- Sigma detections
- hunt hypotheses
- timelines
- coverage gaps
- structured security intelligence artifacts

CORE IDEA:
LLM reasoning + structured tools + orchestration + memory layer.

NOT building offensive tooling.

---

ARCHITECTURE OVERVIEW

Client
↓
MCP Server
↓
Orchestrator
↓
Agents
↓
Tools
↓
Memory
↓
Storage
↓
Optional integrations

---

AGENTS

1. Research Agent
- extract IOCs
- summarize reports
- map ATT&CK
- identify behaviors
- produce structured findings

2. Detection Agent
- generate Sigma rules
- generate hunt hypotheses
- suggest telemetry
- identify detection opportunities

3. Reviewer Agent
- validate logic
- flag false positives
- identify blind spots
- produce confidence score

---

WORKFLOWS

threat_research
hunt_generation
detection_generation
timeline_reconstruction
log_explanation
coverage_analysis
report_comparison

---

MEMORY MODEL

request memory
session memory
project memory
future intelligence graph memory

v1 storage:
SQLite

future:
Synapse
Neo4j

---

INGESTION SOURCES

local files
RSS feeds
TAXII
HTML reports

pipeline:

fetch
parse
normalize
deduplicate
store
analyze

---

DETECTION ENGINEERING OUTPUT

Sigma rules first.

Later:
YARA
KQL
SPL
EQL

---

THREAT HUNT OUTPUT

hypothesis
priority
confidence
evidence
ATT&CK techniques
telemetry needed
hunt steps
queries
detection opportunities

---

FUTURE INTEGRATIONS PLACEHOLDERS

OpenCTI
MISP
Vertex Synapse
Neo4j

---

REPO STRUCTURE

security-agent-mcp/

docs/
architecture.md
roadmap.md
safety-model.md
agent-design.md
memory-model.md
threat-hunting.md
detection-engineering.md
coverage-analysis.md

src/security_agent_mcp/

schemas/
ioc.py
attack.py
sigma.py
timeline.py
workflow.py
memory.py
detection.py
hunt.py
coverage.py

agents/
research_agent.py
detection_agent.py
reviewer_agent.py

tools/
extract_iocs.py
summarize_threat_report.py
map_attack.py
generate_sigma.py
generate_hunt_hypothesis.py
explain_log.py
reconstruct_timeline.py

orchestrator/
router.py
workflow.py
state.py
policy.py
formatter.py

ingestion/
rss_adapter.py
taxii_adapter.py
html_adapter.py
local_file_adapter.py
normalizer.py
deduper.py

memory/
session_store.py
artifact_store.py
retriever.py

storage/
sqlite.py

coverage/
gap_analysis.py
datasource_mapper.py

hunt/
hypothesis_generator.py
hunt_planner.py

detection/
rule_generator.py
rule_validator.py

integrations/
synapse/
neo4j/
opencti/
misp/

retrieval/
semantic.py
hybrid.py

examples/
sample_inputs/
expected_outputs/

tests/

configs/

.github/

---

BUILD ORDER

1 repo skeleton
2 schemas
3 tools
4 MCP server
5 agents
6 orchestrator
7 ingestion
8 memory
9 coverage
10 docs

---

SAFETY

defensive only
read-only analysis
no offensive automation

---

INTENT

Create reusable defensive security reasoning layer
usable by organizations
easy to extend
open-source friendly

