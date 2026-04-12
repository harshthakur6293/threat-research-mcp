# Security Agent MCP — Complete Cursor Handoff Document

> **Implementation Note (v0.2.0):** This specification describes the **full architectural vision** for the threat-research-mcp project. The current release (v0.2) implements the **core workflow**: agents, orchestrator, ingestion, MCP tools, and SQLite storage. Advanced features like graph models, direct CTI platform integrations, semantic retrieval, and multi-tenancy are **scaffolded for future versions** (v0.3+). See [`docs/architecture.md`](docs/architecture.md) for detailed implementation status of each module.

This document is a comprehensive handoff for building the **Security Agent MCP** project. It consolidates the design direction, tradeoffs, architecture, skeleton, workflows, schemas, roadmaps, integration plans, and implementation priorities discussed throughout the planning conversation.

This file is meant to be given directly to Cursor as the primary context document for scaffolding and implementing the repository.

\---

## 1\. Project intent and identity

**Project name:** `security-agent-mcp`

**One-line description:**

Security Agent MCP is an open-source MCP server and orchestration framework that gives AI clients access to defensive security research, threat hunting, detection engineering, and investigation workflows.

**Primary goal:**

Build a modular, organization-friendly, open-source defensive security platform that can be adopted incrementally by individuals, labs, and organizations.

**Long-term goal:**

Enable organizations to easily run the system locally or in simple deployments first, then extend it with their own feeds, policies, storage, CTI systems, and eventually connected intelligence-memory backends such as Vertex Synapse or Neo4j.

**Important positioning:**

This project is **not** about training a custom base model first.

This project is about building:

* reusable defensive-security tools
* an MCP-native tool layer
* a small orchestrated agent workflow
* pluggable intel ingestion
* structured outputs for hunts and detections
* memory and retrieval over time
* optional future graph/intelligence integrations

\---

## 2\. How the project started conceptually

The original question was whether it made more sense to build:

* an AI model for offensive security
* an AI model for defensive security
* or an MCP server with tools

The conclusion was:

### Do not start by training separate offensive and defensive foundation models.

Instead, start with:

* one strong general model
* specialized agent roles
* tool permissions and policies
* orchestration logic
* MCP-exposed reusable tools
* memory, retrieval, and structured outputs

The strongest early value is not in a custom model.
It is in:

* workflow design
* tool design
* data ingestion
* structured outputs
* safety boundaries
* verification and review

The project should be fundamentally **defensive**, not offensive.

\---

## 3\. Core philosophy

The system should be built around this idea:

> Turn messy security information into structured defensive insight.

Examples of messy inputs:

* threat blogs
* threat reports
* vendor advisories
* alert summaries
* suspicious commands
* process trees
* investigation notes
* log artifacts
* RSS/TAXII/HTML sourced intelligence

Examples of structured outputs:

* IOC extraction
* ATT\&CK mapping
* report summaries
* hunt hypotheses
* Sigma drafts
* telemetry requirements
* timeline reconstruction
* coverage gap analysis
* reviewer notes and confidence

\---

## 4\. Target users

The project is meant for:

* threat researchers
* SOC analysts
* detection engineers
* incident responders
* threat hunters
* security engineers
* purple teamers
* AI/security builders
* organizations exploring AI-assisted SecOps workflows

Secondary users:

* students learning detection engineering and threat hunting
* startups building security copilots
* teams experimenting with MCP-native security systems

\---

## 5\. What users should be able to do with it

### A. Analyze a threat report

Input:

* a copied vendor threat report paragraph
* an HTML report
* a local text file
* a fetched feed article

Output:

* summary
* extracted IOCs
* ATT\&CK mappings
* hunt ideas
* Sigma draft
* reviewer notes

### B. Explain a suspicious command or log

Input:

* PowerShell command line
* Event ID and notes
* suspicious process tree

Output:

* explanation of behavior
* why it matters
* likely techniques
* what to check next
* possible detections
* possible hunt ideas

### C. Generate detections

Input:

* threat report
* suspicious behavior description
* ATT\&CK technique

Output:

* Sigma rule draft
* false-positive considerations
* required telemetry
* blind spots
* reviewer comments

### D. Generate hunt hypotheses

Input:

* report
* TTP list
* suspicious behavior cluster

Output:

* structured hunt hypothesis
* priority
* confidence
* required telemetry
* suggested hunt steps
* suggested queries
* detection opportunities

### E. Reconstruct a timeline

Input:

* investigation notes
* sequence of events
* mixed artifacts with timestamps

Output:

* ordered incident timeline
* likely malicious chain
* reviewer notes

### F. Analyze coverage gaps

Input:

* techniques
* existing detections
* data source inventory

Output:

* full / partial / none coverage
* missing detections
* missing telemetry
* improvement recommendations

\---

## 6\. Why MCP was chosen as a foundation

The system should be built as an **MCP-first** project because MCP is a good abstraction for exposing:

* tools
* resources
* prompts

to AI clients in a standard way.

This makes the project more portable and adoptable than a fully custom agent-only interface.

### MCP should be used for:

* reusable security tools
* reusable read-only resources
* reusable prompt templates
* compatibility with AI clients that support MCP

### Important design conclusion:

Do not choose between:

* multi-agent system
* orchestration layer
* MCP server

These solve different problems.

Use them together.

### The mental model:

* **MCP** = interface for tools/resources/prompts
* **Orchestrator** = routing and control flow
* **Agents** = specialized reasoning roles

Recommended stack:

**MCP tools at the bottom, orchestrated agents above them.**

\---

## 7\. Why not start with custom model training

The early recommendation was:

Do **not** start by building:

* an offensive foundation model
* a defensive foundation model
* a fine-tuned large base model

Use one strong general model first and specialize behavior through:

* prompts
* roles
* tool access
* memory
* orchestration
* approval and review steps

Fine-tuning should only be considered later for narrow tasks such as:

* alert classification
* log summarization
* ATT\&CK mapping refinement
* phishing triage
* detection normalization

The project’s early value is in **security workflow infrastructure**, not in training a new model.

\---

## 8\. Multi-agent vs MCP vs orchestration

This was clarified explicitly.

### Multi-agent system

This is about how intelligence is organized.
Example specialized roles:

* Research Agent
* Detection Agent
* Reviewer Agent

### Orchestration layer

This is about workflow control.
Responsibilities:

* routing
* sequencing
* retries
* state management
* approvals
* conflict resolution
* evidence tracking

### MCP server

This is about exposing tools, resources, and prompts in a standard way.

### Final recommendation

Use:

* **MCP** for the reusable interface layer
* **orchestration** for workflow sequencing
* **3 agents** for specialization

Do not build a giant swarm.
Do not build a tool-only host without workflow logic.
Do not build a custom orchestration system that ignores MCP portability.

\---

## 9\. Core project architecture

### High-level layers

1. **MCP layer**
2. **Orchestration layer**
3. **Agent layer**
4. **Ingestion layer**
5. **Memory + storage layer**
6. **Future integration layer**

### End-to-end flow

```text
User / AI Client / CLI
    ↓
MCP Client or CLI Entrypoint
    ↓
Orchestrator
    ↓
Research Agent → Detection Agent → Reviewer Agent
    ↓
MCP Tools / Resources / Prompts
    ↓
Ingestion / Memory / Storage / Retrieval
    ↓
Optional future CTI and graph integrations
```

\---

## 10\. The 3-agent design

The project should start with exactly **3 agents**.

### 10.1 Research Agent

Responsibilities:

* analyze normalized input text
* extract IOCs
* summarize report content
* identify behaviors
* identify likely ATT\&CK technique candidates
* provide evidence snippets
* propose initial hypotheses
* prepare structured findings for downstream detection/hunt work

Typical outputs:

* summary
* extracted\_iocs
* attack\_mapping\_candidates
* evidence\_notes
* hypotheses
* confidence notes

### 10.2 Detection Agent

Responsibilities:

* transform structured research findings into:

  * Sigma drafts
  * hunt hypotheses
  * telemetry suggestions
  * detection opportunities
  * coverage hints

Typical outputs:

* Sigma rule draft
* hunt hypothesis objects
* required telemetry list
* possible blind spots
* false-positive considerations
* suggested next steps for detection engineering

### 10.3 Reviewer Agent

Responsibilities:

* verify claims and logic
* flag unsupported mappings
* check rule quality
* assess confidence
* note false positives and gaps
* review safety boundaries
* ensure outputs conform to schemas

Typical outputs:

* status: pass / fail / pass\_with\_notes
* reviewer notes
* confidence score
* missing evidence list
* quality and safety flags

### Why only 3 agents

Because starting with many agents causes:

* complexity
* token waste
* context fragmentation
* harder debugging
* less maintainable code

\---

## 11\. Orchestrator design

The orchestrator is critical.

It must own:

* workflow routing
* shared workflow state
* agent sequencing
* policy enforcement
* approvals
* evidence trace
* final formatting

### Supported workflow types

* `threat\_research`
* `detection\_generation`
* `hunt\_generation`
* `timeline\_reconstruction`
* `log\_explanation`
* `coverage\_analysis`
* `report\_comparison`

### Example orchestrator logic

1. Accept input from CLI, MCP client, or file
2. Normalize the input
3. Detect workflow type
4. Create `WorkflowState`
5. Run Research Agent if needed
6. Run Detection Agent if needed
7. Run Reviewer Agent last
8. Preserve trace of all tool calls and evidence
9. Format final analyst-facing output

\---

## 12\. Workflow state and memory handling

Memory was discussed as **multiple layers**, not one bucket.

### 12.1 Request memory

This is memory for one single workflow run.

It should live in a `WorkflowState` object.

Suggested fields:

* request\_id
* workflow\_type
* input\_text
* normalized\_document\_id
* extracted\_iocs
* summary
* attack\_mapping
* sigma\_draft
* hunt\_hypotheses
* coverage\_results
* reviewer\_notes
* confidence
* safety\_flags
* evidence\_trace

### 12.2 Session memory

This is context across a single analyst session or one conversation.

Examples:

* recent reports analyzed
* previous report summary
* preferred output style
* recent IOCs
* recent techniques

Use this for:

* compare with previous report
* avoid repetition
* preserve recent continuity

### 12.3 Project memory

Persistent memory for the deployment/workspace.

Store:

* normalized intel documents
* prior Sigma drafts
* prior hunt outputs
* prior ATT\&CK mappings
* source configurations
* ingestion history
* dedup hashes
* reviewed outputs

### 12.4 Intelligence memory

This is the future advanced layer.

This is where:

* Vertex Synapse
* Neo4j
* graph relationships
* long-term intelligence memory

can fit later.

### Important context retention rule

Do **not** stuff prompts with everything.

Use:

* selective retrieval
* structured summaries
* evidence snippets
* recent relevant artifacts

Do not inject:

* entire raw histories
* huge report archives
* giant ATT\&CK dumps

\---

## 13\. Storage and retrieval model

### V1 storage requirements

Use:

* SQLite
* artifact store
* session store
* repository abstractions

### Store these artifacts

* normalized documents
* extracted IOC objects
* ATT\&CK mappings
* Sigma drafts
* hunt outputs
* session summaries
* ingestion records
* source definitions
* dedup fingerprints

### Retrieval model

Support:

* exact retrieval
* metadata retrieval
* later semantic retrieval
* later graph retrieval

### Why SQLite first

Because the project should be:

* local-first
* easy to run
* low-friction
* not dependent on cloud infra

### What not to require in v1

* vector DB
* graph DB
* cloud data warehouse
* external CTI platform

\---

## 14\. Ingestion strategy

The project should support **pluggable threat-intel ingestion**.

Do not call it “scrape everything.”

Call it:

* ingest
* normalize
* parse
* analyze

### V1 source adapter types

* `local\_file`
* `rss\_atom`
* `taxii`
* `html\_report`

### Possible later adapters

* `misp`
* `pdf\_report`
* `custom\_adapter`

### Ingestion pipeline

1. fetch
2. parse
3. normalize
4. deduplicate
5. create normalized document
6. save metadata and fingerprint
7. store artifact
8. hand off to orchestrator if requested

### Internal normalized document model

Each input should normalize into a common schema with fields such as:

* source\_name
* source\_type
* title
* url
* published\_at
* raw\_text
* normalized\_text
* tags
* iocs
* ttps
* fingerprint
* source\_trust

### User flexibility requirement

Organizations should be able to add sources by config and/or custom adapter class.

Example source config:

```yaml
sources:
  - name: vendor\_feed
    type: rss\_atom
    url: https://example.com/feed

  - name: attack\_taxii
    type: taxii
    base\_url: https://example-taxii/
    collection: enterprise-attack

  - name: local\_reports
    type: local\_file
    path: ./examples/sample\_inputs
```

\---

## 15\. Threat hunting design

Threat hunting was identified as a first-class capability.

The project should explicitly help answer:

> What should we investigate next?

### V1 hunting outputs

Support a structured hunt hypothesis with:

* id
* title
* hypothesis
* priority
* confidence
* evidence\_basis
* related\_techniques
* required\_telemetry
* hunt\_steps
* suggested\_queries
* detection\_opportunities
* analyst\_notes

### Hunt generator expectations

Given a report or suspicious behavior, the hunt system should generate:

* hypotheses
* telemetry requirements
* prioritized steps
* example queries or query patterns
* suggested detections if relevant

### Example hunt hypothesis

```yaml
title: Encoded PowerShell Hunt
hypothesis: Adversaries may use encoded PowerShell commands to evade simple command-line detections.
priority: high
required\_telemetry:
  - process\_creation
related\_techniques:
  - T1059.001
hunt\_steps:
  - action: Search for powershell.exe with -enc or EncodedCommand
  - action: Review parent-child process relationships
  - action: Correlate with outbound network activity
detection\_opportunities:
  - Detect encoded PowerShell
  - Alert on Office spawning PowerShell
```

### Example hunt templates to include

* encoded PowerShell
* suspicious rundll32
* rare outbound connections

\---

## 16\. Detection engineering design

Detection engineering was also identified as a first-class feature.

The project should explicitly help answer:

> What rule should we write and what telemetry do we need?

### V1 detection scope

Start with **Sigma only**.

Later extend to:

* YARA
* KQL
* SPL
* EQL

### Detection generation expectations

Given structured findings, the system should produce:

* Sigma rule draft
* assumptions
* required telemetry
* false positives
* blind spots
* ATT\&CK technique references
* reviewer notes

### Example Sigma rule template

```yaml
title: Suspicious PowerShell with Encoded Command
status: experimental
logsource:
  category: process\_creation
  product: windows
detection:
  selection\_img:
    Image|endswith: '\\powershell.exe'
  selection\_cli:
    CommandLine|contains:
      - '-enc'
      - 'EncodedCommand'
  condition: selection\_img and selection\_cli
falsepositives:
  - Administrative automation
level: high
tags:
  - attack.execution
  - attack.t1059.001
```

### Detection templates to include in repo

* suspicious\_powershell.yml
* rundll32\_temp.yml
* scheduled\_task\_persistence.yml

\---

## 17\. Coverage analysis design

Coverage analysis was identified as an important future-facing capability even in basic form for v1.

The project should help answer:

> Do we have detections for this technique, and do we have the telemetry to support them?

### V1 coverage analysis should provide

* technique coverage status
* mapped rules
* required data sources
* available data sources
* gaps
* recommendations

### Core coverage model

```text
Technique → Behavior → Detection Rule → Required Data Source → Required Fields → Coverage Status
```

### Example coverage record

```json
{
  "technique\_id": "T1059.001",
  "technique\_name": "PowerShell",
  "coverage\_status": "partial",
  "mapped\_rules": \["Suspicious Encoded PowerShell"],
  "required\_data\_sources": \["process\_creation"],
  "available\_data\_sources": \["process\_creation"],
  "gaps": \[
    {
      "gap\_type": "partial\_coverage",
      "description": "Coverage exists for encoded PowerShell but not download cradles"
    }
  ]
}
```

\---

## 18\. Safety scope

The project must be explicitly defensive.

### Allowed

* defensive research
* IOC extraction
* ATT\&CK mapping
* report summarization
* hunt hypothesis generation
* detection drafting
* timeline reconstruction
* log explanation
* coverage analysis
* lab-only planning at most

### Disallowed

* offensive targeting
* autonomous exploitation
* credential theft support
* malware deployment
* abuse-oriented persistence/evasion content
* unauthorized attack execution

### Default mode

Read-only, draft-only, analysis-oriented.

\---

## 19\. Organizational adoption strategy

A major clarified goal was:

> Any organization should be able to easily adapt and start using this.

This means design should optimize for:

* easy adoption
* progressive enhancement
* minimal infra requirements
* optional integrations
* strong defaults
* safe outputs

### Three deployment tiers

#### Tier 1: Starter mode

* local CLI
* local file + RSS/TAXII/HTML ingestion
* SQLite
* one model provider
* no graph DB
* no CTI platform required

#### Tier 2: Team mode

* shared deployment
* Docker
* audit traces
* policies
* source trust controls
* optional CTI platform adapters

#### Tier 3: Intelligence platform mode

* optional Synapse backend
* optional Neo4j backend
* optional retrieval layers
* optional graph memory

### Important requirement

The project must be **useful before advanced integrations exist**.

\---

## 20\. Future integrations

These should be modeled as **optional placeholders**, not required dependencies in v1.

### 20.1 Vertex Synapse

Clarified that “Synapse” refers to **The Vertex Project’s Synapse**, not Azure Synapse.

It should be treated as:

* future central intelligence memory backend
* relationship-heavy security knowledge store
* long-term investigation memory layer

Important naming rule:

* use **Storm-oriented** naming for Synapse placeholders, not Cypher

### 20.2 Neo4j

Treat Neo4j as:

* optional general-purpose graph backend
* Cypher-oriented querying layer
* easier generic graph option for some adopters

### 20.3 OpenCTI

Treat OpenCTI as:

* future CTI platform connector
* import/export/enrichment target
* structured intelligence integration

### 20.4 MISP

Treat MISP as:

* future indicator/event feed integration
* structured IOC storage and correlation source

### 20.5 Retrieval and graph

Create placeholders for:

* exact retrieval
* semantic retrieval
* graph retrieval
* hybrid retrieval
* graph ontology

### Important recommendation

Create placeholder packages now, but do not deeply implement them in v1.

\---

## 21\. Full recommended project skeleton

```text
security-agent-mcp/
├── README.md
├── LICENSE
├── CONTRIBUTING.md
├── CODE\_OF\_CONDUCT.md
├── SECURITY.md
├── CHANGELOG.md
├── .gitignore
├── .env.example
├── pyproject.toml
├── Makefile
│
├── docs/
│   ├── architecture.md
│   ├── roadmap.md
│   ├── safety-model.md
│   ├── tool-contracts.md
│   ├── agent-design.md
│   ├── ingestion.md
│   ├── memory-model.md
│   ├── storage.md
│   ├── evaluation.md
│   ├── detection-engineering.md
│   ├── threat-hunting.md
│   ├── coverage-analysis.md
│   ├── organization-adoption.md
│   ├── integration-opencti.md
│   ├── integration-misp.md
│   ├── integration-synapse.md
│   ├── integration-neo4j.md
│   ├── security-hardening.md
│   ├── governance.md
│   └── contribution-guide.md
│
├── deployment/
│   ├── docker/
│   │   ├── Dockerfile
│   │   └── docker-compose.yml
│   ├── kubernetes/
│   │   └── README.md
│   └── systemd/
│       └── README.md
│
├── src/
│   └── security\_agent\_mcp/
│       ├── \_\_init\_\_.py
│       ├── server.py
│       ├── cli.py
│       ├── config.py
│       ├── logging\_config.py
│       ├── constants.py
│       │
│       ├── schemas/
│       │   ├── \_\_init\_\_.py
│       │   ├── common.py
│       │   ├── ioc.py
│       │   ├── attack.py
│       │   ├── sigma.py
│       │   ├── intel.py
│       │   ├── timeline.py
│       │   ├── workflow.py
│       │   ├── memory.py
│       │   ├── ingestion.py
│       │   ├── review.py
│       │   ├── detection.py
│       │   ├── hunt.py
│       │   ├── coverage.py
│       │   ├── datasource.py
│       │   └── hypothesis.py
│       │
│       ├── tools/
│       │   ├── \_\_init\_\_.py
│       │   ├── extract\_iocs.py
│       │   ├── summarize\_threat\_report.py
│       │   ├── map\_attack.py
│       │   ├── generate\_sigma.py
│       │   ├── explain\_log.py
│       │   ├── reconstruct\_timeline.py
│       │   ├── generate\_hunt\_hypothesis.py
│       │   ├── generate\_detection\_ideas.py
│       │   ├── map\_data\_sources.py
│       │   ├── detection\_gap\_analysis.py
│       │   └── detection\_explainer.py
│       │
│       ├── resources/
│       │   ├── \_\_init\_\_.py
│       │   ├── mitre\_reference.py
│       │   ├── sigma\_style\_guide.py
│       │   ├── detection\_notes.py
│       │   ├── analyst\_playbooks.py
│       │   ├── source\_trust\_registry.py
│       │   ├── attack\_data\_sources.py
│       │   ├── hunt\_templates.py
│       │   └── coverage\_defaults.py
│       │
│       ├── prompts/
│       │   ├── threat\_research.md
│       │   ├── detection\_engineering.md
│       │   ├── reviewer.md
│       │   ├── timeline\_analysis.md
│       │   ├── source\_ingestion\_review.md
│       │   ├── hunt\_generation.md
│       │   ├── detection\_review.md
│       │   └── coverage\_review.md
│       │
│       ├── agents/
│       │   ├── \_\_init\_\_.py
│       │   ├── base.py
│       │   ├── research\_agent.py
│       │   ├── detection\_agent.py
│       │   └── reviewer\_agent.py
│       │
│       ├── orchestrator/
│       │   ├── \_\_init\_\_.py
│       │   ├── router.py
│       │   ├── workflow.py
│       │   ├── state.py
│       │   ├── policy.py
│       │   ├── formatter.py
│       │   ├── approvals.py
│       │   └── trace.py
│       │
│       ├── ingestion/
│       │   ├── \_\_init\_\_.py
│       │   ├── base.py
│       │   ├── manager.py
│       │   ├── registry.py
│       │   ├── normalizer.py
│       │   ├── deduper.py
│       │   ├── parser.py
│       │   └── adapters/
│       │       ├── \_\_init\_\_.py
│       │       ├── rss\_adapter.py
│       │       ├── taxii\_adapter.py
│       │       ├── html\_report\_adapter.py
│       │       ├── local\_file\_adapter.py
│       │       └── base\_http\_adapter.py
│       │
│       ├── memory/
│       │   ├── \_\_init\_\_.py
│       │   ├── session\_store.py
│       │   ├── artifact\_store.py
│       │   ├── retriever.py
│       │   ├── summarizer.py
│       │   └── policy.py
│       │
│       ├── storage/
│       │   ├── \_\_init\_\_.py
│       │   ├── sqlite.py
│       │   ├── models.py
│       │   ├── migrations.py
│       │   └── repositories/
│       │       ├── \_\_init\_\_.py
│       │       ├── documents.py
│       │       ├── artifacts.py
│       │       ├── sessions.py
│       │       ├── sources.py
│       │       ├── detections.py
│       │       ├── hunts.py
│       │       └── coverage.py
│       │
│       ├── detection/
│       │   ├── \_\_init\_\_.py
│       │   ├── rule\_generator.py
│       │   ├── rule\_validator.py
│       │   ├── rule\_optimizer.py
│       │   ├── detection\_formatter.py
│       │   ├── detection\_inventory.py
│       │   ├── logic\_analyzer.py
│       │   └── rule\_templates/
│       │       ├── \_\_init\_\_.py
│       │       ├── sigma/
│       │       │   ├── suspicious\_powershell.yml
│       │       │   ├── rundll32\_temp.yml
│       │       │   └── scheduled\_task\_persistence.yml
│       │       ├── yara/
│       │       │   └── README.md
│       │       ├── eql/
│       │       │   └── README.md
│       │       ├── kql/
│       │       │   └── README.md
│       │       └── spl/
│       │           └── README.md
│       │
│       ├── hunt/
│       │   ├── \_\_init\_\_.py
│       │   ├── hypothesis\_generator.py
│       │   ├── hunt\_planner.py
│       │   ├── telemetry\_mapper.py
│       │   ├── hunt\_formatter.py
│       │   ├── hunt\_prioritizer.py
│       │   └── templates/
│       │       ├── encoded\_powershell.yaml
│       │       ├── suspicious\_rundll32.yaml
│       │       └── rare\_outbound\_connections.yaml
│       │
│       ├── coverage/
│       │   ├── \_\_init\_\_.py
│       │   ├── attack\_coverage\_map.py
│       │   ├── gap\_analysis.py
│       │   ├── datasource\_mapper.py
│       │   ├── telemetry\_gaps.py
│       │   └── reporting.py
│       │
│       ├── providers/
│       │   ├── \_\_init\_\_.py
│       │   ├── base.py
│       │   ├── openai\_provider.py
│       │   └── mock\_provider.py
│       │
│       ├── clients/
│       │   ├── \_\_init\_\_.py
│       │   ├── llm\_client.py
│       │   └── mock\_llm\_client.py
│       │
│       ├── integrations/
│       │   ├── \_\_init\_\_.py
│       │   ├── synapse/
│       │   │   ├── \_\_init\_\_.py
│       │   │   ├── README.md
│       │   │   ├── client.py
│       │   │   ├── mapper.py
│       │   │   ├── storm\_queries.py
│       │   │   └── ingestion\_bridge.py
│       │   ├── neo4j/
│       │   │   ├── \_\_init\_\_.py
│       │   │   ├── README.md
│       │   │   ├── client.py
│       │   │   ├── schema.py
│       │   │   ├── queries.py
│       │   │   └── loaders.py
│       │   ├── opencti/
│       │   │   ├── \_\_init\_\_.py
│       │   │   ├── README.md
│       │   │   ├── client.py
│       │   │   ├── mapper.py
│       │   │   └── importer.py
│       │   ├── misp/
│       │   │   ├── \_\_init\_\_.py
│       │   │   ├── README.md
│       │   │   ├── client.py
│       │   │   ├── mapper.py
│       │   │   └── importer.py
│       │   └── attack/
│       │       ├── \_\_init\_\_.py
│       │       ├── stix\_mapper.py
│       │       └── sync.py
│       │
│       ├── retrieval/
│       │   ├── \_\_init\_\_.py
│       │   ├── exact.py
│       │   ├── semantic.py
│       │   ├── graph.py
│       │   ├── hybrid.py
│       │   └── ranking.py
│       │
│       ├── graph/
│       │   ├── \_\_init\_\_.py
│       │   ├── ontology.py
│       │   ├── entities.py
│       │   ├── relationships.py
│       │   └── serializers.py
│       │
│       ├── observability/
│       │   ├── \_\_init\_\_.py
│       │   ├── metrics.py
│       │   ├── tracing.py
│       │   └── audit.py
│       │
│       ├── tenancy/
│       │   ├── \_\_init\_\_.py
│       │   ├── workspace.py
│       │   └── isolation.py
│       │
│       ├── policy/
│       │   ├── source\_trust.py
│       │   ├── data\_retention.py
│       │   ├── redaction.py
│       │   └── reviewer\_thresholds.py
│       │
│       └── utils/
│           ├── \_\_init\_\_.py
│           ├── text.py
│           ├── yaml\_utils.py
│           ├── validation.py
│           ├── time\_utils.py
│           ├── ids.py
│           ├── hashing.py
│           └── files.py
│
├── configs/
│   ├── sources.example.yaml
│   ├── app.example.yaml
│   ├── prompts.example.yaml
│   ├── memory.example.yaml
│   ├── policies.example.yaml
│   ├── hunts.example.yaml
│   └── detections.example.yaml
│
├── data/
│   ├── .gitkeep
│   ├── artifacts/
│   ├── cache/
│   └── db/
│
├── examples/
│   ├── sample\_inputs/
│   │   ├── phishing\_report.txt
│   │   ├── suspicious\_command.txt
│   │   ├── timeline\_notes.txt
│   │   └── hunt\_request.txt
│   ├── expected\_outputs/
│   │   ├── phishing\_report\_output.json
│   │   ├── sigma\_rule.yml
│   │   ├── hunt\_hypothesis.json
│   │   └── coverage\_report.json
│   ├── run\_local\_workflow.py
│   ├── run\_ingestion\_demo.py
│   ├── run\_compare\_reports.py
│   ├── run\_hunt\_generation.py
│   └── example\_client\_openai.py
│
├── tests/
│   ├── conftest.py
│   ├── test\_server.py
│   ├── test\_tools.py
│   ├── test\_agents.py
│   ├── test\_orchestrator.py
│   ├── test\_ingestion.py
│   ├── test\_memory.py
│   ├── test\_storage.py
│   ├── test\_policies.py
│   ├── test\_detection.py
│   ├── test\_hunt.py
│   ├── test\_coverage.py
│   └── fixtures/
│       ├── phishing\_report.txt
│       ├── powershell\_case.txt
│       ├── html\_report\_sample.html
│       ├── rss\_feed\_sample.xml
│       ├── taxii\_sample.json
│       ├── hunt\_case.json
│       └── detection\_inventory.json
│
├── evals/
│   ├── benchmark\_cases.json
│   ├── score.py
│   ├── run\_evals.py
│   ├── rubrics/
│   │   ├── ioc\_extraction.json
│   │   ├── attack\_mapping.json
│   │   ├── sigma\_generation.json
│   │   ├── hunt\_generation.json
│   │   └── coverage\_analysis.json
│   └── expected/
│       ├── ioc\_extraction.json
│       ├── attack\_mapping.json
│       ├── sigma\_generation.yml
│       ├── hunt\_generation.json
│       └── coverage\_analysis.json
│
├── scripts/
│   ├── dev.sh
│   ├── lint.sh
│   ├── test.sh
│   ├── run\_server.sh
│   ├── init\_db.sh
│   └── seed\_examples.sh
│
└── .github/
    ├── ISSUE\_TEMPLATE/
    │   ├── bug\_report.md
    │   ├── feature\_request.md
    │   ├── new-source-adapter.md
    │   ├── new-tool.md
    │   ├── new-hunt-template.md
    │   └── new-detection-template.md
    ├── PULL\_REQUEST\_TEMPLATE.md
    └── workflows/
        ├── ci.yml
        ├── lint.yml
        └── tests.yml
```

\---

## 22\. Core schemas to implement first

### 22.1 Detection schema

```python
from pydantic import BaseModel, Field
from typing import List, Optional

class DetectionDataSource(BaseModel):
    name: str
    category: str
    fields\_required: List\[str] = Field(default\_factory=list)

class DetectionRule(BaseModel):
    id: str
    title: str
    rule\_type: str  # sigma, yara, kql, eql, spl
    description: Optional\[str] = None
    technique\_ids: List\[str] = Field(default\_factory=list)
    tactics: List\[str] = Field(default\_factory=list)
    severity: str = "medium"
    status: str = "draft"
    logic: str
    assumptions: List\[str] = Field(default\_factory=list)
    false\_positives: List\[str] = Field(default\_factory=list)
    blind\_spots: List\[str] = Field(default\_factory=list)
    data\_sources: List\[DetectionDataSource] = Field(default\_factory=list)
    reviewer\_notes: List\[str] = Field(default\_factory=list)
```

### 22.2 Hunt schema

```python
from pydantic import BaseModel, Field
from typing import List, Optional

class HuntStep(BaseModel):
    step\_number: int
    action: str
    reason: Optional\[str] = None

class HuntHypothesis(BaseModel):
    id: str
    title: str
    hypothesis: str
    priority: str = "medium"
    confidence: str = "medium"
    evidence\_basis: List\[str] = Field(default\_factory=list)
    related\_techniques: List\[str] = Field(default\_factory=list)
    required\_telemetry: List\[str] = Field(default\_factory=list)
    hunt\_steps: List\[HuntStep] = Field(default\_factory=list)
    suggested\_queries: List\[str] = Field(default\_factory=list)
    detection\_opportunities: List\[str] = Field(default\_factory=list)
    analyst\_notes: List\[str] = Field(default\_factory=list)
```

### 22.3 Coverage schema

```python
from pydantic import BaseModel, Field
from typing import List

class CoverageGap(BaseModel):
    technique\_id: str
    gap\_type: str  # no\_detection, weak\_detection, no\_telemetry, partial\_coverage
    description: str
    recommended\_actions: List\[str] = Field(default\_factory=list)

class DetectionCoverageRecord(BaseModel):
    technique\_id: str
    technique\_name: str
    coverage\_status: str  # full, partial, none
    mapped\_rules: List\[str] = Field(default\_factory=list)
    required\_data\_sources: List\[str] = Field(default\_factory=list)
    available\_data\_sources: List\[str] = Field(default\_factory=list)
    gaps: List\[CoverageGap] = Field(default\_factory=list)
```

\---

## 23\. Example mock workflows discussed

### 23.1 Threat report to detection

Input:

“Researchers observed a phishing campaign delivering a ZIP archive containing a JavaScript file. When executed, the script launched PowerShell with an encoded command to download a second-stage payload from update-microsoft-login\[.]com. The payload established persistence through a scheduled task and beaconed to 185.224.128\[.]51.”

Expected processing:

* Research Agent extracts IOCs and TTPs
* Detection Agent drafts Sigma and hunt ideas
* Reviewer Agent validates

Expected output includes:

* summary
* domain: update-microsoft-login.com
* IP: 185.224.128.51
* ATT\&CK candidates such as:

  * T1566.001
  * T1059.007
  * T1059.001
  * T1105
  * T1053.005
  * lower-confidence C2 mapping if applicable
* Sigma draft
* hunt opportunities
* reviewer notes

### 23.2 SOC triage example

Input:

“WINWORD.EXE spawned powershell.exe which connected to 203.0.113.77 over port 443.”

Expected output:

* suspicious parent-child relationship explanation
* why it matters
* next investigation steps
* likely ATT\&CK mappings
* telemetry to review
* hunt or detection suggestions

### 23.3 Timeline reconstruction example

Input:

* 10:14 user opened invoice.docm
* 10:15 WINWORD spawned powershell
* 10:16 powershell reached 198.51.100.25
* 10:18 schtasks created updater task
* 10:22 user reported machine slow

Expected output:

* ordered timeline
* likely malicious assessment
* persistence note

\---

## 24\. Implementation roadmap

### Phase 0 — Scope lock

V1 promise should be:

> Given a threat report or suspicious artifact, produce structured findings, ATT\&CK mapping, hunt hypotheses, and a draft Sigma rule.

### Phase 1 — Repo foundation

Create:

* README
* LICENSE
* CONTRIBUTING
* SECURITY
* pyproject.toml
* Makefile
* basic package structure

### Phase 2 — Schemas and tools

Implement:

* IOC schema
* ATT\&CK schema
* Sigma schema
* detection / hunt / coverage schemas
* extract\_iocs
* summarize\_threat\_report
* map\_attack
* generate\_sigma
* generate\_hunt\_hypothesis

### Phase 3 — MCP server and CLI

Implement:

* server.py
* tool registration
* CLI entrypoint
* basic examples

### Phase 4 — Agents and orchestrator

Implement:

* Research Agent
* Detection Agent
* Reviewer Agent
* state.py
* router.py
* workflow.py
* trace.py
* formatter.py

### Phase 5 — Ingestion

Implement:

* local\_file adapter
* RSS adapter
* TAXII adapter
* HTML adapter
* normalizer
* deduper

### Phase 6 — Memory and storage

Implement:

* SQLite layer
* artifact store
* session store
* retriever
* persistence repositories

### Phase 7 — Hunt and coverage

Implement:

* map\_data\_sources
* detection\_gap\_analysis
* coverage modules
* hunt planner
* telemetry mapping

### Phase 8 — Tests and evals

Implement:

* fixtures
* tool tests
* agent tests
* workflow tests
* hunt tests
* coverage tests
* benchmark cases

### Phase 9 — Adoption polish

Implement:

* Docker support
* local quickstart
* org adoption docs
* security hardening docs
* contribution guide

### Phase 10 — Future placeholders

Create but do not deeply implement:

* OpenCTI
* MISP
* Vertex Synapse
* Neo4j
* retrieval
* graph

\---

## 25\. First-wave implementation order

Build in this order:

1. `README.md`
2. `pyproject.toml`
3. package skeleton
4. schemas:

   * `ioc.py`
   * `attack.py`
   * `sigma.py`
   * `workflow.py`
   * `detection.py`
   * `hunt.py`
   * `coverage.py`
5. tools:

   * `extract\_iocs.py`
   * `summarize\_threat\_report.py`
   * `map\_attack.py`
   * `generate\_sigma.py`
   * `generate\_hunt\_hypothesis.py`
6. `server.py`
7. `cli.py`
8. basic agent stubs
9. basic orchestrator state/router/workflow
10. local file adapter
11. RSS adapter
12. SQLite stub
13. example fixtures
14. basic tests

\---

## 26\. Second-wave implementation order

Then build:

* HTML report adapter
* TAXII adapter
* explain\_log
* reconstruct\_timeline
* generate\_detection\_ideas
* map\_data\_sources
* detection\_gap\_analysis
* artifact store
* session store
* retriever
* approvals
* trace
* docs
* Docker
* evals

\---

## 27\. Placeholder-only areas for now

Create light stubs and README files only for:

* `integrations/opencti/`
* `integrations/misp/`
* `integrations/synapse/`
* `integrations/neo4j/`
* `retrieval/`
* `graph/`

Do not deeply implement them in the first iteration.

\---

## 28\. Coding standards and implementation expectations

Use:

* Python
* type hints
* Pydantic models
* pytest
* modular clean structure
* readable code
* strong comments/docstrings where useful
* safe defaults
* separation of concerns

Avoid:

* overengineering
* tight provider coupling
* giant shared files
* hidden side effects
* mandatory cloud services

\---

## 29\. Contribution model

The repo should be open to contributions, but the maintainer remains the central reviewer and merger.

Encourage PRs for:

* new source adapters
* new Sigma templates
* new hunt templates
* tests
* fixtures
* docs
* eval cases

Document that:

* major architecture changes require review
* offensive capability requests are out of scope
* safety and defensive alignment are mandatory

\---

## 30\. Final build intent

The repository should feel like:

> a modular, extensible, organization-friendly defensive security intelligence platform with MCP-native tooling, small-agent orchestration, pluggable threat-intel ingestion, structured hunt and detection outputs, and room for future CTI and graph-backed intelligence memory.

It should be:

* practical on day one
* easy to run locally
* easy for organizations to try
* easy to extend
* promising long term

