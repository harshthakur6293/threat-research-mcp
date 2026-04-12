# Agent Design

Current role-oriented agents:
- **research_agent**: summarize intel + extract key findings
- **hunting_agent**: generate hunt hypotheses
- **detection_agent**: produce detection ideas/Sigma draft
- **reviewer_agent**: quality/safety pass over outputs

All agents share orchestrator state, and are intended to stay deterministic where possible.
