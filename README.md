# Threat Research MCP

Threat Research MCP is an open-source MCP server and orchestration framework for defensive security research, threat hunting, and detection engineering.

## Workspace location

This project is now scaffolded as a clean standalone workspace at:

`c:/Dev/Vibe Coding/threat-research-mcp`

If VS Code is still showing files from `sentinel-forge`, open this folder directly as your main workspace.

## Core capabilities

- IOC extraction from unstructured text
- Threat report summarization and ATT&CK keyword mapping
- Hunt hypothesis generation
- Sigma detection draft generation
- Timeline reconstruction and log explanation
- Coverage gap analysis primitives

## Safety scope

This project is defensive-only and intended for authorized environments.

## Quickstart

```bash
python -m pip install -e .[dev]
python -m threat_research_mcp --workflow threat_research --text "Phishing campaign using encoded PowerShell"
pytest -q
```

## How a user can use this (mock)

### Example 1: Threat report analysis

Command:

```bash
python -m threat_research_mcp --workflow threat_research --text "Phishing email delivered a zip with JavaScript. Script launched PowerShell encoded command and created a scheduled task."
```

Expected output shape:

```json
{
  "workflow": "threat_research",
  "research": {
    "summary": "Summary: ...",
    "iocs": {"ips": [], "domains": [], "urls": [], "hashes": [], "emails": []},
    "attack": "{\"techniques\": [...]}"
  },
  "hunting": {},
  "detection": {
    "sigma": "title: Generated Detection ...",
    "ideas": "{\"ideas\": [...]}"
  },
  "review": {
    "status": "pass",
    "notes": [],
    "confidence": "medium"
  }
}
```

### Example 2: Hunting workflow

Command:

```bash
python -m threat_research_mcp --workflow hunt_generation --text "WINWORD spawned powershell and host connected to rare external IP"
```

This returns a generated hunt hypothesis, timeline normalization, and reviewer output.

### Example 3: Use as an MCP server

Run:

```bash
python -m threat_research_mcp.server
```

Then connect an MCP-capable client and call tools such as:

- `extract_iocs`
- `summarize`
- `attack_map`
- `hunt`
- `sigma`
- `coverage`

## CI cache hygiene

This repository includes a dedicated cache hygiene workflow that can:

- list workflow caches
- purge caches manually (workflow_dispatch)

This keeps build caches healthy over time and avoids stale cache buildup.
