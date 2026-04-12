# Quickstart (Local)

## 1) Install
`ash
python -m pip install -e .[dev]
`

## 2) Run tests
`ash
pytest -q
`

## 3) Run a workflow
`ash
python -m threat_research_mcp --workflow threat_research --text  Phishing with encoded PowerShell
`

## 4) Run MCP server
`ash
python -m threat_research_mcp.server
`
