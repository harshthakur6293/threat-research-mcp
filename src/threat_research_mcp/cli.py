from __future__ import annotations

import argparse
from threat_research_mcp.orchestrator.workflow import run_workflow


def main() -> None:
    parser = argparse.ArgumentParser(prog="threat-research-mcp")
    parser.add_argument("--workflow", default="threat_research")
    parser.add_argument("--text", default="")
    args = parser.parse_args()
    print(run_workflow(args.workflow, args.text))
