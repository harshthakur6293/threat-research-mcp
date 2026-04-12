from __future__ import annotations

import argparse
import json

from threat_research_mcp.orchestrator.workflow import run_workflow
from threat_research_mcp.tools.ingest_tools import combine_intel_for_workflow


def main() -> None:
    parser = argparse.ArgumentParser(prog="threat-research-mcp")
    parser.add_argument("--workflow", default="threat_research")
    parser.add_argument("--text", default="")
    parser.add_argument(
        "--sources",
        default="",
        metavar="PATH",
        help="Optional YAML/JSON sources config (see configs/sources.example.yaml); merged with --text for workflow.",
    )
    args = parser.parse_args()

    if args.sources.strip():
        combined, docs = combine_intel_for_workflow(
            text=args.text,
            sources_config_path=args.sources.strip(),
        )
        payload = json.loads(
            run_workflow(args.workflow, combined, provenance_documents=docs)
        )
        print(json.dumps(payload, indent=2))
    else:
        print(run_workflow(args.workflow, args.text))
