from __future__ import annotations

import os
from typing import List, Optional

from threat_research_mcp.agents.research_agent import run_research
from threat_research_mcp.agents.hunting_agent import run_hunting
from threat_research_mcp.agents.detection_agent import run_detection
from threat_research_mcp.agents.reviewer_agent import run_review
from threat_research_mcp.orchestrator.router import route_workflow
from threat_research_mcp.orchestrator.policy import defensive_policy_ok
from threat_research_mcp.orchestrator.formatter import format_output
from threat_research_mcp.orchestrator.state import init_state
from threat_research_mcp.orchestrator.analysis_product_builder import build_analysis_product
from threat_research_mcp.orchestrator.provenance_merge import merge_ingestion_provenance
from threat_research_mcp.schemas.intel_document import NormalizedDocument


def _persist_workflow_output(output: dict, input_text: str) -> None:
    db_path = os.environ.get("THREAT_RESEARCH_MCP_DB", "").strip()
    if not db_path:
        return
    from threat_research_mcp.storage.sqlite import save_analysis_product, save_workflow_run

    save_workflow_run(
        db_path,
        run_id=output["request_id"],
        workflow_type=str(output["workflow"]),
        input_text=input_text,
        output_payload=output,
    )
    ap = output.get("analysis_product")
    if isinstance(ap, dict) and str(ap.get("product_id") or "").strip():
        save_analysis_product(
            db_path,
            workflow_type=str(output.get("workflow") or ""),
            product=ap,
        )


def run_workflow(
    workflow: str,
    text: str,
    provenance_documents: Optional[List[NormalizedDocument]] = None,
) -> str:
    routed = route_workflow(workflow)
    state = init_state(routed, text)

    if not defensive_policy_ok(text):
        return format_output(
            {
                "request_id": state.request_id,
                "status": "blocked",
                "reason": "defensive policy violation",
                "workflow": routed,
            }
        )

    state.research = run_research(text)
    state.hunting = (
        run_hunting(text)
        if routed in {"hunt_generation", "timeline_reconstruction", "log_explanation", "coverage_analysis"}
        else {}
    )
    state.detection = (
        run_detection(text, state.research)
        if routed in {"threat_research", "detection_generation", "coverage_analysis"}
        else {}
    )
    state.review = run_review(state.research, state.hunting, state.detection)

    output = state.to_output_dict()
    product = build_analysis_product(
        workflow=routed,
        input_text=text,
        research=state.research,
        hunting=state.hunting,
        detection=state.detection,
        review=state.review,
        request_id=state.request_id,
    )
    ap_dump = product.model_dump(mode="json")
    if provenance_documents:
        ap_dump = merge_ingestion_provenance(ap_dump, provenance_documents)
    output["analysis_product"] = ap_dump
    _persist_workflow_output(output, text)
    return format_output(output)
