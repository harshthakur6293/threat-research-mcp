"""Helpers for MCP/CLI ingestion from YAML or JSON source configs."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import List, Tuple

from threat_research_mcp.ingestion import IngestionManager
from threat_research_mcp.ingestion.errors import IngestionError
from threat_research_mcp.ingestion.manager import load_sources_json, load_sources_yaml
from threat_research_mcp.schemas.intel_document import NormalizedDocument


def _maybe_persist_ingested_documents(documents: List[NormalizedDocument]) -> None:
    db_path = os.environ.get("THREAT_RESEARCH_MCP_DB", "").strip()
    if not db_path or not documents:
        return
    from threat_research_mcp.storage.sqlite import save_normalized_documents

    save_normalized_documents(db_path, documents)


def ingest_from_config_path(config_path: str) -> List[NormalizedDocument]:
    """Load sources from a .yaml / .yml / .json file and run ingestion."""
    p = Path(config_path).expanduser()
    if not p.is_file():
        raise IngestionError(f"Config is not a file: {p}")
    suffix = p.suffix.lower()
    if suffix in (".yaml", ".yml"):
        sources = load_sources_yaml(p)
    elif suffix == ".json":
        sources = load_sources_json(p)
    else:
        raise IngestionError("Config file must end with .yaml, .yml, or .json")
    return IngestionManager(sources).run()


def ingest_from_config_path_json(config_path: str) -> str:
    """Return JSON string: { count, documents: [...] }."""
    try:
        docs = ingest_from_config_path(config_path)
    except IngestionError as e:
        return json.dumps({"error": str(e), "count": 0, "documents": []}, indent=2)
    payload = {
        "count": len(docs),
        "documents": [d.model_dump(mode="json") for d in docs],
    }
    _maybe_persist_ingested_documents(docs)
    return json.dumps(payload, indent=2)


def combine_intel_for_workflow(
    *,
    text: str = "",
    sources_config_path: str = "",
    max_total_chars: int = 120_000,
) -> Tuple[str, List[NormalizedDocument]]:
    """Merge optional analyst text with normalized bodies from ingestion."""
    parts: List[str] = []
    docs: List[NormalizedDocument] = []
    if sources_config_path.strip():
        docs = ingest_from_config_path(sources_config_path.strip())
        bodies: List[str] = []
        for d in docs:
            chunk = (d.normalized_text or "").strip()
            if chunk:
                bodies.append(f"## {d.source_name}: {d.title}\n{chunk}")
        if bodies:
            parts.append("\n\n---\n\n".join(bodies))
    t = (text or "").strip()
    if t:
        parts.insert(0, t)
    combined = "\n\n".join(parts).strip()
    if len(combined) > max_total_chars:
        combined = combined[:max_total_chars] + "\n\n[truncated for workflow size limit]"
    return combined, docs


def intel_to_analysis_product_json(
    text: str = "",
    sources_config_path: str = "",
    workflow: str = "threat_research",
) -> str:
    """Ingest optional sources, merge with text, run workflow, return AnalysisProduct JSON."""
    from threat_research_mcp.orchestrator.workflow import run_workflow

    combined, docs = combine_intel_for_workflow(
        text=text,
        sources_config_path=sources_config_path,
    )
    if not combined.strip():
        return json.dumps(
            {
                "schema_version": "1.0",
                "error": "no_intel",
                "hint": "Provide non-empty text and/or a sources YAML/JSON path that yields documents.",
            },
            indent=2,
        )

    payload = json.loads(run_workflow(workflow, combined, provenance_documents=docs))
    ap = payload.get("analysis_product")
    if ap is None:
        return json.dumps(
            {
                "schema_version": "1.0",
                "error": "workflow_blocked_or_missing_product",
                "workflow": payload,
            },
            indent=2,
        )
    _maybe_persist_ingested_documents(docs)
    return json.dumps(ap, indent=2)
