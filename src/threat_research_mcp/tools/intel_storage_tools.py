"""MCP-facing JSON helpers for querying THREAT_RESEARCH_MCP_DB intel tables."""

from __future__ import annotations

import json
import os
from typing import Optional, Tuple

from threat_research_mcp.storage.sqlite import (
    get_analysis_product_by_row_id,
    search_analysis_products,
    search_normalized_documents,
)


def _db_path_or_error() -> Tuple[str, Optional[str]]:
    p = os.environ.get("THREAT_RESEARCH_MCP_DB", "").strip()
    if not p:
        return "", "THREAT_RESEARCH_MCP_DB is not set"
    return p, None


def search_ingested_intel_json(
    text_query: str = "",
    source_name: str = "",
    fingerprint: str = "",
    limit: int = 30,
    offset: int = 0,
) -> str:
    """Search append-only `normalized_documents` (requires THREAT_RESEARCH_MCP_DB)."""
    db, err = _db_path_or_error()
    if err:
        return json.dumps({"error": err, "count": 0, "documents": []}, indent=2)
    rows = search_normalized_documents(
        db,
        text_query=text_query,
        source_name=source_name,
        fingerprint=fingerprint,
        limit=limit,
        offset=offset,
    )
    return json.dumps({"count": len(rows), "documents": rows}, indent=2)


def search_analysis_product_history_json(
    text_query: str = "",
    workflow: str = "",
    limit: int = 30,
    offset: int = 0,
) -> str:
    """Search stored analysis products by narrative or JSON substring."""
    db, err = _db_path_or_error()
    if err:
        return json.dumps({"error": err, "count": 0, "products": []}, indent=2)
    rows = search_analysis_products(
        db,
        text_query=text_query,
        workflow_type=workflow,
        limit=limit,
        offset=offset,
    )
    return json.dumps({"count": len(rows), "products": rows}, indent=2)


def get_stored_analysis_product_json(row_id: int) -> str:
    """Return full AnalysisProduct JSON for `row_id` from search results."""
    db, err = _db_path_or_error()
    if err:
        return json.dumps({"error": err}, indent=2)
    data = get_analysis_product_by_row_id(db, row_id)
    if data is None:
        return json.dumps({"error": "not_found", "row_id": row_id}, indent=2)
    return json.dumps(data, indent=2)
