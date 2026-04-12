"""Merge normalized document metadata into AnalysisProduct dict (shared by workflow + ingestion)."""

from __future__ import annotations

from typing import List

from threat_research_mcp.schemas.intel_document import NormalizedDocument


def merge_ingestion_provenance(
    analysis_product: dict,
    documents: List[NormalizedDocument],
    *,
    max_entries: int = 50,
) -> dict:
    """Append document-level provenance rows to analysis_product."""
    out = dict(analysis_product)
    prov = list(out.get("provenance") or [])
    for d in documents[:max_entries]:
        prov.append(
            {
                "source_name": d.source_name,
                "source_type": d.source_type,
                "document_fingerprint": d.fingerprint,
                "document_title": d.title,
                "ingested_at": d.published_at,
            }
        )
    out["provenance"] = prov
    return out
