"""Normalize RawDocument + source metadata into NormalizedDocument."""

from __future__ import annotations

import re
from typing import List

from threat_research_mcp.schemas.intel_document import NormalizedDocument, RawDocument, SourceConfig
from threat_research_mcp.utils.hashing import sha256_hex


def collapse_whitespace(text: str) -> str:
    return re.sub(r"\s+", " ", text or "").strip()


def normalize_text(text: str) -> str:
    return collapse_whitespace(text)


def compute_fingerprint(source_name: str, title: str, normalized_body: str) -> str:
    basis = f"{source_name}\n{title}\n{normalized_body[:8000]}"
    return sha256_hex(basis)


def to_normalized(raw: RawDocument, cfg: SourceConfig) -> NormalizedDocument:
    combined = raw.body if not raw.title else f"{raw.title}\n\n{raw.body}"
    norm = normalize_text(combined)
    fp = compute_fingerprint(cfg.name, raw.title or "(no title)", norm)
    tags = list(dict.fromkeys(raw.tags))  # dedupe preserve order
    return NormalizedDocument(
        source_name=cfg.name,
        source_type=cfg.type,
        title=raw.title or "(no title)",
        url=raw.url,
        published_at=raw.published_at,
        raw_text=combined,
        normalized_text=norm,
        tags=tags,
        fingerprint=fp,
        source_trust=cfg.source_trust,
    )


def normalize_batch(raw_docs: List[RawDocument], cfg: SourceConfig) -> List[NormalizedDocument]:
    return [to_normalized(r, cfg) for r in raw_docs]
