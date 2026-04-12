"""Fingerprint-based deduplication for ingested documents."""

from __future__ import annotations

from typing import Iterable, List, Optional, Set

from threat_research_mcp.schemas.intel_document import NormalizedDocument


class Deduper:
    """Tracks seen fingerprints across a manager run or process lifetime."""

    def __init__(self, initial: Optional[Iterable[str]] = None) -> None:
        self._seen: Set[str] = set(initial or ())

    def reset(self) -> None:
        self._seen.clear()

    def filter_new(self, docs: List[NormalizedDocument]) -> List[NormalizedDocument]:
        out: List[NormalizedDocument] = []
        for d in docs:
            if d.fingerprint in self._seen:
                continue
            self._seen.add(d.fingerprint)
            out.append(d)
        return out

    def remember(self, fingerprint: str) -> None:
        self._seen.add(fingerprint)
