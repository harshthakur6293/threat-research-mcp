"""Adapter base types for threat intel ingestion."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List

from threat_research_mcp.schemas.intel_document import RawDocument, SourceConfig


class IntelAdapter(ABC):
    """Fetches raw documents for a single source type."""

    @property
    @abstractmethod
    def source_type(self) -> str:
        ...

    @abstractmethod
    def collect_raw(self, cfg: SourceConfig) -> List[RawDocument]:
        ...
