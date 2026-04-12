"""Orchestrate ingestion: fetch → normalize → optional dedupe."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from threat_research_mcp.ingestion.deduper import Deduper
from threat_research_mcp.ingestion.errors import IngestionError
from threat_research_mcp.ingestion.normalizer import normalize_batch
from threat_research_mcp.ingestion.registry import get_adapter
from threat_research_mcp.schemas.intel_document import NormalizedDocument, SourceConfig


class IngestionManager:
    """Run all configured sources through adapters, normalizer, and deduper."""

    def __init__(
        self,
        sources: List[SourceConfig],
        deduper: Optional[Deduper] = None,
    ) -> None:
        self.sources = sources
        self.deduper = deduper or Deduper()

    def run(self, skip_duplicates: bool = True) -> List[NormalizedDocument]:
        normalized: List[NormalizedDocument] = []
        for cfg in self.sources:
            adapter = get_adapter(cfg.type)
            raw_docs = adapter.collect_raw(cfg)
            normalized.extend(normalize_batch(raw_docs, cfg))
        if skip_duplicates:
            return self.deduper.filter_new(normalized)
        return normalized

    def run_source(self, name: str, skip_duplicates: bool = True) -> List[NormalizedDocument]:
        matches = [s for s in self.sources if s.name == name]
        if not matches:
            raise IngestionError(f"No source named '{name}'")
        sub = IngestionManager(matches, self.deduper)
        return sub.run(skip_duplicates=skip_duplicates)


def sources_from_dict(data: Union[Dict[str, Any], List[Any]]) -> List[SourceConfig]:
    """Build SourceConfig list from `{"sources": [...]}` or a bare list."""
    if isinstance(data, dict):
        items = data.get("sources")
        if not isinstance(items, list):
            raise IngestionError("Dict config must contain a 'sources' list")
    elif isinstance(data, list):
        items = data
    else:
        raise IngestionError("Config must be a dict or list")

    out: List[SourceConfig] = []
    for i, row in enumerate(items):
        if not isinstance(row, dict):
            raise IngestionError(f"sources[{i}] must be an object/dict")
        out.append(SourceConfig(**row))
    return out


def load_sources_yaml(path: Union[str, Path]) -> List[SourceConfig]:
    """Load sources from a YAML file (requires PyYAML)."""
    try:
        import yaml
    except ImportError as e:
        raise IngestionError(
            "PyYAML is required for YAML configs. Install with: pip install pyyaml"
        ) from e

    p = Path(path)
    text = p.read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    if data is None:
        return []
    return sources_from_dict(data)


def load_sources_json(path: Union[str, Path]) -> List[SourceConfig]:
    import json

    p = Path(path)
    data = json.loads(p.read_text(encoding="utf-8"))
    return sources_from_dict(data)
