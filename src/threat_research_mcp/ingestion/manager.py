"""Orchestrate ingestion: fetch → normalize → optional dedupe."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from threat_research_mcp.ingestion.deduper import Deduper
from threat_research_mcp.ingestion.errors import IngestionError
from threat_research_mcp.ingestion.normalizer import normalize_batch
from threat_research_mcp.ingestion.registry import get_adapter
from threat_research_mcp.schemas.intel_document import NormalizedDocument, SourceConfig

logger = logging.getLogger(__name__)


@dataclass
class SourceResult:
    """Outcome for a single source after a run."""

    name: str
    status: str  # "ok" | "error"
    count: int = 0
    error: str = ""


@dataclass
class RunResult:
    """Aggregate outcome of IngestionManager.run()."""

    documents: List[NormalizedDocument] = field(default_factory=list)
    source_results: List[SourceResult] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.documents)

    @property
    def errors(self) -> List[str]:
        return [r.error for r in self.source_results if r.status == "error"]

    def to_dict(self) -> dict:
        return {
            "count": self.count,
            "source_results": [
                {
                    "name": r.name,
                    "status": r.status,
                    "count": r.count,
                    **({"error": r.error} if r.error else {}),
                }
                for r in self.source_results
            ],
            "errors": self.errors,
        }


class IngestionManager:
    """Run all configured sources through adapters, normalizer, and deduper.

    One failing source does NOT abort the run — partial results are returned
    and the failure is recorded in RunResult.source_results.
    """

    def __init__(
        self,
        sources: List[SourceConfig],
        deduper: Optional[Deduper] = None,
    ) -> None:
        self.sources = sources
        self.deduper = deduper or Deduper()

    def run(self, skip_duplicates: bool = True) -> RunResult:
        result = RunResult()
        for cfg in self.sources:
            try:
                adapter = get_adapter(cfg.type)
                raw_docs = adapter.collect_raw(cfg)
                batch = normalize_batch(raw_docs, cfg)
                result.documents.extend(batch)
                result.source_results.append(
                    SourceResult(name=cfg.name, status="ok", count=len(batch))
                )
            except Exception as exc:
                msg = str(exc)
                logger.warning("Ingestion source %r failed: %s", cfg.name, msg)
                result.source_results.append(SourceResult(name=cfg.name, status="error", error=msg))

        if skip_duplicates:
            result.documents = self.deduper.filter_new(result.documents)
        return result

    def run_source(self, name: str, skip_duplicates: bool = True) -> RunResult:
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
