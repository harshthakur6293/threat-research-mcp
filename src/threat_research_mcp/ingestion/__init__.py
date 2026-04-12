"""Threat intel ingestion: local files, RSS/Atom, HTML, STIX bundles, TAXII 2.1."""

from threat_research_mcp.ingestion.errors import IngestionError
from threat_research_mcp.ingestion.manager import (
    IngestionManager,
    load_sources_json,
    load_sources_yaml,
    sources_from_dict,
)
from threat_research_mcp.ingestion.registry import get_adapter, list_adapter_types, register_adapter

__all__ = [
    "IngestionError",
    "IngestionManager",
    "get_adapter",
    "list_adapter_types",
    "load_sources_json",
    "load_sources_yaml",
    "register_adapter",
    "sources_from_dict",
]
