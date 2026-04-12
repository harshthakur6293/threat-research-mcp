"""Map source `type` strings to adapter implementations."""

from __future__ import annotations

from typing import Dict, List

from threat_research_mcp.ingestion.adapters.html_report_adapter import HtmlReportAdapter
from threat_research_mcp.ingestion.adapters.local_file_adapter import (
    LocalFileAdapter,
    StixBundleAdapter,
)
from threat_research_mcp.ingestion.adapters.rss_adapter import RssAdapter, RssAtomAdapter
from threat_research_mcp.ingestion.adapters.taxii_adapter import Taxii2Adapter, TaxiiAdapter
from threat_research_mcp.ingestion.base import IntelAdapter
from threat_research_mcp.ingestion.errors import IngestionError

_ADAPTERS: Dict[str, IntelAdapter] = {
    "local_file": LocalFileAdapter(),
    "rss": RssAdapter(),
    "rss_atom": RssAtomAdapter(),
    "html_report": HtmlReportAdapter(),
    "html": HtmlReportAdapter(),
    "taxii": TaxiiAdapter(),
    "taxii2": Taxii2Adapter(),
    "stix_bundle": StixBundleAdapter(),
    "stix": StixBundleAdapter(),
}


def register_adapter(type_name: str, adapter: IntelAdapter) -> None:
    """Register or override an adapter for a source type string."""
    _ADAPTERS[type_name.lower()] = adapter


def list_adapter_types() -> List[str]:
    return sorted(_ADAPTERS.keys())


def get_adapter(type_name: str) -> IntelAdapter:
    key = (type_name or "").strip().lower()
    adapter = _ADAPTERS.get(key)
    if adapter is None:
        known = ", ".join(list_adapter_types())
        raise IngestionError(f"Unknown source type '{type_name}'. Supported: {known}")
    return adapter
