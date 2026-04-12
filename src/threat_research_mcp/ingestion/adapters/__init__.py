"""Ingestion adapters."""

from threat_research_mcp.ingestion.adapters.html_report_adapter import HtmlReportAdapter
from threat_research_mcp.ingestion.adapters.local_file_adapter import (
    LocalFileAdapter,
    StixBundleAdapter,
)
from threat_research_mcp.ingestion.adapters.rss_adapter import RssAdapter, RssAtomAdapter
from threat_research_mcp.ingestion.adapters.taxii_adapter import Taxii2Adapter, TaxiiAdapter

__all__ = [
    "HtmlReportAdapter",
    "LocalFileAdapter",
    "RssAdapter",
    "RssAtomAdapter",
    "StixBundleAdapter",
    "Taxii2Adapter",
    "TaxiiAdapter",
]
