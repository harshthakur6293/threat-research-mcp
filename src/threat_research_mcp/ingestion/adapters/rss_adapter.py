"""Fetch and parse RSS or Atom feeds."""

from __future__ import annotations

from typing import List

from threat_research_mcp.ingestion.adapters.base_http_adapter import http_get_text
from threat_research_mcp.ingestion.base import IntelAdapter
from threat_research_mcp.ingestion.errors import IngestionError
from threat_research_mcp.ingestion.parser import parse_feed_xml
from threat_research_mcp.schemas.intel_document import RawDocument, SourceConfig


class RssAdapter(IntelAdapter):
    @property
    def source_type(self) -> str:
        return "rss"

    def collect_raw(self, cfg: SourceConfig) -> List[RawDocument]:
        if not cfg.url:
            raise IngestionError("rss source requires 'url'")
        xml_text = http_get_text(cfg.url, cfg=cfg)
        items = parse_feed_xml(xml_text)
        return [
            RawDocument(
                body=item.get("summary") or item.get("title") or "",
                title=item.get("title") or "untitled",
                url=item.get("url") or cfg.url,
                published_at=item.get("published_at"),
                mime_hint="application/rss+xml",
            )
            for item in items
        ]


class RssAtomAdapter(RssAdapter):
    """Alias type name from handoff (`rss_atom`)."""

    @property
    def source_type(self) -> str:
        return "rss_atom"
