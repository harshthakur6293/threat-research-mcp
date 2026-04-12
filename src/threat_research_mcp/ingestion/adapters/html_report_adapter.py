"""Fetch or load HTML reports and extract readable text."""

from __future__ import annotations

from pathlib import Path
from typing import List

from threat_research_mcp.ingestion.adapters.base_http_adapter import http_get_text
from threat_research_mcp.ingestion.base import IntelAdapter
from threat_research_mcp.ingestion.errors import IngestionError
from threat_research_mcp.ingestion.parser import parse_html_title, parse_html_to_text
from threat_research_mcp.schemas.intel_document import RawDocument, SourceConfig


def _read_local(path: str) -> str:
    p = Path(path).expanduser().resolve()
    if not p.is_file():
        raise IngestionError(f"html_report path is not a file: {p}")
    data = p.read_bytes()
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1", errors="replace")


class HtmlReportAdapter(IntelAdapter):
    @property
    def source_type(self) -> str:
        return "html_report"

    def collect_raw(self, cfg: SourceConfig) -> List[RawDocument]:
        if cfg.url and cfg.path:
            raise IngestionError("html_report: set only one of 'url' or 'path'")
        if cfg.url:
            html = http_get_text(cfg.url, cfg=cfg)
            page_url = cfg.url
        elif cfg.path:
            html = _read_local(cfg.path)
            page_url = f"file://{Path(cfg.path).expanduser().resolve().as_posix()}"
        else:
            raise IngestionError("html_report requires 'url' or 'path'")

        title = parse_html_title(html) or cfg.name
        body = parse_html_to_text(html)
        return [
            RawDocument(
                body=body or html,
                title=title,
                url=page_url,
                mime_hint="text/html",
            )
        ]
