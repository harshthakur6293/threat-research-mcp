"""Ingest plain text, HTML, or STIX JSON from local paths."""

from __future__ import annotations

import fnmatch
from pathlib import Path
from typing import List

from threat_research_mcp.ingestion.base import IntelAdapter
from threat_research_mcp.ingestion.errors import IngestionError
from threat_research_mcp.ingestion.parser import parse_html_to_text, parse_html_title, parse_stix_bundle_json
from threat_research_mcp.schemas.intel_document import RawDocument, SourceConfig


def _read_bytes(p: Path) -> str:
    data = p.read_bytes()
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1", errors="replace")


class LocalFileAdapter(IntelAdapter):
    @property
    def source_type(self) -> str:
        return "local_file"

    def collect_raw(self, cfg: SourceConfig) -> List[RawDocument]:
        if not cfg.path:
            raise IngestionError("local_file source requires 'path'")
        base = Path(cfg.path).expanduser().resolve()
        if not base.exists():
            raise IngestionError(f"Path does not exist: {base}")

        files: List[Path]
        if base.is_dir():
            files = sorted(
                p for p in base.iterdir() if p.is_file() and fnmatch.fnmatch(p.name.lower(), cfg.pattern.lower())
            )
        else:
            files = [base]

        out: List[RawDocument] = []
        for p in files:
            out.extend(self._read_one_file(p, cfg))
        return out

    def _read_one_file(self, p: Path, cfg: SourceConfig) -> List[RawDocument]:
        suffix = p.suffix.lower()
        text = _read_bytes(p)

        if suffix == ".json" or (text.strip().startswith("{") and '"type"' in text[:2000]):
            try:
                entries = parse_stix_bundle_json(text)
            except IngestionError:
                return [
                    RawDocument(
                        body=text,
                        title=p.name,
                        url=f"file://{p.as_posix()}",
                        mime_hint="application/json",
                        tags=["json"],
                    )
                ]
            if not entries:
                return [
                    RawDocument(
                        body=text,
                        title=p.name,
                        url=f"file://{p.as_posix()}",
                        mime_hint="application/json",
                        tags=["json", "stix"],
                    )
                ]
            return [
                RawDocument(
                    body=e["body"],
                    title=e.get("title") or p.name,
                    url=e.get("url") or f"file://{p.as_posix()}",
                    published_at=e.get("published_at"),
                    mime_hint="stix+json",
                    tags=e.get("tags") or [],
                )
                for e in entries
            ]

        if suffix in (".html", ".htm"):
            title = parse_html_title(text) or p.stem
            body = parse_html_to_text(text)
            return [
                RawDocument(
                    body=body or text,
                    title=title,
                    url=f"file://{p.as_posix()}",
                    mime_hint="text/html",
                )
            ]

        return [
            RawDocument(
                body=text,
                title=p.name,
                url=f"file://{p.as_posix()}",
                mime_hint="text/plain",
            )
        ]


class StixBundleAdapter(IntelAdapter):
    """Explicit STIX 2.x bundle file (same disk logic, fails if not STIX-shaped)."""

    @property
    def source_type(self) -> str:
        return "stix_bundle"

    def collect_raw(self, cfg: SourceConfig) -> List[RawDocument]:
        if not cfg.path:
            raise IngestionError("stix_bundle source requires 'path'")
        p = Path(cfg.path).expanduser().resolve()
        if not p.is_file():
            raise IngestionError(f"stix_bundle must be a file: {p}")
        text = _read_bytes(p)
        entries = parse_stix_bundle_json(text)
        if not entries:
            raise IngestionError(f"No STIX objects extracted from {p}")
        return [
            RawDocument(
                body=e["body"],
                title=e.get("title") or p.name,
                url=f"file://{p.as_posix()}",
                published_at=e.get("published_at"),
                mime_hint="stix+json",
                tags=e.get("tags") or [],
            )
            for e in entries
        ]
