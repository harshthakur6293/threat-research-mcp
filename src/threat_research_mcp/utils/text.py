"""Text processing helpers used across ingestion and mapping."""

from __future__ import annotations

import re
from html import unescape


_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")


def strip_html(text: str) -> str:
    """Best-effort HTML to text conversion."""
    return normalize_whitespace(unescape(_TAG_RE.sub(" ", text or "")))


def normalize_whitespace(text: str) -> str:
    """Collapse whitespace and trim."""
    return _WS_RE.sub(" ", text or "").strip()


def truncate(text: str, limit: int = 400) -> str:
    """Truncate text safely for previews."""
    normalized = normalize_whitespace(text)
    if len(normalized) <= limit:
        return normalized
    return normalized[: max(0, limit - 3)] + "..."
