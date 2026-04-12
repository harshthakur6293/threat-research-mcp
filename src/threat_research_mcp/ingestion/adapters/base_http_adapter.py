"""Shared HTTP fetch for RSS, HTML URL, and TAXII JSON."""

from __future__ import annotations

import base64
import json
import ssl
from typing import Any, Dict, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from threat_research_mcp.ingestion.errors import IngestionError
from threat_research_mcp.schemas.intel_document import SourceConfig


def _basic_auth_header(username: str, password: str) -> str:
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return f"Basic {token}"


def http_get_bytes(
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    cfg: Optional[SourceConfig] = None,
    timeout: int = 60,
) -> bytes:
    """GET URL; optional Basic auth or API key from SourceConfig."""
    hdrs = dict(headers or {})
    if cfg:
        if cfg.username and cfg.password:
            hdrs.setdefault("Authorization", _basic_auth_header(cfg.username, cfg.password))
        if cfg.api_key:
            if cfg.api_key_header.lower() == "authorization":
                hdrs.setdefault(
                    cfg.api_key_header,
                    f"{cfg.api_key_prefix}{cfg.api_key}".strip(),
                )
            else:
                hdrs.setdefault(cfg.api_key_header, cfg.api_key)
        timeout = cfg.timeout_seconds
    req = Request(url, headers=hdrs, method="GET")
    ctx = ssl.create_default_context()
    try:
        with urlopen(req, timeout=timeout, context=ctx) as resp:  # nosec B310
            return resp.read()
    except HTTPError as e:
        raise IngestionError(f"HTTP {e.code} for {url}: {e.reason}") from e
    except URLError as e:
        raise IngestionError(f"URL error for {url}: {e.reason}") from e


def http_get_text(url: str, *, cfg: Optional[SourceConfig] = None, headers: Optional[Dict[str, str]] = None) -> str:
    raw = http_get_bytes(url, cfg=cfg, headers=headers)
    return raw.decode("utf-8", errors="replace")


def http_get_json(url: str, *, cfg: Optional[SourceConfig] = None, headers: Optional[Dict[str, str]] = None) -> Any:
    text = http_get_text(url, cfg=cfg, headers=headers)
    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        raise IngestionError(f"Invalid JSON from {url}: {e}") from e
