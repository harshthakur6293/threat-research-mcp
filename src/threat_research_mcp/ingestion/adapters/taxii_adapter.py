"""TAXII 2.1 client: fetch STIX objects from a collection (JSON over HTTPS)."""

from __future__ import annotations

from typing import Any, Dict, List, cast
from urllib.parse import urlparse, urljoin

from threat_research_mcp.ingestion.adapters.base_http_adapter import http_get_json
from threat_research_mcp.ingestion.base import IntelAdapter
from threat_research_mcp.ingestion.errors import IngestionError
from threat_research_mcp.ingestion.parser import stix_objects_to_entries
from threat_research_mcp.schemas.intel_document import RawDocument, SourceConfig

TAXII_ACCEPT = "application/taxii+json;version=2.1"


def _api_root_url(api_root: str) -> str:
    return api_root.rstrip("/") + "/"


def _taxii_headers() -> Dict[str, str]:
    return {"Accept": TAXII_ACCEPT}


def list_taxii_collections(api_root: str, cfg: SourceConfig) -> List[Dict[str, Any]]:
    root = _api_root_url(api_root)
    url = root + "collections/"
    data = cast(
        Dict[str, Any],
        http_get_json(url, cfg=cfg, headers=_taxii_headers()),
    )
    cols = data.get("collections")
    if not isinstance(cols, list):
        return []
    return [c for c in cols if isinstance(c, dict)]


def fetch_taxii_objects(api_root: str, collection_id: str, cfg: SourceConfig) -> List[Dict[str, Any]]:
    root = _api_root_url(api_root)
    cid = collection_id.strip().strip("/")
    url = f"{root}collections/{cid}/objects/"
    headers = _taxii_headers()
    all_objects: List[Dict[str, Any]] = []

    while url:
        data = cast(Dict[str, Any], http_get_json(url, cfg=cfg, headers=headers))
        objs = data.get("objects")
        if isinstance(objs, list):
            for o in objs:
                if isinstance(o, dict):
                    all_objects.append(o)
        nxt = data.get("next")
        if isinstance(nxt, str) and nxt.strip():
            nxt = nxt.strip()
            if nxt.startswith("http://") or nxt.startswith("https://"):
                url = nxt
            elif nxt.startswith("/"):
                pu = urlparse(root)
                url = f"{pu.scheme}://{pu.netloc}{nxt}"
            else:
                url = urljoin(root, nxt)
        else:
            url = ""

    return all_objects


class TaxiiAdapter(IntelAdapter):
    """Requires `api_root`; `collection_id` optional if exactly one collection exists."""

    @property
    def source_type(self) -> str:
        return "taxii"

    def collect_raw(self, cfg: SourceConfig) -> List[RawDocument]:
        if not cfg.api_root:
            raise IngestionError("taxii source requires 'api_root' (TAXII 2.1 API root URL)")

        collection_id = cfg.collection_id
        if not collection_id:
            cols = list_taxii_collections(cfg.api_root, cfg)
            if not cols:
                raise IngestionError("No TAXII collections returned; check api_root and credentials")
            if len(cols) == 1:
                cid = cols[0].get("id")
                if not isinstance(cid, str) or not cid:
                    raise IngestionError("TAXII collection missing id field")
                collection_id = cid
            else:
                titles = [str(c.get("title", c.get("id", "?"))) for c in cols[:10]]
                raise IngestionError(
                    "Multiple TAXII collections; set 'collection_id' in source config. "
                    f"Available (sample): {', '.join(titles)}"
                )

        objects = fetch_taxii_objects(cfg.api_root, collection_id, cfg)
        entries = stix_objects_to_entries(objects)
        base_url = _api_root_url(cfg.api_root) + f"collections/{collection_id.strip('/')}/objects/"

        return [
            RawDocument(
                body=e["body"],
                title=e.get("title") or "STIX object",
                url=base_url,
                published_at=e.get("published_at"),
                mime_hint="stix+json",
                tags=(e.get("tags") or []) + ["taxii", collection_id],
            )
            for e in entries
        ]


class Taxii2Adapter(TaxiiAdapter):
    """Alias type name."""

    @property
    def source_type(self) -> str:
        return "taxii2"
