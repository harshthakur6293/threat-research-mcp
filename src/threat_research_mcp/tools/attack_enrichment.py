"""MITRE ATT&CK enrichment via mitreattack-python + official STIX bundle.

Provides per-technique detail pulled directly from MITRE's published data:
platforms, data sources, detection guidance, and known threat groups.

Setup (one-time):
    pip install "threat-research-mcp[attack]"
    python scripts/download_attack_stix.py

All public functions degrade gracefully — returning empty dicts / lists —
when either mitreattack-python is not installed or the STIX file has not
been downloaded yet.  No crash, no exception surfaced to the caller.
"""

from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path
from typing import Any

try:
    from mitreattack.stix20 import MitreAttackData as _MitreAttackData

    _MITRE_OK = True
except ImportError:
    _MITRE_OK = False

_STIX_CANDIDATES: list[Path] = [
    Path(__file__).parent.parent.parent.parent / "playbook" / "enterprise-attack.json",
    Path(os.getcwd()) / "playbook" / "enterprise-attack.json",
    Path(__file__).parent.parent / "playbook" / "enterprise-attack.json",
]


def _stix_path() -> Path | None:
    for p in _STIX_CANDIDATES:
        if p.exists():
            return p
    return None


@lru_cache(maxsize=1)
def _data() -> Any | None:
    """Load MitreAttackData once per process and cache it."""
    if not _MITRE_OK:
        return None
    p = _stix_path()
    if not p:
        return None
    try:
        return _MitreAttackData(str(p))
    except Exception:
        return None


def is_available() -> bool:
    """Return True when STIX enrichment is ready."""
    return _MITRE_OK and _stix_path() is not None


def stix_status() -> dict[str, Any]:
    """Return setup status — useful for diagnosing missing dependencies."""
    path = _stix_path()
    return {
        "mitreattack_python_installed": _MITRE_OK,
        "stix_file_found": path is not None,
        "stix_file_path": str(path) if path else None,
        "enrichment_available": is_available(),
        "setup_instructions": (
            "Ready — STIX enrichment active."
            if is_available()
            else (
                "Run: pip install 'threat-research-mcp[attack]' "
                "&& python scripts/download_attack_stix.py"
            )
        ),
    }


def enrich_technique(technique_id: str) -> dict[str, Any]:
    """Return MITRE detail for one technique ID.

    Fields returned (all optional — may be empty if not in STIX data):
      description, platforms, data_sources, detection, version, groups

    Returns {} when STIX data is unavailable.
    """
    d = _data()
    if not d:
        return {}

    tid = technique_id.strip().upper()
    try:
        obj = d.get_object_by_attack_id(tid, "attack-pattern")
        if not obj:
            return {}

        detail: dict[str, Any] = {
            "description": (obj.get("description") or "")[:600],
            "platforms": obj.get("x_mitre_platforms") or [],
            "data_sources": obj.get("x_mitre_data_sources") or [],
            "detection": (obj.get("x_mitre_detection") or "")[:500],
            "version": obj.get("x_mitre_version") or "",
            "groups": _groups_for(obj.id, top_n=5),
        }
        return detail
    except Exception:
        return {}


def _groups_for(stix_id: str, top_n: int = 5) -> list[dict[str, str]]:
    """Return top N threat groups known to use this technique (by STIX ID)."""
    d = _data()
    if not d:
        return []
    try:
        items = d.get_groups_using_technique(stix_id) or []
        results: list[dict[str, str]] = []
        for item in items[:top_n]:
            group = item.get("object") if isinstance(item, dict) else item
            if group is None:
                continue
            refs = group.get("external_references") or []
            attack_id = next(
                (r.get("external_id", "") for r in refs if r.get("source_name") == "mitre-attack"),
                "",
            )
            url = next(
                (r.get("url", "") for r in refs if r.get("source_name") == "mitre-attack"),
                "",
            )
            name = group.get("name") or ""
            if name:
                results.append(
                    {
                        "id": attack_id,
                        "name": name,
                        "aliases": (group.get("aliases") or [])[:3],
                        "url": url,
                    }
                )
        return results
    except Exception:
        return []


def enrich_techniques_batch(technique_ids: list[str]) -> dict[str, dict[str, Any]]:
    """Enrich multiple techniques in one call. Returns {tid: detail_dict}."""
    return {tid: enrich_technique(tid) for tid in technique_ids}


# ── MCP-facing tool functions ─────────────────────────────────────────────────


def stix_status_json() -> str:
    """Return STIX enrichment setup status as JSON."""
    return json.dumps(stix_status(), indent=2)


def enrich_techniques_json(technique_ids: str) -> str:
    """Enrich a comma-separated list of ATT&CK technique IDs from STIX data.

    Args:
        technique_ids: Comma-separated IDs, e.g. "T1059.001,T1003.001,T1071"

    Returns: JSON mapping each ID to its MITRE enrichment (platforms, data
             sources, detection notes, top threat groups).
    """
    ids = [t.strip().upper() for t in technique_ids.split(",") if t.strip()]
    if not ids:
        return json.dumps({"error": "No technique IDs provided."}, indent=2)

    if not is_available():
        return json.dumps(
            {
                "error": "STIX enrichment not available.",
                "techniques_requested": ids,
                **stix_status(),
            },
            indent=2,
        )

    enriched = enrich_techniques_batch(ids)
    found = {k: v for k, v in enriched.items() if v}
    missing = [k for k, v in enriched.items() if not v]

    return json.dumps(
        {
            "enriched": found,
            "not_found": missing,
            "count": len(found),
            "source": "MITRE ATT&CK STIX bundle (enterprise-attack.json)",
        },
        indent=2,
    )
