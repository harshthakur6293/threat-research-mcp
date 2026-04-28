"""Campaign Tracker — stateful, multi-report threat campaign store.

Each campaign is a JSON file in the campaigns store directory (default: ./.campaigns/).
Multiple reports can be added to the same campaign; IOCs and techniques accumulate
across runs, enabling temporal correlation and full actor-picture visibility.

Team usage: point campaigns.store_dir at a shared git repository and commit
after each update — git handles conflict resolution and history.

Design: intentionally simple JSON files. No database, no schema migrations.
Analysts can read, edit, or grep campaign files directly.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from threat_research_mcp.tools.get_operator_context import load_operator_context


def _campaigns_dir() -> Path:
    ctx = load_operator_context()
    store = ctx.get("campaigns", {}).get("store_dir", "./.campaigns")
    d = Path(store)
    d.mkdir(parents=True, exist_ok=True)
    return d


def _campaign_path(campaign_id: str) -> Path:
    safe = re.sub(r"[^\w\-]", "-", campaign_id.lower())
    return _campaigns_dir() / f"{safe}.json"


def _load_campaign(campaign_id: str) -> dict[str, Any]:
    path = _campaign_path(campaign_id)
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return {
                "id": campaign_id,
                "created": datetime.utcnow().date().isoformat(),
                "last_updated": datetime.utcnow().date().isoformat(),
                "reports_ingested": 0,
                "actor": "",
                "description": "",
                "iocs": {"ips": [], "domains": [], "hashes": [], "emails": [], "urls": []},
                "filtered_fps": [],
                "techniques": {},
                "detections": {"tier1": 0, "tier2": 0, "tier3": 0},
                "coverage_gaps": [],
                "sources": [],
                "tags": [],
                "outputs": {},
                "load_error": f"Failed to parse existing campaign file {path}: {exc}",
            }
    return {
        "id": campaign_id,
        "created": datetime.utcnow().date().isoformat(),
        "last_updated": datetime.utcnow().date().isoformat(),
        "reports_ingested": 0,
        "actor": "",
        "description": "",
        "iocs": {"ips": [], "domains": [], "hashes": [], "emails": [], "urls": []},
        "filtered_fps": [],
        "techniques": {},
        "detections": {"tier1": 0, "tier2": 0, "tier3": 0},
        "coverage_gaps": [],
        "sources": [],
        "tags": [],
        "outputs": {},
    }


def _save_campaign(campaign: dict[str, Any]) -> Path:
    path = _campaign_path(campaign["id"])
    campaign["last_updated"] = datetime.utcnow().date().isoformat()
    path.write_text(json.dumps(campaign, indent=2), encoding="utf-8")
    return path


def _merge_iocs(existing: dict, new_iocs: dict) -> tuple[dict, int]:
    """Merge new IOCs into existing campaign IOCs. Returns (merged, new_count)."""
    new_count = 0
    merged = {k: list(v) for k, v in existing.items()}

    for key in ("ips", "domains", "hashes", "emails", "urls"):
        existing_set = set(merged.get(key, []))
        incoming = new_iocs.get(key, [])

        # Accept both rich dicts and plain strings
        incoming_values: list[str] = []
        for item in incoming:
            if isinstance(item, dict):
                incoming_values.append(item.get("value", ""))
            elif isinstance(item, str):
                incoming_values.append(item)

        for val in incoming_values:
            if val and val not in existing_set:
                merged.setdefault(key, []).append(val)
                existing_set.add(val)
                new_count += 1

    return merged, new_count


def _merge_techniques(existing: dict, new_techniques: list[dict]) -> dict:
    """Merge new techniques into existing campaign techniques."""
    merged = dict(existing)
    for tech in new_techniques:
        tid = tech.get("id", "")
        if not tid:
            continue
        if tid not in merged:
            merged[tid] = {
                "name": tech.get("name", ""),
                "tactic": tech.get("tactic", ""),
                "confidence": tech.get("confidence", tech.get("score", 0.5)),
                "evidence_count": len(tech.get("evidence", [])),
                "first_seen": datetime.utcnow().date().isoformat(),
                "last_seen": datetime.utcnow().date().isoformat(),
            }
        else:
            # Update confidence (take max), update last_seen
            old = merged[tid]
            new_conf = tech.get("confidence", tech.get("score", 0.5))
            old["confidence"] = max(old.get("confidence", 0), new_conf)
            old["evidence_count"] = old.get("evidence_count", 0) + len(tech.get("evidence", []))
            old["last_seen"] = datetime.utcnow().date().isoformat()
    return merged


def update_campaign(
    campaign_id: str,
    iocs: dict | None = None,
    techniques: list[dict] | None = None,
    source_url: str = "",
    actor: str = "",
    description: str = "",
    tags: list[str] | None = None,
    coverage_gaps: list[str] | None = None,
    detection_counts: dict | None = None,
    output_paths: dict | None = None,
) -> str:
    """Add intelligence from a new report to an existing (or new) campaign.

    Args:
        campaign_id: Campaign identifier (slug). Created if it doesn't exist.
        iocs: IOC dict from extract_iocs. New IOCs are merged with existing.
        techniques: Technique list from map_attack. Merged with existing.
        source_url: URL/path of the source report being added.
        actor: Threat actor name (optional — only set on first run or override).
        description: Campaign description (optional).
        tags: Additional tags (e.g. ["ransomware", "financial-sector"]).
        coverage_gaps: List of technique IDs with no detection coverage.
        detection_counts: Dict like {"tier1": 3, "tier2": 6, "tier3": 8}.
        output_paths: Dict of output file paths produced by this run.

    Returns: JSON with campaign summary and what changed.
    """
    campaign = _load_campaign(campaign_id)

    # Actor / description — only overwrite if provided
    if actor and not campaign.get("actor"):
        campaign["actor"] = actor
    if description and not campaign.get("description"):
        campaign["description"] = description

    # Source tracking
    if source_url and source_url not in campaign["sources"]:
        campaign["sources"].append(source_url)
        campaign["reports_ingested"] = len(campaign["sources"])

    # Tags
    if tags:
        existing_tags = set(campaign.get("tags", []))
        for tag in tags:
            existing_tags.add(tag)
        campaign["tags"] = sorted(existing_tags)

    # IOC merge
    new_ioc_count = 0
    if iocs:
        merged_iocs, new_ioc_count = _merge_iocs(campaign["iocs"], iocs)
        campaign["iocs"] = merged_iocs

        # Track filtered false positives
        fps = iocs.get("filtered_fps", [])
        if fps:
            existing_fps = set(campaign.get("filtered_fps", []))
            for fp in fps:
                existing_fps.add(fp if isinstance(fp, str) else fp.get("value", ""))
            campaign["filtered_fps"] = sorted(existing_fps)

    # Technique merge
    if techniques:
        campaign["techniques"] = _merge_techniques(campaign["techniques"], techniques)

    # Coverage gaps
    if coverage_gaps is not None:
        campaign["coverage_gaps"] = sorted(set(coverage_gaps))

    # Detection counts (cumulative max)
    if detection_counts:
        for tier_key in ("tier1", "tier2", "tier3"):
            campaign["detections"][tier_key] = max(
                campaign["detections"].get(tier_key, 0),
                detection_counts.get(tier_key, 0),
            )

    # Output paths
    if output_paths:
        campaign.setdefault("outputs", {}).update(output_paths)

    path = _save_campaign(campaign)

    return json.dumps(
        {
            "campaign_id": campaign_id,
            "path": str(path),
            "reports_ingested": campaign["reports_ingested"],
            "iocs_total": {k: len(v) for k, v in campaign["iocs"].items()},
            "new_iocs_added": new_ioc_count,
            "techniques_total": len(campaign["techniques"]),
            "detection_totals": campaign["detections"],
            "coverage_gaps": campaign["coverage_gaps"],
            "actor": campaign["actor"],
            "tags": campaign["tags"],
        },
        indent=2,
    )


def get_campaign(campaign_id: str) -> str:
    """Retrieve the full state of a campaign by ID.

    Returns: Full campaign JSON including all accumulated IOCs and techniques.
    """
    campaign = _load_campaign(campaign_id)
    return json.dumps(campaign, indent=2)


def list_campaigns() -> str:
    """List all campaigns in the campaign store.

    Returns: JSON array of campaign summaries (id, actor, techniques count, IOC count).
    """
    d = _campaigns_dir()
    summaries = []
    for f in sorted(d.glob("*.json")):
        try:
            c = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            summaries.append(
                {
                    "id": f.stem,
                    "path": str(f),
                    "error": f"Could not load campaign file: {exc}",
                }
            )
        else:
            ioc_total = sum(len(v) for v in c.get("iocs", {}).values() if isinstance(v, list))
            summaries.append(
                {
                    "id": c.get("id"),
                    "actor": c.get("actor", ""),
                    "description": c.get("description", ""),
                    "reports_ingested": c.get("reports_ingested", 0),
                    "techniques": len(c.get("techniques", {})),
                    "iocs_total": ioc_total,
                    "last_updated": c.get("last_updated"),
                    "tags": c.get("tags", []),
                    "coverage_gaps": len(c.get("coverage_gaps", [])),
                }
            )

    return json.dumps(
        {
            "campaigns": summaries,
            "count": len(summaries),
            "store_dir": str(d),
        },
        indent=2,
    )


def correlate_iocs_across_campaigns(ioc_value: str) -> str:
    """Find which campaigns share a specific IOC value.

    Useful for: "has this IP appeared in any other campaign?"
    Enables cross-campaign attribution and temporal correlation.

    Args:
        ioc_value: The IOC to search for (IP, domain, hash, email).

    Returns: JSON listing all campaigns that contain this IOC.
    """
    d = _campaigns_dir()
    matches: list[dict] = []

    for f in sorted(d.glob("*.json")):
        try:
            c = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            c = {}
        if c:
            found_in: list[str] = []
            for ioc_type, items in c.get("iocs", {}).items():
                if isinstance(items, list) and ioc_value in items:
                    found_in.append(ioc_type)
            if found_in:
                matches.append(
                    {
                        "campaign_id": c.get("id"),
                        "actor": c.get("actor", ""),
                        "found_in_types": found_in,
                        "last_updated": c.get("last_updated"),
                        "techniques": list(c.get("techniques", {}).keys()),
                    }
                )

    return json.dumps(
        {
            "ioc": ioc_value,
            "found_in_campaigns": matches,
            "campaign_count": len(matches),
            "correlation_note": (
                f"IOC '{ioc_value}' appears in {len(matches)} campaign(s). "
                + (
                    "Multi-campaign presence increases attribution confidence."
                    if len(matches) > 1
                    else "Single campaign — no cross-campaign correlation yet."
                )
            ),
        },
        indent=2,
    )
