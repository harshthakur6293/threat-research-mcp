"""MITRE ATT&CK lookup tools backed by a local SQLite database.

Build the database once with:
    python scripts/build_attack_db.py

The database lives at playbook/attack.db (relative to the repo root).
All functions degrade gracefully when the DB is absent — they return a
structured 'db_not_built' response rather than crashing.

Tools exposed via MCP:
  get_technique           — full ATT&CK technique card (description, platforms, data sources, detection)
  get_threat_groups       — groups that use a given technique (actor attribution)
  get_techniques_by_group — all techniques attributed to a threat group
  attribute_to_group      — given observed technique IDs, rank best-matching threat groups
  get_data_sources        — what you must log to detect a technique
  get_mitigations         — recommended controls for a technique
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

# Locate the database: repo root / playbook / attack.db
_CANDIDATES = [
    Path(__file__).parent.parent.parent.parent / "playbook" / "attack.db",
    Path(__file__).parent.parent / "playbook" / "attack.db",
]


def _db_path() -> Path | None:
    for p in _CANDIDATES:
        if p.exists():
            return p
    return None


def _con() -> sqlite3.Connection | None:
    p = _db_path()
    if not p:
        return None
    con = sqlite3.connect(p)
    con.row_factory = sqlite3.Row
    return con


def _no_db_response(tool: str) -> str:
    return json.dumps(
        {
            "error": "attack.db not found",
            "tool": tool,
            "fix": "Run: python scripts/build_attack_db.py",
            "note": (
                "The ATT&CK database is built from the MITRE STIX bundle. "
                "Run the script once; re-run quarterly when ATT&CK updates."
            ),
        },
        indent=2,
    )


def _jload(s: str | None) -> list:
    try:
        return json.loads(s or "[]")
    except Exception:
        return []


# ── Tool implementations ──────────────────────────────────────────────────────


def get_technique(technique_id: str) -> str:
    """Return the full ATT&CK technique card for a given technique ID.

    Includes: name, tactic(s), description, platforms, data sources,
    detection guidance, sub-techniques, URL, and any mitigations.

    Args:
        technique_id: ATT&CK ID, e.g. "T1059.001" or "T1059".
    """
    con = _con()
    if not con:
        return _no_db_response("get_technique")

    tid = technique_id.strip().upper()
    row = con.execute("SELECT * FROM techniques WHERE id=?", (tid,)).fetchone()
    if not row:
        # Try parent wildcard: "T1059" returns T1059 and all sub-techniques
        rows = con.execute(
            "SELECT * FROM techniques WHERE id=? OR parent_id=? ORDER BY id",
            (tid, tid),
        ).fetchall()
        if not rows:
            con.close()
            return json.dumps({"error": f"Technique {tid} not found in ATT&CK database."}, indent=2)
        results = [_row_to_dict(r) for r in rows]
        con.close()
        return json.dumps(
            {"technique_id": tid, "results": results, "count": len(results)}, indent=2
        )

    result = _row_to_dict(row)

    # Mitigations
    mit_rows = con.execute(
        "SELECT m.id, m.name, m.description FROM mitigations m "
        "JOIN technique_mitigations tm ON m.id=tm.mitigation_id "
        "WHERE tm.technique_id=?",
        (tid,),
    ).fetchall()
    result["mitigations"] = [
        {"id": m["id"], "name": m["name"], "description": (m["description"] or "")[:300]}
        for m in mit_rows
    ]

    # Sub-techniques (if parent)
    if not row["is_subtechnique"]:
        subs = con.execute(
            "SELECT id, name FROM techniques WHERE parent_id=? ORDER BY id", (tid,)
        ).fetchall()
        result["sub_techniques"] = [{"id": s["id"], "name": s["name"]} for s in subs]

    con.close()
    return json.dumps(result, indent=2)


def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "name": row["name"],
        "tactics": _jload(row["tactics"]),
        "platforms": _jload(row["platforms"]),
        "data_sources": _jload(row["data_sources"]),
        "description": (row["description"] or "")[:800]
        + ("…" if len(row["description"] or "") > 800 else ""),
        "detection": (row["detection"] or "")[:600]
        + ("…" if len(row["detection"] or "") > 600 else ""),
        "is_subtechnique": bool(row["is_subtechnique"]),
        "parent_id": row["parent_id"],
        "url": row["url"],
    }


def get_threat_groups(technique_id: str) -> str:
    """Return threat groups (APT/cybercrime) that use a given ATT&CK technique.

    Useful for actor attribution: given an observed technique, who typically
    uses it? Confidence is highest when multiple techniques overlap with a
    known group (see attribute_to_group for that analysis).

    Args:
        technique_id: ATT&CK technique ID, e.g. "T1059.001".
    """
    con = _con()
    if not con:
        return _no_db_response("get_threat_groups")

    tid = technique_id.strip().upper()
    rows = con.execute(
        "SELECT g.id, g.name, g.aliases, g.url FROM groups g "
        "JOIN group_techniques gt ON g.id=gt.group_id "
        "WHERE gt.technique_id=? ORDER BY g.name",
        (tid,),
    ).fetchall()
    con.close()

    groups = [
        {
            "id": r["id"],
            "name": r["name"],
            "aliases": _jload(r["aliases"]),
            "url": r["url"],
        }
        for r in rows
    ]
    return json.dumps(
        {
            "technique_id": tid,
            "groups": groups,
            "count": len(groups),
            "note": (
                f"{len(groups)} known threat group(s) use {tid}. "
                "Call attribute_to_group with multiple technique IDs for stronger attribution."
            ),
        },
        indent=2,
    )


def get_techniques_by_group(group_name_or_id: str) -> str:
    """Return all ATT&CK techniques attributed to a specific threat group.

    Accepts group ID (G0010), common name (APT28), or alias (Fancy Bear).

    Args:
        group_name_or_id: Group identifier — ID, name, or alias.
    """
    con = _con()
    if not con:
        return _no_db_response("get_techniques_by_group")

    q = group_name_or_id.strip()
    # Try exact ID match first, then name, then alias substring
    group_row = (
        con.execute("SELECT * FROM groups WHERE id=?", (q.upper(),)).fetchone()
        or con.execute("SELECT * FROM groups WHERE LOWER(name)=LOWER(?)", (q,)).fetchone()
        or con.execute(
            "SELECT * FROM groups WHERE LOWER(aliases) LIKE LOWER(?)", (f"%{q}%",)
        ).fetchone()
    )
    if not group_row:
        con.close()
        return json.dumps(
            {"error": f"Group '{q}' not found. Try the ATT&CK group ID (G0010) or name."}, indent=2
        )

    gid = group_row["id"]
    rows = con.execute(
        "SELECT t.id, t.name, t.tactics FROM techniques t "
        "JOIN group_techniques gt ON t.id=gt.technique_id "
        "WHERE gt.group_id=? ORDER BY t.id",
        (gid,),
    ).fetchall()
    con.close()

    techniques = [{"id": r["id"], "name": r["name"], "tactics": _jload(r["tactics"])} for r in rows]
    tactic_counts: dict[str, int] = {}
    for t in techniques:
        for tac in t["tactics"]:
            tactic_counts[tac] = tactic_counts.get(tac, 0) + 1

    return json.dumps(
        {
            "group_id": gid,
            "group_name": group_row["name"],
            "aliases": _jload(group_row["aliases"]),
            "url": group_row["url"],
            "techniques": techniques,
            "technique_count": len(techniques),
            "tactic_distribution": dict(sorted(tactic_counts.items(), key=lambda x: -x[1])),
        },
        indent=2,
    )


def attribute_to_group(technique_ids: str) -> str:
    """Rank threat groups by overlap with a set of observed technique IDs.

    Given the techniques extracted from a threat report, this finds which
    known threat groups have the highest technique overlap — supporting
    actor attribution hypotheses.

    Scoring: Jaccard similarity = |observed ∩ group_techniques| / |observed ∪ group_techniques|

    Args:
        technique_ids: Comma-separated ATT&CK IDs, e.g. "T1059.001,T1003.001,T1071.001".
    """
    con = _con()
    if not con:
        return _no_db_response("attribute_to_group")

    observed = {t.strip().upper() for t in technique_ids.split(",") if t.strip()}
    if not observed:
        con.close()
        return json.dumps({"error": "No technique IDs provided."}, indent=2)

    # For each group, get their technique set
    groups_rows = con.execute("SELECT id, name, aliases, url FROM groups").fetchall()
    results = []

    for g in groups_rows:
        gid = g["id"]
        g_techniques = {
            r["technique_id"]
            for r in con.execute(
                "SELECT technique_id FROM group_techniques WHERE group_id=?", (gid,)
            ).fetchall()
        }
        if not g_techniques:
            continue

        intersection = observed & g_techniques
        union = observed | g_techniques
        jaccard = len(intersection) / len(union) if union else 0
        overlap_ratio = len(intersection) / len(observed) if observed else 0

        if intersection:
            results.append(
                {
                    "group_id": gid,
                    "group_name": g["name"],
                    "aliases": _jload(g["aliases"]),
                    "url": g["url"],
                    "matched_techniques": sorted(intersection),
                    "matched_count": len(intersection),
                    "total_group_techniques": len(g_techniques),
                    "jaccard_similarity": round(jaccard, 4),
                    "observed_overlap_pct": round(overlap_ratio * 100, 1),
                }
            )

    con.close()
    results.sort(key=lambda x: (-x["matched_count"], -x["jaccard_similarity"]))
    top = results[:10]

    confidence = (
        "HIGH"
        if top and top[0]["observed_overlap_pct"] >= 60
        else "MEDIUM"
        if top and top[0]["observed_overlap_pct"] >= 30
        else "LOW"
    )

    return json.dumps(
        {
            "observed_techniques": sorted(observed),
            "observed_count": len(observed),
            "top_matches": top,
            "attribution_confidence": confidence,
            "note": (
                f"Top match: {top[0]['group_name']} ({top[0]['observed_overlap_pct']}% technique overlap). "
                f"Attribution is probabilistic — multiple overlapping indicators increase confidence."
                if top
                else "No matching threat groups found for these techniques."
            ),
        },
        indent=2,
    )


def get_data_sources(technique_id: str) -> str:
    """Return the data sources (log types) needed to detect a technique.

    Maps ATT&CK data source labels to practical log sources in Splunk,
    Sentinel (KQL), and Elastic so analysts know what to enable.

    Args:
        technique_id: ATT&CK technique ID, e.g. "T1059.001".
    """
    con = _con()
    if not con:
        return _no_db_response("get_data_sources")

    tid = technique_id.strip().upper()
    row = con.execute(
        "SELECT id, name, data_sources, detection FROM techniques WHERE id=?", (tid,)
    ).fetchone()
    if not row:
        con.close()
        return json.dumps({"error": f"{tid} not found in ATT&CK database."}, indent=2)

    data_sources = _jload(row["data_sources"])
    # Map ATT&CK data source labels to practical SIEM sources
    siem_map: dict[str, dict[str, str]] = {
        "Process: Process Creation": {
            "splunk": "index=sysmon EventCode=1",
            "kql": "DeviceProcessEvents",
            "elastic": "process.executable:*",
        },
        "Process: Process Access": {
            "splunk": "index=sysmon EventCode=10",
            "kql": "DeviceEvents",
            "elastic": "event.category:process",
        },
        "Network Traffic: Network Connection Created": {
            "splunk": "index=sysmon EventCode=3",
            "kql": "DeviceNetworkEvents",
            "elastic": "network.direction:egress",
        },
        "File: File Creation": {
            "splunk": "index=sysmon EventCode=11",
            "kql": "DeviceFileEvents",
            "elastic": "file.path:*",
        },
        "Script: Script Execution": {
            "splunk": "index=wineventlog EventCode=4104",
            "kql": "Event | where EventID==4104",
            "elastic": "event.code:4104",
        },
        "Windows Registry: Windows Registry Key Modified": {
            "splunk": "index=sysmon EventCode=13",
            "kql": "DeviceRegistryEvents",
            "elastic": "event.category:registry",
        },
        "Logon Session: Logon Session Creation": {
            "splunk": "index=wineventlog EventCode=4624",
            "kql": "SigninLogs or SecurityEvent|where EventID==4624",
            "elastic": "event.code:4624",
        },
        "Command: Command Execution": {
            "splunk": "index=wineventlog EventCode=4688",
            "kql": "SecurityEvent | where EventID==4688",
            "elastic": "process.command_line:*",
        },
        "Cloud Service: Cloud Service Activity": {
            "splunk": "index=aws_cloudtrail",
            "kql": "AWSCloudTrail or AzureActivity",
            "elastic": "aws.cloudtrail.*",
        },
    }

    mapped = []
    unmapped = []
    for ds in data_sources:
        if ds in siem_map:
            mapped.append({"data_source": ds, **siem_map[ds]})
        else:
            unmapped.append(ds)

    con.close()
    return json.dumps(
        {
            "technique_id": tid,
            "technique_name": row["name"],
            "data_sources": data_sources,
            "siem_mapping": mapped,
            "unmapped_sources": unmapped,
            "detection_guidance": (row["detection"] or "")[:600],
            "note": (
                f"{len(mapped)} of {len(data_sources)} data sources mapped to SIEM queries. "
                "Enable these log sources before deploying detection rules."
            ),
        },
        indent=2,
    )


def get_mitigations(technique_id: str) -> str:
    """Return recommended ATT&CK mitigations (controls) for a technique.

    Args:
        technique_id: ATT&CK technique ID, e.g. "T1059.001".
    """
    con = _con()
    if not con:
        return _no_db_response("get_mitigations")

    tid = technique_id.strip().upper()
    rows = con.execute(
        "SELECT m.id, m.name, m.description, m.url FROM mitigations m "
        "JOIN technique_mitigations tm ON m.id=tm.mitigation_id "
        "WHERE tm.technique_id=? ORDER BY m.id",
        (tid,),
    ).fetchall()
    con.close()

    mitigations = [
        {
            "id": r["id"],
            "name": r["name"],
            "description": (r["description"] or "")[:400],
            "url": r["url"],
        }
        for r in rows
    ]
    return json.dumps(
        {
            "technique_id": tid,
            "mitigations": mitigations,
            "count": len(mitigations),
        },
        indent=2,
    )
