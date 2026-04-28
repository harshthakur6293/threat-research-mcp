"""Download and index the MITRE ATT&CK Enterprise dataset into a local SQLite database.

Run once to create playbook/attack.db, then re-run quarterly when ATT&CK releases
a new version (currently Jan, Apr, Jul, Oct).

Usage:
    python scripts/build_attack_db.py
    python scripts/build_attack_db.py --stix path/to/enterprise-attack.json
    python scripts/build_attack_db.py --version 15.1

The database is written to playbook/attack.db relative to the repo root.
All tools in threat_research_mcp.tools.attack_lookup read from this file.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
)
VERSIONED_URL = (
    "https://raw.githubusercontent.com/mitre/cti/ATT%26CK-v{version}/"
    "enterprise-attack/enterprise-attack.json"
)

REPO_ROOT = Path(__file__).parent.parent
DB_PATH = REPO_ROOT / "playbook" / "attack.db"


# ── Schema ────────────────────────────────────────────────────────────────────

DDL = """
CREATE TABLE IF NOT EXISTS techniques (
    id              TEXT PRIMARY KEY,   -- T1059.001
    name            TEXT NOT NULL,
    description     TEXT,
    platforms       TEXT,               -- JSON array
    data_sources    TEXT,               -- JSON array
    tactics         TEXT,               -- JSON array of tactic names
    detection       TEXT,               -- ATT&CK detection guidance
    url             TEXT,
    is_subtechnique INTEGER DEFAULT 0,
    parent_id       TEXT                -- T1059 for T1059.001; NULL otherwise
);

CREATE TABLE IF NOT EXISTS groups (
    id          TEXT PRIMARY KEY,       -- G0010
    name        TEXT NOT NULL,
    aliases     TEXT,                   -- JSON array
    description TEXT,
    url         TEXT
);

CREATE TABLE IF NOT EXISTS software (
    id          TEXT PRIMARY KEY,       -- S0002
    name        TEXT NOT NULL,
    type        TEXT,                   -- malware | tool
    platforms   TEXT,                   -- JSON array
    description TEXT,
    url         TEXT
);

CREATE TABLE IF NOT EXISTS group_techniques (
    group_id     TEXT NOT NULL,
    technique_id TEXT NOT NULL,
    PRIMARY KEY (group_id, technique_id)
);

CREATE TABLE IF NOT EXISTS software_techniques (
    software_id  TEXT NOT NULL,
    technique_id TEXT NOT NULL,
    PRIMARY KEY (software_id, technique_id)
);

CREATE TABLE IF NOT EXISTS mitigations (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT,
    url         TEXT
);

CREATE TABLE IF NOT EXISTS technique_mitigations (
    technique_id  TEXT NOT NULL,
    mitigation_id TEXT NOT NULL,
    PRIMARY KEY (technique_id, mitigation_id)
);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);

CREATE INDEX IF NOT EXISTS idx_gt_technique ON group_techniques(technique_id);
CREATE INDEX IF NOT EXISTS idx_gt_group     ON group_techniques(group_id);
CREATE INDEX IF NOT EXISTS idx_st_technique ON software_techniques(technique_id);
CREATE INDEX IF NOT EXISTS idx_tm_technique ON technique_mitigations(technique_id);
"""


# ── Helpers ───────────────────────────────────────────────────────────────────


def _j(obj) -> str:
    return json.dumps(obj, ensure_ascii=False) if obj else "[]"


def _ext_ref_url(refs: list[dict]) -> str:
    for r in refs or []:
        if r.get("source_name") == "mitre-attack":
            return r.get("url", "")
    return ""


def _mitre_id(refs: list[dict]) -> str:
    for r in refs or []:
        if r.get("source_name") == "mitre-attack":
            return r.get("external_id", "")
    return ""


def _load_stix(path: str | None, version: str | None) -> dict:
    if path:
        print(f"Loading STIX from local file: {path}")
        return json.loads(Path(path).read_text(encoding="utf-8"))

    import requests

    url = VERSIONED_URL.format(version=version) if version else STIX_URL
    print(f"Downloading ATT&CK STIX bundle from {url} …")
    resp = requests.get(url, timeout=120)
    resp.raise_for_status()
    return resp.json()


# ── Main builder ──────────────────────────────────────────────────────────────


def build(stix_path: str | None = None, version: str | None = None) -> None:
    bundle = _load_stix(stix_path, version)
    objects = bundle.get("objects", [])
    print(f"  {len(objects)} STIX objects loaded")

    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    if DB_PATH.exists():
        DB_PATH.unlink()

    con = sqlite3.connect(DB_PATH)
    con.executescript(DDL)

    # Index by STIX ID for relationship resolution
    by_stix: dict[str, dict] = {}
    mitre_id_map: dict[str, str] = {}  # stix_id → mitre_id (T1059.001, G0010 …)

    # Pass 1 — index all objects
    for obj in objects:
        stix_id = obj.get("id", "")
        refs = obj.get("external_references", [])
        mid = _mitre_id(refs)
        if mid:
            by_stix[stix_id] = obj
            mitre_id_map[stix_id] = mid

    techniques_inserted = groups_inserted = software_inserted = mitigations_inserted = 0
    relationships_inserted = 0

    # Pass 2 — insert entities
    with con:
        for stix_id, obj in by_stix.items():
            otype = obj.get("type", "")
            refs = obj.get("external_references", [])
            mid = mitre_id_map.get(stix_id, "")
            if not mid:
                continue

            if otype == "attack-pattern" and not obj.get("x_mitre_deprecated", False):
                phases = obj.get("kill_chain_phases", [])
                tactics = [
                    p["phase_name"] for p in phases if p.get("kill_chain_name") == "mitre-attack"
                ]
                parent_id = None
                if obj.get("x_mitre_is_subtechnique"):
                    # T1059.001 → parent is T1059
                    parent_id = mid.rsplit(".", 1)[0] if "." in mid else None
                con.execute(
                    "INSERT OR REPLACE INTO techniques VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (
                        mid,
                        obj.get("name", ""),
                        obj.get("description", ""),
                        _j(obj.get("x_mitre_platforms", [])),
                        _j(obj.get("x_mitre_data_sources", [])),
                        _j(tactics),
                        obj.get("x_mitre_detection", ""),
                        _ext_ref_url(refs),
                        int(bool(obj.get("x_mitre_is_subtechnique"))),
                        parent_id,
                    ),
                )
                techniques_inserted += 1

            elif otype == "intrusion-set" and not obj.get("x_mitre_deprecated", False):
                con.execute(
                    "INSERT OR REPLACE INTO groups VALUES (?,?,?,?,?)",
                    (
                        mid,
                        obj.get("name", ""),
                        _j(obj.get("aliases", [])),
                        obj.get("description", ""),
                        _ext_ref_url(refs),
                    ),
                )
                groups_inserted += 1

            elif otype in ("malware", "tool") and not obj.get("x_mitre_deprecated", False):
                con.execute(
                    "INSERT OR REPLACE INTO software VALUES (?,?,?,?,?,?)",
                    (
                        mid,
                        obj.get("name", ""),
                        otype,
                        _j(obj.get("x_mitre_platforms", [])),
                        obj.get("description", ""),
                        _ext_ref_url(refs),
                    ),
                )
                software_inserted += 1

            elif otype == "course-of-action" and not obj.get("x_mitre_deprecated", False):
                con.execute(
                    "INSERT OR REPLACE INTO mitigations VALUES (?,?,?,?)",
                    (
                        mid,
                        obj.get("name", ""),
                        obj.get("description", ""),
                        _ext_ref_url(refs),
                    ),
                )
                mitigations_inserted += 1

        # Pass 3 — insert relationships
        for obj in objects:
            if obj.get("type") != "relationship" or obj.get("x_mitre_deprecated", False):
                continue
            rel_type = obj.get("relationship_type", "")
            src = mitre_id_map.get(obj.get("source_ref", ""), "")
            tgt = mitre_id_map.get(obj.get("target_ref", ""), "")
            if not src or not tgt:
                continue

            if rel_type == "uses" and src.startswith("G") and tgt.startswith("T"):
                con.execute("INSERT OR IGNORE INTO group_techniques VALUES (?,?)", (src, tgt))
                relationships_inserted += 1
            elif rel_type == "uses" and src.startswith("S") and tgt.startswith("T"):
                con.execute("INSERT OR IGNORE INTO software_techniques VALUES (?,?)", (src, tgt))
                relationships_inserted += 1
            elif rel_type == "mitigates" and tgt.startswith("T"):
                con.execute("INSERT OR IGNORE INTO technique_mitigations VALUES (?,?)", (tgt, src))
                relationships_inserted += 1

        # Meta
        attack_version = ""
        for obj in objects:
            if obj.get("type") == "x-mitre-collection":
                attack_version = obj.get("x_mitre_attack_spec_version", "")
                break
        con.execute("INSERT OR REPLACE INTO meta VALUES ('attack_version',?)", (attack_version,))
        con.execute("INSERT OR REPLACE INTO meta VALUES ('built_at', datetime('now'))")

    con.close()
    size_kb = DB_PATH.stat().st_size // 1024
    print(
        f"\n  attack.db built at {DB_PATH}\n"
        f"  {techniques_inserted} techniques, {groups_inserted} groups, "
        f"{software_inserted} software, {mitigations_inserted} mitigations\n"
        f"  {relationships_inserted} relationships  ·  {size_kb} KB"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build local ATT&CK SQLite database")
    parser.add_argument("--stix", help="Path to local enterprise-attack.json (skips download)")
    parser.add_argument("--version", help="ATT&CK version tag, e.g. 15.1")
    args = parser.parse_args()
    try:
        build(stix_path=args.stix, version=args.version)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
