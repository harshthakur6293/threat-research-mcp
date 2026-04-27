"""STIX 2.1 bundle parser — extract IOCs and ATT&CK techniques without external deps.

Supports STIX 2.0 and 2.1 bundles (JSON). Parses indicator patterns, attack-pattern
objects, malware objects, and threat-actor objects. No stix2 library required.
"""

from __future__ import annotations

import json
import re
from typing import Any


# ── STIX pattern extractors ───────────────────────────────────────────────────

_PATTERN_IPV4 = re.compile(r"ipv4-addr:value\s*=\s*'([^']+)'", re.IGNORECASE)
_PATTERN_DOMAIN = re.compile(r"domain-name:value\s*=\s*'([^']+)'", re.IGNORECASE)
_PATTERN_URL = re.compile(r"url:value\s*=\s*'([^']+)'", re.IGNORECASE)
_PATTERN_MD5 = re.compile(r"file:hashes\.'?MD5'?\s*=\s*'([a-fA-F0-9]{32})'", re.IGNORECASE)
_PATTERN_SHA1 = re.compile(r"file:hashes\.'?SHA-1'?\s*=\s*'([a-fA-F0-9]{40})'", re.IGNORECASE)
_PATTERN_SHA256 = re.compile(r"file:hashes\.'?SHA-256'?\s*=\s*'([a-fA-F0-9]{64})'", re.IGNORECASE)
_PATTERN_EMAIL = re.compile(r"email-addr:value\s*=\s*'([^']+)'", re.IGNORECASE)

# ATT&CK external reference source name
_ATTACK_SOURCE = "mitre-attack"


def _extract_attack_id(refs: list[dict]) -> str | None:
    for ref in refs:
        if ref.get("source_name") == _ATTACK_SOURCE:
            ext_id = ref.get("external_id", "")
            if re.match(r"T\d{4}", ext_id):
                return ext_id
    return None


def _parse_pattern(pattern: str) -> dict[str, list[str]]:
    return {
        "ips": _PATTERN_IPV4.findall(pattern),
        "domains": _PATTERN_DOMAIN.findall(pattern),
        "urls": _PATTERN_URL.findall(pattern),
        "hashes_md5": _PATTERN_MD5.findall(pattern),
        "hashes_sha1": _PATTERN_SHA1.findall(pattern),
        "hashes_sha256": _PATTERN_SHA256.findall(pattern),
        "emails": _PATTERN_EMAIL.findall(pattern),
    }


def _merge_iocs(base: dict, new: dict) -> None:
    for key, vals in new.items():
        base.setdefault(key, [])
        for v in vals:
            if v not in base[key]:
                base[key].append(v)


# ── Public API ────────────────────────────────────────────────────────────────


def parse_stix_bundle(bundle_json: str) -> str:
    """Parse a STIX 2.x bundle JSON string.

    Returns JSON with:
    - iocs: { ips, domains, urls, hashes, emails }
    - techniques: [ { id, name, tactic, description } ]
    - malware: [ { name, description } ]
    - threat_actors: [ { name, description } ]
    - indicator_count, object_count
    """
    try:
        bundle = json.loads(bundle_json)
    except json.JSONDecodeError as exc:
        return json.dumps({"error": f"Invalid JSON: {exc}"})

    objects: list[dict[str, Any]] = bundle.get("objects", [])
    if not objects and bundle.get("type") != "bundle":
        # Accept a bare list of STIX objects too
        objects = bundle if isinstance(bundle, list) else []

    iocs: dict[str, list[str]] = {
        "ips": [],
        "domains": [],
        "urls": [],
        "hashes": [],
        "emails": [],
    }
    techniques: list[dict] = []
    malware: list[dict] = []
    threat_actors: list[dict] = []
    seen_tids: set[str] = set()
    indicator_count = 0

    for obj in objects:
        obj_type = obj.get("type", "")

        if obj_type == "indicator":
            indicator_count += 1
            pattern = obj.get("pattern", "")
            extracted = _parse_pattern(pattern)
            all_hashes = (
                extracted.pop("hashes_md5", [])
                + extracted.pop("hashes_sha1", [])
                + extracted.pop("hashes_sha256", [])
            )
            extracted["hashes"] = all_hashes
            _merge_iocs(iocs, extracted)

        elif obj_type == "attack-pattern":
            refs = obj.get("external_references", [])
            tid = _extract_attack_id(refs)
            if tid and tid not in seen_tids:
                seen_tids.add(tid)
                kill_chain = obj.get("kill_chain_phases", [{}])
                tactic = kill_chain[0].get("phase_name", "") if kill_chain else ""
                techniques.append(
                    {
                        "id": tid,
                        "name": obj.get("name", ""),
                        "tactic": tactic,
                        "description": obj.get("description", "")[:300],
                        "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
                    }
                )

        elif obj_type == "malware":
            malware.append(
                {
                    "name": obj.get("name", ""),
                    "description": obj.get("description", "")[:300],
                    "malware_types": obj.get("malware_types", []),
                    "is_family": obj.get("is_family", False),
                }
            )

        elif obj_type == "threat-actor":
            threat_actors.append(
                {
                    "name": obj.get("name", ""),
                    "description": obj.get("description", "")[:300],
                    "aliases": obj.get("aliases", []),
                    "sophistication": obj.get("sophistication", ""),
                    "primary_motivation": obj.get("primary_motivation", ""),
                }
            )

    return json.dumps(
        {
            "iocs": iocs,
            "techniques": techniques,
            "malware": malware,
            "threat_actors": threat_actors,
            "indicator_count": indicator_count,
            "object_count": len(objects),
            "notes": "Parsed from STIX 2.x bundle. Pipe techniques into hunt_for_techniques for queries.",
        },
        indent=2,
    )


def stix_to_pipeline_text(bundle_json: str) -> str:
    """Convert a STIX bundle to a flat text blob suitable for run_pipeline_tool.

    Concatenates indicator descriptions, attack-pattern names, and malware names
    into a single string that the existing keyword-based pipeline can process.
    """
    try:
        bundle = json.loads(bundle_json)
    except json.JSONDecodeError as exc:
        return f"Error parsing STIX bundle: {exc}"

    objects = bundle.get("objects", [])
    lines: list[str] = []

    for obj in objects:
        name = obj.get("name", "")
        desc = obj.get("description", "")
        pattern = obj.get("pattern", "")

        if name:
            lines.append(name)
        if desc:
            lines.append(desc[:500])
        if pattern:
            lines.append(pattern)

        for ref in obj.get("external_references", []):
            if ref.get("description"):
                lines.append(ref["description"][:300])

    return "\n".join(lines)
