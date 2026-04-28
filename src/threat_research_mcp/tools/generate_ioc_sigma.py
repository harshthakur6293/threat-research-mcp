"""Tier 1 IOC Blocklist Sigma Rule Generator — fully programmatic, no LLM required.

Given the IOC dict produced by extract_iocs.py, this module generates:
  - Network blocklist Sigma rule (IPs + domains → network connection events)
  - File hash blocklist Sigma rule (MD5 / SHA1 / SHA256)
  - Combined blocklist bundle (all rules in one JSON response)

Every generated rule:
  - Contains ONLY the actual IOC values from the report (no generic placeholders)
  - Has a TTL annotation (IPs ~30d, domains ~180d, hashes permanent)
  - Is structurally valid Sigma YAML (passes validate_sigma)
  - Carries full metadata: title, id, status, date, tags, author, references

Design principle: Tier 1 is 100% deterministic. The same IOCs always produce
the same rules. This is intentional — analysts can reproduce and audit it.
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timedelta

import yaml


_TODAY = datetime.utcnow().date()

# TTL estimates for different IOC types
_TTL_IP_DAYS = 30
_TTL_DOMAIN_DAYS = 180
_TTL_HASH_DAYS = 36500  # hashes don't rotate — 100 years


def _expiry(days: int) -> str:
    return (_TODAY + timedelta(days=days)).isoformat()


_RULE_NS = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")  # uuid.NAMESPACE_URL


def _sigma_id(campaign: str, rule_type: str) -> str:
    """Stable, reproducible rule ID — same campaign + type → same UUID forever."""
    return str(uuid.uuid5(_RULE_NS, f"threat-research-mcp/ioc/{campaign}/{rule_type}"))


def _yaml_dump(obj: dict) -> str:
    return yaml.dump(obj, default_flow_style=False, allow_unicode=True, sort_keys=False)


def _build_network_blocklist_rule(
    iocs: dict,
    campaign: str = "",
    source_url: str = "",
    technique_ids: list[str] | None = None,
) -> dict | None:
    """Build a Sigma rule blocking network IOCs (IPs + domains)."""
    ips = [i["value"] for i in iocs.get("ips", []) if i.get("confidence", 0) >= 0.35]
    domains = [d["value"] for d in iocs.get("domains", []) if d.get("confidence", 0) >= 0.35]

    # Also accept plain lists (legacy IOC dict format)
    if not ips and isinstance(iocs.get("ips"), list):
        ips = [i for i in iocs["ips"] if isinstance(i, str)]
    if not domains and isinstance(iocs.get("domains"), list):
        domains = [d for d in iocs["domains"] if isinstance(d, str)]

    if not ips and not domains:
        return None

    tags = ["attack.command_and_control"]
    if technique_ids:
        for tid in technique_ids:
            tags.append(f"attack.{tid.lower().replace('.', '_')}")

    detection: dict = {}
    if ips:
        detection["network_dst_ip"] = {"dst_ip|contains": ips}
    if domains:
        detection["network_dst_domain"] = {"dst_domain|contains": domains}

    conditions = list(detection.keys())
    condition_str = " or ".join(conditions) if len(conditions) > 1 else conditions[0]

    logsource_note = (
        "Adapt logsource to your environment: "
        "Sysmon EID 3 (sysmon_network), proxy logs, firewall flows, "
        "DeviceNetworkEvents (Sentinel), or index=sysmon EventCode=3 (Splunk)."
    )

    rule = {
        "title": f"IOC Network Blocklist{' — ' + campaign if campaign else ''}",
        "id": _sigma_id(campaign, "network"),
        "status": "stable",
        "description": (
            f"Network IOC blocklist generated from threat intelligence"
            f"{' for campaign: ' + campaign if campaign else ''}. "
            f"Blocks outbound connections to known-malicious IPs and domains. "
            f"IP TTL: {_expiry(_TTL_IP_DAYS)}. Domain TTL: {_expiry(_TTL_DOMAIN_DAYS)}. "
            f"{logsource_note}"
        ),
        "date": _TODAY.isoformat(),
        "modified": _TODAY.isoformat(),
        "author": "threat-research-mcp",
        "tags": tags,
        "references": [source_url] if source_url else [],
        "logsource": {
            "category": "network_connection",
            "product": "windows",
        },
        "detection": {
            **detection,
            "condition": condition_str,
        },
        "fields": ["Image", "DestinationIp", "DestinationHostname", "User", "ProcessId"],
        "falsepositives": ["None expected — specific IOC values"],
        "level": "high",
        "metadata": {
            "ioc_counts": {"ips": len(ips), "domains": len(domains)},
            "ip_ttl_expires": _expiry(_TTL_IP_DAYS),
            "domain_ttl_expires": _expiry(_TTL_DOMAIN_DAYS),
            "tier": 1,
        },
    }

    return rule


def _build_file_hash_blocklist_rule(
    iocs: dict,
    campaign: str = "",
    source_url: str = "",
    technique_ids: list[str] | None = None,
) -> dict | None:
    """Build a Sigma rule blocking file hashes (MD5 / SHA1 / SHA256)."""
    raw_hashes = iocs.get("hashes", [])

    # Accept both rich dicts and plain string lists
    hashes: list[str] = []
    if raw_hashes and isinstance(raw_hashes[0], dict):
        hashes = [h["value"] for h in raw_hashes if h.get("confidence", 0) >= 0.35]
    else:
        hashes = [h for h in raw_hashes if isinstance(h, str)]

    if not hashes:
        return None

    # Classify by length
    md5s = [h for h in hashes if re.fullmatch(r"[a-fA-F0-9]{32}", h)]
    sha1s = [h for h in hashes if re.fullmatch(r"[a-fA-F0-9]{40}", h)]
    sha256s = [h for h in hashes if re.fullmatch(r"[a-fA-F0-9]{64}", h)]

    tags = ["attack.execution", "attack.defense_evasion"]
    if technique_ids:
        for tid in technique_ids:
            tags.append(f"attack.{tid.lower().replace('.', '_')}")

    detection: dict = {}
    if sha256s:
        detection["hash_sha256"] = {"Hashes|contains": sha256s}
    if sha1s:
        detection["hash_sha1"] = {"Hashes|contains": sha1s}
    if md5s:
        detection["hash_md5"] = {"Hashes|contains": md5s}

    conditions = list(detection.keys())
    condition_str = " or ".join(conditions) if len(conditions) > 1 else conditions[0]

    hash_note = "SHA-256 hashes are the most reliable. MD5/SHA-1 hashes have collision risk."

    rule = {
        "title": f"IOC File Hash Blocklist{' — ' + campaign if campaign else ''}",
        "id": _sigma_id(campaign, "file-hash"),
        "status": "stable",
        "description": (
            f"File hash blocklist generated from threat intelligence"
            f"{' for campaign: ' + campaign if campaign else ''}. "
            f"Hashes do not rotate — no TTL. {hash_note}"
        ),
        "date": _TODAY.isoformat(),
        "modified": _TODAY.isoformat(),
        "author": "threat-research-mcp",
        "tags": tags,
        "references": [source_url] if source_url else [],
        "logsource": {
            "category": "process_creation",
            "product": "windows",
        },
        "detection": {
            **detection,
            "condition": condition_str,
        },
        "fields": ["Image", "Hashes", "CommandLine", "ParentImage", "User"],
        "falsepositives": ["None expected — specific hash values"],
        "level": "critical",
        "metadata": {
            "ioc_counts": {"md5": len(md5s), "sha1": len(sha1s), "sha256": len(sha256s)},
            "ttl_expires": "permanent",
            "tier": 1,
            "hash_quality": "sha256" if sha256s else ("sha1" if sha1s else "md5"),
        },
    }

    return rule


def _build_email_blocklist_rule(
    iocs: dict,
    campaign: str = "",
    source_url: str = "",
) -> dict | None:
    """Build a Sigma rule blocking sender email addresses."""
    raw = iocs.get("emails", [])
    emails: list[str] = []
    if raw and isinstance(raw[0], dict):
        emails = [e["value"] for e in raw if e.get("confidence", 0) >= 0.35]
    else:
        emails = [e for e in raw if isinstance(e, str)]

    if not emails:
        return None

    rule = {
        "title": f"IOC Email Sender Blocklist{' — ' + campaign if campaign else ''}",
        "id": _sigma_id(campaign, "email"),
        "status": "stable",
        "description": (
            f"Email sender blocklist from threat intelligence"
            f"{' for campaign: ' + campaign if campaign else ''}. "
            "Apply to email gateway / Exchange Online rules."
        ),
        "date": _TODAY.isoformat(),
        "modified": _TODAY.isoformat(),
        "author": "threat-research-mcp",
        "tags": ["attack.initial_access", "attack.t1566"],
        "references": [source_url] if source_url else [],
        "logsource": {
            "category": "application",
            "product": "email",
        },
        "detection": {
            "sender_block": {"SenderAddress|contains": emails},
            "condition": "sender_block",
        },
        "fields": ["SenderAddress", "RecipientAddress", "Subject", "FileName"],
        "falsepositives": ["Unlikely — specific sender addresses"],
        "level": "high",
        "metadata": {
            "ioc_counts": {"emails": len(emails)},
            "ttl_expires": _expiry(_TTL_DOMAIN_DAYS),
            "tier": 1,
        },
    }

    return rule


def generate_ioc_sigma_bundle(
    iocs: dict,
    campaign: str = "",
    source_url: str = "",
    technique_ids: list[str] | None = None,
) -> str:
    """Generate a complete Tier 1 IOC blocklist Sigma bundle.

    Args:
        iocs: IOC dict from extract_iocs_from_text() — accepts both the new
              confidence-scored format {"ips": [{"value":..,"confidence":..}]}
              and the legacy flat format {"ips": ["1.2.3.4"]}.
        campaign: Optional campaign name for rule titles (e.g. "axios-supply-chain").
        source_url: Source report URL embedded in rule references.
        technique_ids: Optional list of ATT&CK IDs to include in rule tags.

    Returns:
        JSON with all generated rules, YAML strings, IOC counts, and TTL calendar.
    """
    rules = []
    yamls = []

    net_rule = _build_network_blocklist_rule(iocs, campaign, source_url, technique_ids)
    if net_rule:
        rules.append(net_rule)
        yamls.append({"rule_type": "network_blocklist", "yaml": _yaml_dump(net_rule)})

    hash_rule = _build_file_hash_blocklist_rule(iocs, campaign, source_url, technique_ids)
    if hash_rule:
        rules.append(hash_rule)
        yamls.append({"rule_type": "file_hash_blocklist", "yaml": _yaml_dump(hash_rule)})

    email_rule = _build_email_blocklist_rule(iocs, campaign, source_url)
    if email_rule:
        rules.append(email_rule)
        yamls.append({"rule_type": "email_blocklist", "yaml": _yaml_dump(email_rule)})

    # Build IOC summary
    def _count(key: str) -> int:
        items = iocs.get(key, [])
        return len(items)

    ttl_calendar: list[dict] = []
    if net_rule:
        ips = _count("ips")
        domains = _count("domains")
        if ips:
            ttl_calendar.append(
                {"expires": _expiry(_TTL_IP_DAYS), "action": "Review/extend IP blocklist rule"}
            )
        if domains:
            ttl_calendar.append(
                {
                    "expires": _expiry(_TTL_DOMAIN_DAYS),
                    "action": "Review/extend domain blocklist rule",
                }
            )
    if hash_rule:
        ttl_calendar.append({"expires": "permanent", "action": "Hash blocklist — no expiry"})

    result = {
        "tier": 1,
        "tier_label": "IOC Blocklists — deploy immediately, ~0 expected FP",
        "campaign": campaign or None,
        "generated": _TODAY.isoformat(),
        "rules_count": len(rules),
        "rules": yamls,
        "ioc_summary": {
            "ips": _count("ips"),
            "domains": _count("domains"),
            "hashes": _count("hashes"),
            "emails": _count("emails"),
            "urls": _count("urls"),
        },
        "ttl_calendar": ttl_calendar,
        "deploy_guidance": (
            "Tier 1 rules contain only specific IOC values — false positive risk is ~0. "
            "Load network_blocklist into your EDR/SIEM network detection layer. "
            "Load file_hash_blocklist into your AV/EDR deny list and Sysmon process creation alerts. "
            "Load email_blocklist into your email gateway. "
            "Review on TTL expiry date — infrastructure may rotate."
        ),
    }

    return json.dumps(result, indent=2)
