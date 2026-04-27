"""MISP integration — pull threat events, push generated Sigma rules back.

Requires environment variables:
  MISP_URL  — base URL of your MISP instance, e.g. https://misp.example.org
  MISP_KEY  — MISP automation key (User → My Profile → Auth key)

All calls use requests with SSL verification enabled by default.
Set MISP_VERIFY_SSL=false to disable (self-signed certs in lab environments).
"""

from __future__ import annotations

import json
import os
from typing import Any

import requests

_DEFAULT_TIMEOUT = 30


def _session() -> tuple[str, dict[str, str], bool]:
    url = os.environ.get("MISP_URL", "").rstrip("/")
    key = os.environ.get("MISP_KEY", "")
    verify = os.environ.get("MISP_VERIFY_SSL", "true").lower() not in ("false", "0", "no")
    if not url or not key:
        raise RuntimeError(
            "MISP_URL and MISP_KEY environment variables must be set. "
            "Find your key at MISP → My Profile → Auth key."
        )
    headers = {
        "Authorization": key,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    return url, headers, verify


def pull_misp_events(
    tags: str = "",
    limit: int = 10,
    threat_level: int | None = None,
) -> str:
    """Pull recent MISP events and return as pipeline-ready text + IOC list.

    Args:
        tags:          Comma-separated MISP tags to filter by, e.g. "tlp:red,APT28"
        limit:         Max number of events to fetch (default 10)
        threat_level:  1=High, 2=Medium, 3=Low, 4=Undefined

    Returns JSON with events, extracted text, and flat IOC lists.
    """
    try:
        url, headers, verify = _session()
    except RuntimeError as exc:
        return json.dumps({"error": str(exc)})

    payload: dict[str, Any] = {"returnFormat": "json", "limit": limit, "metadata": False}
    if tags:
        payload["tags"] = [t.strip() for t in tags.split(",") if t.strip()]
    if threat_level is not None:
        payload["threat_level_id"] = threat_level

    try:
        resp = requests.post(
            f"{url}/events/restSearch",
            headers=headers,
            json=payload,
            timeout=_DEFAULT_TIMEOUT,
            verify=verify,
        )
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as exc:
        return json.dumps({"error": f"MISP request failed: {exc}"})

    events = data.get("response", [])
    result_events = []
    pipeline_text_parts = []
    all_iocs: dict[str, list[str]] = {"ips": [], "domains": [], "hashes": [], "urls": []}

    for event_wrapper in events:
        event = event_wrapper.get("Event", event_wrapper)
        info = event.get("info", "")
        eid = event.get("id", "")
        date = event.get("date", "")
        attributes = event.get("Attribute", [])

        # Build pipeline text from event title + attribute values
        text_lines = [info]
        event_iocs: dict[str, list[str]] = {"ips": [], "domains": [], "hashes": [], "urls": []}

        for attr in attributes:
            attr_type = attr.get("type", "")
            value = attr.get("value", "")
            comment = attr.get("comment", "")

            if comment:
                text_lines.append(comment)
            text_lines.append(value)

            if attr_type in ("ip-dst", "ip-src", "ip-dst|port"):
                ip = value.split("|")[0]
                if ip not in all_iocs["ips"]:
                    all_iocs["ips"].append(ip)
                event_iocs["ips"].append(ip)
            elif attr_type in ("domain", "hostname"):
                if value not in all_iocs["domains"]:
                    all_iocs["domains"].append(value)
                event_iocs["domains"].append(value)
            elif attr_type in ("md5", "sha1", "sha256", "sha-256"):
                if value not in all_iocs["hashes"]:
                    all_iocs["hashes"].append(value)
                event_iocs["hashes"].append(value)
            elif attr_type == "url":
                if value not in all_iocs["urls"]:
                    all_iocs["urls"].append(value)
                event_iocs["urls"].append(value)

        result_events.append(
            {
                "id": eid,
                "date": date,
                "info": info,
                "iocs": event_iocs,
                "attribute_count": len(attributes),
            }
        )
        pipeline_text_parts.append("\n".join(text_lines))

    return json.dumps(
        {
            "events": result_events,
            "total": len(result_events),
            "all_iocs": all_iocs,
            "pipeline_text": "\n\n---\n\n".join(pipeline_text_parts),
            "note": "Pass pipeline_text to run_pipeline_tool for TTP mapping and detection generation.",
        },
        indent=2,
    )


def push_sigma_to_misp(
    event_id: str,
    sigma_yaml: str,
    technique_id: str = "",
    comment: str = "",
) -> str:
    """Push a Sigma rule as a MISP attribute to an existing event.

    Args:
        event_id:      MISP event ID to attach the attribute to.
        sigma_yaml:    Sigma rule YAML string.
        technique_id:  ATT&CK technique ID for tagging (optional).
        comment:       Free-text comment for the attribute (optional).

    Returns JSON with the created attribute ID or an error.
    """
    try:
        url, headers, verify = _session()
    except RuntimeError as exc:
        return json.dumps({"error": str(exc)})

    # MISP attribute type for YARA/Sigma rules
    attribute: dict[str, Any] = {
        "event_id": event_id,
        "type": "sigma",
        "category": "External analysis",
        "value": sigma_yaml,
        "comment": comment or f"Sigma rule generated by threat-research-mcp for {technique_id}",
        "to_ids": False,
        "distribution": 0,  # organisation only
    }

    if technique_id:
        attribute["Tag"] = [{"name": f"misp-galaxy:mitre-attack-pattern={technique_id}"}]

    try:
        resp = requests.post(
            f"{url}/attributes/add/{event_id}",
            headers=headers,
            json={"Attribute": attribute},
            timeout=_DEFAULT_TIMEOUT,
            verify=verify,
        )
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as exc:
        return json.dumps({"error": f"MISP push failed: {exc}"})

    attr_id = data.get("Attribute", {}).get("id", "unknown")
    return json.dumps(
        {
            "status": "success",
            "misp_event_id": event_id,
            "attribute_id": attr_id,
            "technique_id": technique_id,
            "note": f"Sigma rule attached to MISP event {event_id} as attribute {attr_id}.",
        },
        indent=2,
    )


def create_misp_event_from_pipeline(
    pipeline_result: str,
    distribution: int = 0,
    threat_level: int = 2,
    analysis: int = 1,
) -> str:
    """Create a new MISP event from run_pipeline_tool output.

    Args:
        pipeline_result: JSON string from run_pipeline_tool.
        distribution:    0=org, 1=community, 2=connected, 3=all.
        threat_level:    1=High, 2=Medium, 3=Low.
        analysis:        0=initial, 1=ongoing, 2=complete.

    Returns JSON with the new MISP event ID.
    """
    try:
        url, headers, verify = _session()
    except RuntimeError as exc:
        return json.dumps({"error": str(exc)})

    try:
        pipeline = json.loads(pipeline_result)
    except json.JSONDecodeError as exc:
        return json.dumps({"error": f"Invalid pipeline JSON: {exc}"})

    summary = pipeline.get("summary", {})
    iocs = pipeline.get("pipeline_stages", {}).get("iocs", {})
    techniques = (
        pipeline.get("pipeline_stages", {}).get("attack_techniques", {}).get("techniques", [])
    )

    info = f"threat-research-mcp: {summary.get('technique_count', 0)} techniques, {summary.get('ioc_count', 0)} IOCs"

    attributes = []
    for ip in iocs.get("ips", []):
        attributes.append(
            {"type": "ip-dst", "category": "Network activity", "value": ip, "to_ids": True}
        )
    for domain in iocs.get("domains", []):
        attributes.append(
            {"type": "domain", "category": "Network activity", "value": domain, "to_ids": True}
        )
    for h in iocs.get("hashes", []):
        h_type = "md5" if len(h) == 32 else "sha1" if len(h) == 40 else "sha256"
        attributes.append(
            {"type": h_type, "category": "Payload delivery", "value": h, "to_ids": True}
        )
    for url_val in iocs.get("urls", []):
        attributes.append(
            {"type": "url", "category": "External analysis", "value": url_val, "to_ids": False}
        )

    tags = []
    for tech in techniques:
        tags.append({"name": f"misp-galaxy:mitre-attack-pattern={tech['id']}"})

    event_payload: dict[str, Any] = {
        "Event": {
            "info": info,
            "distribution": distribution,
            "threat_level_id": threat_level,
            "analysis": analysis,
            "Attribute": attributes,
            "Tag": tags,
        }
    }

    try:
        resp = requests.post(
            f"{url}/events/add",
            headers=headers,
            json=event_payload,
            timeout=_DEFAULT_TIMEOUT,
            verify=verify,
        )
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as exc:
        return json.dumps({"error": f"MISP event creation failed: {exc}"})

    new_id = data.get("Event", {}).get("id", "unknown")
    return json.dumps(
        {
            "status": "success",
            "misp_event_id": new_id,
            "attributes_added": len(attributes),
            "techniques_tagged": len(techniques),
            "note": f"MISP event {new_id} created with {len(attributes)} IOC attributes and {len(techniques)} ATT&CK tags.",
        },
        indent=2,
    )
