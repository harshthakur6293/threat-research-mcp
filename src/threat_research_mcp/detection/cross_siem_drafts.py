"""Draft KQL (Microsoft Sentinel-style) and SPL from behavior text + technique context."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from threat_research_mcp.detection.technique_data_sources import data_sources_for_techniques


def parse_technique_ids_from_research(research: Dict[str, Any]) -> List[str]:
    """Extract technique IDs from research['attack'] JSON string or dict."""
    attack = research.get("attack")
    if attack is None:
        return []
    if isinstance(attack, str):
        try:
            data = json.loads(attack)
        except json.JSONDecodeError:
            return []
    elif isinstance(attack, dict):
        data = attack
    else:
        return []
    out: List[str] = []
    for t in data.get("techniques") or []:
        if isinstance(t, dict) and t.get("id"):
            out.append(str(t["id"]))
    return out


def sanitize_query_literal(text: str, *, max_len: int = 120) -> str:
    """Make a short fragment safe to embed in KQL/SPL string literals."""
    s = re.sub(r"[\r\n\t]+", " ", text or "").strip()
    s = s.replace("\\", "\\\\").replace('"', '\\"').replace("'", "\\'")
    if len(s) > max_len:
        s = s[: max_len - 1] + "…"
    return s or "suspicious"


def build_kql_process_draft(behavior_snippet: str, technique_ids: List[str]) -> str:
    """Sentinel `DeviceProcessEvents` style draft (Windows)."""
    frag = sanitize_query_literal(behavior_snippet)
    tech_note = ";".join(technique_ids[:12]) if technique_ids else "T1059.001"
    tech_esc = sanitize_query_literal(tech_note, max_len=200)
    return (
        "// Draft KQL — tune table/column names to your workspace (DeviceProcessEvents / SecurityEvent).\n"
        "DeviceProcessEvents\n"
        "| where TimeGenerated > ago(7d)\n"
        f'| where ProcessCommandLine has "{frag}" or InitiatingProcessCommandLine has "{frag}"\n'
        f'| extend MitreTechniqueHint = "{tech_esc}"\n'
        "| project TimeGenerated, DeviceName, AccountName, FolderPath, FileName, ProcessCommandLine, InitiatingProcessFileName, MitreTechniqueHint\n"
        "| take 500\n"
    )


def _spl_search_fragment(text: str, *, max_len: int = 100) -> str:
    s = re.sub(r"[\r\n]+", " ", text or "").strip()[:max_len]
    return s.replace("'", "''")


def build_spl_process_draft(behavior_snippet: str, technique_ids: List[str]) -> str:
    """Splunk process / Sysmon-style draft."""
    frag_spl = _spl_search_fragment(behavior_snippet)
    tech_comment = ";".join(technique_ids[:8]) if technique_ids else "T1059.001"
    return (
        "// Draft SPL — align index/sourcetype with your deployment (Sysmon EventCode=1 or Windows Security 4688).\n"
        "index=windows ((sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1) OR "
        "(sourcetype=WinEventLog:Security EventCode=4688))\n"
        f'| search process="*{frag_spl}*" OR process="*powershell*"\n'
        f'| eval threat_research_mcp_techniques="{tech_comment}"\n'
        "| head 500\n"
    )


def build_detection_sidecar(
    text: str,
    research: Dict[str, Any],
) -> Dict[str, Any]:
    """Sigma stays primary; add KQL/SPL drafts and MITRE data-source list."""
    technique_ids = parse_technique_ids_from_research(research)
    behavior = (text or "").strip()[:400]
    ds = data_sources_for_techniques(technique_ids)
    return {
        "technique_ids": technique_ids,
        "data_source_recommendations": ds,
        "kql": build_kql_process_draft(behavior, technique_ids),
        "spl": build_spl_process_draft(behavior, technique_ids),
    }
