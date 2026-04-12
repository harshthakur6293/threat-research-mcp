"""Curated MITRE ATT&CK data-source strings for common techniques (defensive mapping).

Source of truth is the public ATT&CK framework; this table is a compact offline subset
so detection bundles can populate `data_source_recommendations` without network calls.
Expand over time or replace with STIX-backed lookup later.
"""

from __future__ import annotations

from typing import Dict, List

# Technique ID -> list of "Data Source: Data Component" style strings
MITRE_DATA_SOURCES_BY_TECHNIQUE: Dict[str, List[str]] = {
    "T1059.001": [
        "Command: Command Execution",
        "Process: Process Creation",
        "Script: Script Execution",
    ],
    "T1059.003": [
        "Command: Command Execution",
        "Process: Process Creation",
    ],
    "T1059.007": [
        "Command: Command Execution",
        "Script: Script Execution",
    ],
    "T1566.001": [
        "Application Log: Application Log Content",
        "Email: Email Content",
        "File: File Creation",
        "Process: Process Creation",
    ],
    "T1053.005": [
        "Command: Command Execution",
        "File: File Modification",
        "Process: Process Creation",
        "Scheduled Job: Scheduled Job Creation",
    ],
    "T1105": [
        "Network Traffic: Network Connection Creation",
        "Process: Process Creation",
        "File: File Creation",
    ],
    "T1003.001": [
        "Process: OS API Execution",
        "Process: Process Access",
        "Command: Command Execution",
    ],
    "T1021.001": [
        "Logon Session: Logon Session Metadata",
        "Network Traffic: Network Connection Creation",
        "Process: Process Creation",
    ],
    "T1547.001": [
        "Command: Command Execution",
        "File: File Modification",
        "Process: Process Creation",
        "Windows Registry: Windows Registry Key Creation",
    ],
    "T1071.004": [
        "Network Traffic: Network Traffic Content",
        "Network Traffic: Network Connection Creation",
    ],
}


def data_sources_for_techniques(technique_ids: List[str]) -> List[str]:
    """Return merged, de-duplicated data source strings for the given technique IDs."""
    seen: List[str] = []
    for tid in technique_ids:
        key = tid.strip().upper()
        if not key.startswith("T"):
            continue
        for row in MITRE_DATA_SOURCES_BY_TECHNIQUE.get(key, []):
            if row not in seen:
                seen.append(row)
    return seen
