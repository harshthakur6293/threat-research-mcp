"""Standalone KQL, SPL, EQL (Elastic), and YARA detection rule generators.

Each SIEM generator pulls queries from the same hunt playbook used by
hunt_for_techniques, so the detection rules are consistent with the
hypotheses generated for each technique.

YARA generator produces file-scanning rules from either ATT&CK technique
templates or free-form string patterns supplied by the analyst.
"""

from __future__ import annotations

import json
import re
from typing import Any

from threat_research_mcp.tools.generate_hunt_hypothesis import _PLAYBOOK, _LOG_SOURCE_LABELS

# ── Technique name lookup (shared across all generators) ──────────────────────

_TECHNIQUE_NAMES: dict[str, str] = {tid: entry["name"] for tid, entry in _PLAYBOOK.items()}


# ── KQL (Microsoft Sentinel / Defender) ──────────────────────────────────────


def generate_kql_detection(technique_id: str) -> str:
    """Generate KQL detection rules for a specific ATT&CK technique.

    Pulls queries from the hunt playbook (same source as hunt_for_techniques).
    Returns one rule block per available log source, with Sentinel-style metadata.

    Returns JSON: {technique_id, technique_name, tactic, siem, rules: [...]}
    """
    tid = technique_id.strip().upper()
    entry = _PLAYBOOK.get(tid)

    if not entry:
        # Generic fallback using KQLGenerator for unknown techniques
        from threat_research_mcp.detection.generators.kql import KQLGenerator

        gen = KQLGenerator()
        rule = gen.generate_from_technique(tid, tid)
        return json.dumps(
            {
                "technique_id": tid,
                "technique_name": tid,
                "tactic": "unknown",
                "siem": "KQL (Microsoft Sentinel)",
                "rules": [rule.to_dict()],
                "note": f"Technique {tid} not in playbook — generic rule generated.",
            },
            indent=2,
        )

    rules: list[dict[str, Any]] = []
    for src_key, src in entry["log_sources"].items():
        kql = src.get("kql", "")
        if not kql:
            continue
        rules.append(
            {
                "log_source_key": src_key,
                "log_source": src["name"],
                "hypothesis": src["hypothesis"],
                "query": kql,
                "sentinel_rule": {
                    "displayName": f"[{tid}] {entry['name']} — {src['name']}",
                    "description": src["hypothesis"],
                    "severity": _severity_for_tactic(entry["tactic"]),
                    "query": kql,
                    "queryFrequency": "PT5M",
                    "queryPeriod": "PT5M",
                    "triggerOperator": "GreaterThan",
                    "triggerThreshold": 0,
                    "tactics": [_tactic_sentinel(entry["tactic"])],
                    "techniques": [tid],
                },
            }
        )

    return json.dumps(
        {
            "technique_id": tid,
            "technique_name": entry["name"],
            "tactic": entry["tactic"],
            "siem": "KQL (Microsoft Sentinel)",
            "rules": rules,
        },
        indent=2,
    )


# ── SPL (Splunk) ──────────────────────────────────────────────────────────────


def generate_spl_detection(technique_id: str) -> str:
    """Generate SPL detection searches for a specific ATT&CK technique.

    Pulls queries from the hunt playbook. Returns one alert definition
    per available log source in Splunk Saved Search format.

    Returns JSON: {technique_id, technique_name, tactic, siem, rules: [...]}
    """
    tid = technique_id.strip().upper()
    entry = _PLAYBOOK.get(tid)

    if not entry:
        from threat_research_mcp.detection.generators.spl import SPLGenerator

        gen = SPLGenerator()
        rule = gen.generate_from_technique(tid, tid)
        return json.dumps(
            {
                "technique_id": tid,
                "technique_name": tid,
                "tactic": "unknown",
                "siem": "SPL (Splunk)",
                "rules": [rule.to_dict()],
                "note": f"Technique {tid} not in playbook — generic rule generated.",
            },
            indent=2,
        )

    rules: list[dict[str, Any]] = []
    for src_key, src in entry["log_sources"].items():
        spl = src.get("splunk", "")
        if not spl:
            continue
        severity = _severity_for_tactic(entry["tactic"]).lower()
        rules.append(
            {
                "log_source_key": src_key,
                "log_source": src["name"],
                "hypothesis": src["hypothesis"],
                "search": spl,
                "splunk_alert": {
                    "name": f"[{tid}] {entry['name']} — {src['name']}",
                    "description": src["hypothesis"],
                    "search": spl,
                    "earliest_time": "-5m",
                    "latest_time": "now",
                    "cron_schedule": "*/5 * * * *",
                    "severity": severity,
                    "mitre_attack": [tid],
                    "recommended_actions": [
                        f"Review matching events for {entry['name']} indicators.",
                        "Correlate with enrichment data (enrich_ioc_tool).",
                        "Escalate if confirmed malicious.",
                    ],
                },
            }
        )

    return json.dumps(
        {
            "technique_id": tid,
            "technique_name": entry["name"],
            "tactic": entry["tactic"],
            "siem": "SPL (Splunk)",
            "rules": rules,
        },
        indent=2,
    )


# ── EQL / Elastic ─────────────────────────────────────────────────────────────


def generate_eql_detection(technique_id: str) -> str:
    """Generate Elastic detection rules for a specific ATT&CK technique.

    Pulls queries from the hunt playbook and wraps them in Elastic Security
    rule format (compatible with Kibana Detection Engine).

    Returns JSON: {technique_id, technique_name, tactic, siem, rules: [...]}
    """
    tid = technique_id.strip().upper()
    entry = _PLAYBOOK.get(tid)

    if not entry:
        from threat_research_mcp.detection.generators.eql import EQLGenerator

        gen = EQLGenerator()
        rule = gen.generate_from_technique(tid, tid)
        return json.dumps(
            {
                "technique_id": tid,
                "technique_name": tid,
                "tactic": "unknown",
                "siem": "Elastic Security (EQL/Lucene)",
                "rules": [rule.to_dict()],
                "note": f"Technique {tid} not in playbook — generic rule generated.",
            },
            indent=2,
        )

    rules: list[dict[str, Any]] = []
    for src_key, src in entry["log_sources"].items():
        elastic = src.get("elastic", "")
        if not elastic:
            continue
        risk_score = _risk_score_for_tactic(entry["tactic"])
        rules.append(
            {
                "log_source_key": src_key,
                "log_source": src["name"],
                "hypothesis": src["hypothesis"],
                "query": elastic,
                "elastic_rule": {
                    "name": f"[{tid}] {entry['name']} — {src['name']}",
                    "description": src["hypothesis"],
                    "severity": _severity_for_tactic(entry["tactic"]).lower(),
                    "risk_score": risk_score,
                    "query": elastic,
                    "rule_type": "query",
                    "language": "lucene",
                    "index": ["winlogbeat-*", "logs-endpoint.events.*", "logs-*"],
                    "interval": "5m",
                    "from": "now-6m",
                    "max_signals": 100,
                    "threat": [
                        {
                            "framework": "MITRE ATT&CK",
                            "tactic": {
                                "id": _tactic_id(entry["tactic"]),
                                "name": entry["tactic"].replace("-", " ").title(),
                                "reference": f"https://attack.mitre.org/tactics/{_tactic_id(entry['tactic'])}/",
                            },
                            "technique": [
                                {
                                    "id": tid,
                                    "name": entry["name"],
                                    "reference": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
                                }
                            ],
                        }
                    ],
                    "tags": [
                        "Domain: Endpoint",
                        f"Tactic: {entry['tactic'].replace('-', ' ').title()}",
                        f"Technique: {tid}",
                    ],
                },
            }
        )

    return json.dumps(
        {
            "technique_id": tid,
            "technique_name": entry["name"],
            "tactic": entry["tactic"],
            "siem": "Elastic Security (EQL/Lucene)",
            "rules": rules,
        },
        indent=2,
    )


# ── YARA ──────────────────────────────────────────────────────────────────────

# Per-technique YARA templates: list of (var_name, string_type, value)
# Types: "text" | "hex" | "regex"
_YARA_TEMPLATES: dict[str, dict[str, Any]] = {
    "T1059.001": {
        "rule_name": "PowerShell_Suspicious_Execution",
        "description": "Detects files/scripts with PowerShell encoded command or download cradle patterns",
        "strings": [
            ("$enc1", "text", "-EncodedCommand"),
            ("$enc2", "text", "-enc "),
            ("$dl1", "text", "DownloadString("),
            ("$dl2", "text", "Net.WebClient"),
            ("$iex1", "text", "IEX("),
            ("$iex2", "text", "Invoke-Expression"),
            ("$b64", "text", "FromBase64String"),
        ],
        "condition": "any of them",
        "tags": ["PowerShell", "T1059.001", "Execution"],
    },
    "T1003.001": {
        "rule_name": "LSASS_Credential_Dumping",
        "description": "Detects tools and techniques used for LSASS memory credential dumping",
        "strings": [
            ("$mimikatz1", "text", "sekurlsa::"),
            ("$mimikatz2", "text", "lsadump::"),
            ("$mimikatz3", "text", "mimikatz"),
            ("$minidump1", "text", "MiniDumpWriteDump"),
            ("$minidump2", "text", "comsvcs.dll"),
            ("$procdump", "text", "-ma lsass"),
        ],
        "condition": "any of them",
        "tags": ["CredentialAccess", "T1003.001", "Mimikatz"],
    },
    "T1055": {
        "rule_name": "Process_Injection_Indicators",
        "description": "Detects common process injection API call sequences in executables",
        "strings": [
            ("$va", "text", "VirtualAllocEx"),
            ("$wpm", "text", "WriteProcessMemory"),
            ("$crt", "text", "CreateRemoteThread"),
            ("$nqat", "text", "NtQueueApcThread"),
            ("$op", "text", "OpenProcess"),
        ],
        "condition": "3 of them",
        "tags": ["DefenseEvasion", "T1055", "Injection"],
    },
    "T1027": {
        "rule_name": "Obfuscation_Patterns",
        "description": "Detects common obfuscation techniques in scripts and executables",
        "strings": [
            ("$xor1", "text", "XOR"),
            ("$b64_1", "text", "base64_decode"),
            ("$b64_2", "text", "FromBase64String"),
            ("$chr1", "text", "Chr("),
            ("$concat1", "text", "[char]"),
            ("$bxor", "text", "-bxor"),
        ],
        "condition": "2 of them",
        "tags": ["DefenseEvasion", "T1027", "Obfuscation"],
    },
    "T1486": {
        "rule_name": "Ransomware_Indicators",
        "description": "Detects common ransomware strings: ransom notes, encryption API patterns, file extension targeting",
        "strings": [
            ("$ransom1", "text", "YOUR FILES HAVE BEEN ENCRYPTED"),
            ("$ransom2", "text", "your files are encrypted"),
            ("$ransom3", "text", "send bitcoin"),
            ("$ransom4", "text", "decrypt"),
            ("$crypt1", "text", "CryptEncrypt"),
            ("$crypt2", "text", "CryptoAPI"),
            ("$ext1", "text", ".encrypted"),
            ("$ext2", "text", ".locked"),
        ],
        "condition": "2 of ($ransom*) or any of ($crypt*) or 2 of ($ext*)",
        "tags": ["Impact", "T1486", "Ransomware"],
    },
    "T1505.003": {
        "rule_name": "Web_Shell_Indicators",
        "description": "Detects common web shell patterns in server-side scripts",
        "strings": [
            ("$php1", "text", "eval($_POST"),
            ("$php2", "text", "eval($_GET"),
            ("$php3", "text", "system($_"),
            ("$php4", "text", "passthru($_"),
            ("$php5", "text", "shell_exec($_"),
            ("$aspx1", "text", 'Request["cmd"]'),
            ("$aspx2", "text", "Response.Write(shell"),
            ("$jsp1", "text", "Runtime.getRuntime().exec("),
        ],
        "condition": "any of them",
        "tags": ["Persistence", "T1505.003", "WebShell"],
    },
    "T1566.001": {
        "rule_name": "Phishing_Macro_Indicators",
        "description": "Detects Office macro and phishing document patterns",
        "strings": [
            ("$macro1", "text", "AutoOpen"),
            ("$macro2", "text", "Document_Open"),
            ("$macro3", "text", "Shell("),
            ("$dde1", "text", "DDEAUTO"),
            ("$vba1", "text", 'CreateObject("WScript.Shell")'),
            ("$vba2", "text", 'CreateObject("Shell.Application")'),
        ],
        "condition": "any of them",
        "tags": ["InitialAccess", "T1566.001", "Phishing"],
    },
    "T1071.001": {
        "rule_name": "C2_HTTP_Beacon_Indicators",
        "description": "Detects common C2 framework strings used in HTTP-based command and control",
        "strings": [
            ("$cs1", "text", "beacon.dll"),
            ("$cs2", "text", "Cobalt Strike"),
            ("$sliver1", "text", "sliver-implant"),
            ("$empire1", "text", "PowerShell Empire"),
            ("$ua1", "text", "Mozilla/5.0 (compatible; MSIE 9.0"),
        ],
        "condition": "any of them",
        "tags": ["CommandAndControl", "T1071.001", "C2"],
    },
    "T1547.001": {
        "rule_name": "Registry_Run_Key_Persistence",
        "description": "Detects suspicious registry persistence strings in executables/scripts",
        "strings": [
            ("$run1", "text", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
            ("$run2", "text", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
            ("$reg1", "text", "reg add"),
            ("$reg2", "text", "RegSetValueEx"),
        ],
        "condition": "any of them",
        "tags": ["Persistence", "T1547.001", "Registry"],
    },
    "T1053.005": {
        "rule_name": "Scheduled_Task_Abuse",
        "description": "Detects scheduled task creation patterns in scripts and executables",
        "strings": [
            ("$schtasks1", "text", "schtasks /create"),
            ("$schtasks2", "text", "ITaskService"),
            ("$schtasks3", "text", "TaskScheduler"),
            ("$at1", "text", "at.exe /create"),
        ],
        "condition": "any of them",
        "tags": ["Persistence", "T1053.005", "ScheduledTask"],
    },
}


def generate_yara_for_technique(technique_id: str) -> str:
    """Generate a YARA rule for a specific ATT&CK technique.

    Returns a YARA rule string ready to save as a .yar file.
    Returns JSON: {technique_id, technique_name, rule_name, yara_rule, covered}
    """
    tid = technique_id.strip().upper()
    template = _YARA_TEMPLATES.get(tid)

    if not template:
        technique_name = _TECHNIQUE_NAMES.get(tid, tid)
        return json.dumps(
            {
                "technique_id": tid,
                "technique_name": technique_name,
                "covered": False,
                "yara_rule": None,
                "note": (
                    f"No YARA template for {tid}. Use generate_yara_rule to create one "
                    f"from custom strings, or generate_sigma_rule for log-based detection."
                ),
            },
            indent=2,
        )

    rule_text = _build_yara_rule(
        rule_name=template["rule_name"],
        description=template["description"],
        technique_id=tid,
        strings=template["strings"],
        condition=template["condition"],
        tags=template.get("tags", []),
    )

    return json.dumps(
        {
            "technique_id": tid,
            "technique_name": _TECHNIQUE_NAMES.get(tid, tid),
            "rule_name": template["rule_name"],
            "covered": True,
            "yara_rule": rule_text,
        },
        indent=2,
    )


def generate_yara_rule(rule_name: str, strings_csv: str, condition: str = "any of them") -> str:
    """Generate a YARA rule from free-form string patterns.

    Use this to build IOC-based YARA rules from strings found in malware samples,
    threat reports, or IOC lists.

    Args:
        rule_name: Alphanumeric rule name (spaces replaced with underscores)
        strings_csv: Comma-separated strings to search for in files
        condition: YARA condition expression (default: "any of them")

    Returns JSON: {rule_name, yara_rule, string_count}
    """
    safe_name = re.sub(r"[^a-zA-Z0-9_]", "_", rule_name.strip())
    raw_strings = [s.strip() for s in strings_csv.split(",") if s.strip()]
    if not raw_strings:
        return json.dumps(
            {"error": "No strings provided — strings_csv must be a comma-separated list."}, indent=2
        )

    string_defs = [(f"$s{i}", "text", s) for i, s in enumerate(raw_strings)]
    rule_text = _build_yara_rule(
        rule_name=safe_name,
        description=f"Custom IOC rule: {rule_name}",
        technique_id="",
        strings=string_defs,
        condition=condition,
        tags=["custom"],
    )

    return json.dumps(
        {
            "rule_name": safe_name,
            "string_count": len(raw_strings),
            "yara_rule": rule_text,
        },
        indent=2,
    )


def _build_yara_rule(
    rule_name: str,
    description: str,
    technique_id: str,
    strings: list[tuple[str, str, str]],
    condition: str,
    tags: list[str],
) -> str:
    """Build a YARA rule string from components."""
    meta_lines = [
        f'        description = "{description}"',
        '        author = "threat-research-mcp"',
    ]
    if technique_id:
        meta_lines.append(f'        mitre_technique = "{technique_id}"')
    if tags:
        meta_lines.append(f'        tags = "{", ".join(tags)}"')

    string_lines = []
    for var, stype, value in strings:
        if stype == "hex":
            string_lines.append(f"        {var} = {{{value}}}")
        elif stype == "regex":
            string_lines.append(f"        {var} = /{value}/")
        else:
            escaped = value.replace("\\", "\\\\").replace('"', '\\"')
            string_lines.append(f'        {var} = "{escaped}" ascii wide nocase')

    lines = [
        f"rule {rule_name}",
        "{",
        "    meta:",
        *[f"    {ln.lstrip()}" if ln.startswith("    ") else ln for ln in meta_lines],
        "    strings:",
        *[f"    {ln.lstrip()}" if ln.startswith("    ") else ln for ln in string_lines],
        "    condition:",
        f"        {condition}",
        "}",
    ]
    return "\n".join(lines)


# ── Log Source Catalog ────────────────────────────────────────────────────────


def list_log_sources() -> str:
    """Return the catalog of all log source keys available in the hunt playbook.

    Use these keys with hunt_for_techniques(log_sources=...) to filter
    hypotheses and queries to your actual SIEM environment.

    Returns JSON with log_sources list and a per-key technique coverage count.
    """
    coverage: dict[str, dict[str, Any]] = {}

    for src_key, label in _LOG_SOURCE_LABELS.items():
        coverage[src_key] = {
            "key": src_key,
            "label": label,
            "techniques": [],
        }

    for tid, entry in _PLAYBOOK.items():
        for src_key in entry["log_sources"]:
            if src_key in coverage:
                coverage[src_key]["techniques"].append(
                    {
                        "id": tid,
                        "name": entry["name"],
                        "tactic": entry["tactic"],
                    }
                )

    log_sources = sorted(coverage.values(), key=lambda x: -len(x["techniques"]))

    # Build environment presets
    presets = {
        "windows_sysmon": [
            "sysmon_process",
            "sysmon_process_access",
            "sysmon_registry",
            "sysmon_file",
            "sysmon_create_remote_thread",
            "script_block_logging",
        ],
        "windows_events": [
            "windows_event_4624",
            "windows_event_4625",
            "windows_event_4698",
            "windows_event_4769",
            "windows_event_7045",
        ],
        "network": ["proxy_logs", "dns_logs", "firewall_logs"],
        "perimeter": ["email_gateway", "web_server_logs"],
        "edr": ["windows_defender"],
    }

    return json.dumps(
        {
            "log_sources": log_sources,
            "total_sources": len(log_sources),
            "environment_presets": {
                name: {"log_source_keys": keys, "description": _preset_description(name)}
                for name, keys in presets.items()
            },
            "usage": (
                "Pass log_source_keys to hunt_for_techniques(log_sources=...) or "
                "run_pipeline(log_sources=...) to filter results to your environment. "
                "Example: 'sysmon_process,script_block_logging,dns_logs'"
            ),
        },
        indent=2,
    )


def _preset_description(name: str) -> str:
    return {
        "windows_sysmon": "Full Sysmon deployment (EID 1,8,10,11,13) + PowerShell Script Block Logging",
        "windows_events": "Windows Security + System event logs (no Sysmon required)",
        "network": "Web proxy, DNS, and firewall/flow logs",
        "perimeter": "Email gateway and web server / WAF logs",
        "edr": "Microsoft Defender for Endpoint / EDR telemetry",
    }.get(name, name)


# ── Helpers ───────────────────────────────────────────────────────────────────


def _severity_for_tactic(tactic: str) -> str:
    return {
        "impact": "High",
        "credential-access": "High",
        "initial-access": "Medium",
        "lateral-movement": "High",
        "exfiltration": "High",
        "command-and-control": "Medium",
        "execution": "Medium",
        "persistence": "Medium",
        "defense-evasion": "Medium",
        "discovery": "Low",
    }.get(tactic, "Medium")


def _risk_score_for_tactic(tactic: str) -> int:
    return {
        "impact": 85,
        "credential-access": 80,
        "initial-access": 63,
        "lateral-movement": 75,
        "exfiltration": 77,
        "command-and-control": 55,
        "execution": 55,
        "persistence": 47,
        "defense-evasion": 47,
        "discovery": 25,
    }.get(tactic, 47)


def _tactic_sentinel(tactic: str) -> str:
    return {
        "initial-access": "InitialAccess",
        "execution": "Execution",
        "persistence": "Persistence",
        "privilege-escalation": "PrivilegeEscalation",
        "defense-evasion": "DefenseEvasion",
        "credential-access": "CredentialAccess",
        "discovery": "Discovery",
        "lateral-movement": "LateralMovement",
        "collection": "Collection",
        "command-and-control": "CommandAndControl",
        "exfiltration": "Exfiltration",
        "impact": "Impact",
    }.get(tactic, "Unknown")


def _tactic_id(tactic: str) -> str:
    return {
        "initial-access": "TA0001",
        "execution": "TA0002",
        "persistence": "TA0003",
        "privilege-escalation": "TA0004",
        "defense-evasion": "TA0005",
        "credential-access": "TA0006",
        "discovery": "TA0007",
        "lateral-movement": "TA0008",
        "collection": "TA0009",
        "command-and-control": "TA0011",
        "exfiltration": "TA0010",
        "impact": "TA0040",
    }.get(tactic, "TA0000")
