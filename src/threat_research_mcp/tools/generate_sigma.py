"""MCP tool: generate Sigma detection rules from ATT&CK technique IDs or raw behavior text."""

from __future__ import annotations

import json

from threat_research_mcp.detection.generators.sigma import SigmaGenerator


_generator = SigmaGenerator()

# Technique ID → human name (covers most common techniques)
_TECHNIQUE_NAMES: dict[str, str] = {
    "T1059.001": "PowerShell",
    "T1059.003": "Windows Command Shell",
    "T1059.004": "Unix Shell",
    "T1059.005": "Visual Basic",
    "T1059.006": "Python",
    "T1059.007": "JavaScript",
    "T1003.001": "LSASS Memory Dumping",
    "T1003.003": "NTDS Credential Dumping",
    "T1071.001": "C2 over Web Protocols",
    "T1071.004": "C2 over DNS",
    "T1053.005": "Scheduled Task Persistence",
    "T1543.003": "Windows Service Creation",
    "T1547.001": "Registry Run Key Persistence",
    "T1505.003": "Web Shell",
    "T1566.001": "Spearphishing Attachment",
    "T1566.002": "Spearphishing Link",
    "T1190": "Exploit Public-Facing Application",
    "T1078": "Valid Accounts",
    "T1027": "Obfuscated Files",
    "T1055": "Process Injection",
    "T1055.001": "DLL Injection",
    "T1055.012": "Process Hollowing",
    "T1218.010": "Regsvr32 Proxy Execution",
    "T1218.011": "Rundll32 Proxy Execution",
    "T1021.001": "Remote Desktop Protocol",
    "T1021.002": "SMB Lateral Movement",
    "T1486": "Ransomware / Data Encryption",
    "T1110": "Brute Force",
    "T1110.003": "Password Spraying",
    "T1046": "Network Port Scanning",
    "T1082": "System Information Discovery",
    "T1087.002": "Domain Account Discovery",
    "T1482": "Domain Trust Discovery",
    "T1041": "Exfiltration Over C2",
    "T1567.002": "Exfiltration to Cloud Storage",
    "T1548.002": "UAC Bypass",
    "T1550.002": "Pass the Hash",
    "T1558.003": "Kerberoasting",
    "T1562.001": "Disable Security Tools",
    "T1562.002": "Disable Windows Event Logging",
    "T1036": "Masquerading",
}


def generate_sigma(title: str, behavior: str, logsource: str = "process_creation") -> str:
    """Generate a Sigma rule from a title + behavior description."""
    from threat_research_mcp.tools.validate_sigma import validate_sigma_json

    def _escape(value: str) -> str:
        return (value or "").replace("\\", "\\\\").replace('"', '\\"')[:400]

    rule_yaml = (
        f'title: "{_escape(title or "Untitled")}"\n'
        "status: experimental\n"
        "logsource:\n"
        f"  category: {logsource}\n"
        "  product: windows\n"
        "detection:\n"
        "  selection:\n"
        f'    CommandLine|contains: "{_escape(behavior)}"\n'
        "  condition: selection\n"
        "level: medium\n"
        "falsepositives:\n"
        "  - Legitimate administrative scripts\n"
    )

    validation = json.loads(validate_sigma_json(rule_yaml))
    return json.dumps(
        {
            "rule": rule_yaml,
            "valid": validation.get("valid", False),
            "errors": validation.get("errors", []),
        },
        indent=2,
    )


def generate_sigma_for_technique(technique_id: str, environment: str = "windows") -> str:
    """Return a curated Sigma rule for a specific ATT&CK technique ID.

    When no hand-written rule exists, returns a structured 'no_curated_rule' response
    with search links rather than generating a plausible-looking but useless stub.
    """
    tid = technique_id.upper()
    name = _TECHNIQUE_NAMES.get(tid, "Unknown Technique")
    rule = _generator.generate_from_technique(tid, name, environment)

    if rule is None:
        return json.dumps(
            {
                "technique_id": tid,
                "technique_name": name,
                "status": "no_curated_rule",
                "rule_yaml": "",
                "rule": None,
                "fallback": {
                    "sigmahq_search": f"https://github.com/SigmaHQ/sigma/search?q={tid}",
                    "elastic_rules": f"https://github.com/elastic/detection-rules/search?q={tid}",
                    "splunk_security_content": f"https://research.splunk.com/detections/?q={tid}",
                },
                "note": (
                    f"No production Sigma rule authored for {tid}. "
                    "Use the fallback links to find community rules, or call "
                    "generate_sigma() with a specific behavior description."
                ),
            },
            indent=2,
        )

    return json.dumps(
        {
            "technique_id": tid,
            "technique_name": name,
            "status": "curated",
            "rule_yaml": rule.to_yaml(),
            "rule": rule.to_dict(),
        },
        indent=2,
    )


def generate_sigma_bundle(technique_ids: list[str], environment: str = "windows") -> str:
    """Generate Sigma rules for a list of ATT&CK technique IDs.

    Includes both curated rules and no_curated_rule stubs so the caller
    can see exactly which techniques are covered vs. which need community rules.
    """
    results = []
    curated = 0
    for tid in technique_ids:
        parsed = json.loads(generate_sigma_for_technique(tid, environment))
        results.append(parsed)
        if parsed.get("status") == "curated":
            curated += 1
    return json.dumps(
        {
            "rules": results,
            "count": len(results),
            "curated_count": curated,
            "stub_count": len(results) - curated,
        },
        indent=2,
    )
