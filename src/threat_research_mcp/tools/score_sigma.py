"""Sigma rule quality scorer — rate rules on specificity, coverage, and FP risk.

Scores are heuristic, not authoritative. They give analysts a quick triage signal
to prioritise which rules to tune first.
"""

from __future__ import annotations

import json
import re
from typing import Any

# Patterns that indicate high specificity (low FP risk)
_HIGH_SPECIFICITY = [
    r"\b(?:md5|sha1|sha256|sha-256)\s*[=|]",  # hash comparisons
    r"[a-fA-F0-9]{32,64}",  # actual hash values
    r"\b(?:C2|beacon|cobalt.?strike|mimikatz|meterpreter)\b",
    r"EventID\s*(?:in|==|=)\s*[\d,\[\]]+",  # specific event IDs
    r"process\.name\s*(?:in|==|:)\s*[\w\"'\[\]]+",
    r"CommandLine\s*(?:contains|has(?:_any)?|matches)",
    r"TargetImage|SourceImage|ParentImage",
]

# Patterns that broaden scope (raise FP risk)
_BROAD_PATTERNS = [
    r"\*\s*(?:OR|\|)\s*\*",  # wildcard OR wildcard
    r"count\(\)\s*>\s*[1-9]\d{3}",  # very high count thresholds
    r"\bAND NOT\b.*\bAND NOT\b",  # multiple exclusions (complex logic)
    r"index=\*",  # wildcard index
    r"source\s*=\s*\*",
]

# Log sources with broad coverage (good)
_WIDE_COVERAGE_SOURCES = {
    "windows/process_creation",
    "windows/sysmon/sysmon",
    "proxy",
    "dns",
    "firewall",
    "webserver",
    "cloud/aws/cloudtrail",
    "cloud/gcp",
    "cloud/azure/activitylogs",
    "cloud/kubernetes/audit",
    "cloud/container/docker",
    "macos/process_creation",
    "macos/file_event",
}

# Suspicious terms that indicate high-value detection (increases score)
_HIGH_VALUE_TERMS = [
    "lsass",
    "mimikatz",
    "cobalt strike",
    "encoded",
    "base64",
    "reflective",
    "process injection",
    "credential dump",
    "TCC.db",
    "osascript",
    "launchd",
    "telegram bot",
]


def _count_matches(text: str, patterns: list[str]) -> int:
    count = 0
    for pat in patterns:
        if re.search(pat, text, re.IGNORECASE):
            count += 1
    return count


def score_sigma_rule(sigma_yaml: str) -> str:
    """Score a Sigma rule YAML string on three dimensions.

    Returns JSON:
    {
      "specificity": 1-5,   # how targeted the detection is
      "coverage":    1-5,   # how many log sources / environments it covers
      "fp_risk":     1-5,   # 1 = low risk, 5 = high false-positive risk
      "overall":     1-5,   # weighted composite
      "rationale":   [str]  # list of observations driving the score
    }
    """
    text = sigma_yaml or ""
    rationale: list[str] = []

    # ── Specificity (1-5) ─────────────────────────────────────────────────────
    spec_hits = _count_matches(text, _HIGH_SPECIFICITY)
    high_val = sum(1 for t in _HIGH_VALUE_TERMS if t.lower() in text.lower())
    specificity = min(5, 1 + spec_hits + (1 if high_val >= 2 else 0))

    if spec_hits >= 3:
        rationale.append(f"High specificity: {spec_hits} precision indicators found.")
    elif spec_hits == 0:
        rationale.append(
            "Low specificity: no precise indicators (hashes, event IDs, process names)."
        )

    # ── Coverage (1-5) ────────────────────────────────────────────────────────
    logsource_matches = sum(1 for src in _WIDE_COVERAGE_SOURCES if src in text)
    # Count distinct SIEM query blocks (rough proxy for coverage breadth)
    siem_count = sum(1 for kw in ["splunk:", "kql:", "elastic:"] if kw in text.lower())
    coverage = min(5, 1 + logsource_matches + siem_count)

    if siem_count >= 3:
        rationale.append("Good coverage: queries for Splunk, KQL, and Elastic present.")
    elif siem_count == 0:
        rationale.append("Limited coverage: no SIEM-specific queries found.")

    # ── FP risk (1 = low, 5 = high) ──────────────────────────────────────────
    broad_hits = _count_matches(text, _BROAD_PATTERNS)
    # Detect missing exclusions (e.g., no 'NOT' or 'filter' clauses)
    has_exclusion = bool(re.search(r"\b(NOT|filter|exclude|whitelist)\b", text, re.IGNORECASE))
    fp_risk = min(5, 1 + broad_hits + (0 if has_exclusion else 1) + (0 if spec_hits > 1 else 1))

    if broad_hits > 0:
        rationale.append(f"FP risk elevated: {broad_hits} broad pattern(s) detected.")
    if not has_exclusion:
        rationale.append("No exclusion clauses found — consider adding noise filters.")

    # ── Overall (weighted: spec 40%, coverage 30%, FP 30%) ───────────────────
    # FP risk is inverted (low risk = high score)
    fp_score = 6 - fp_risk  # convert to positive scale
    overall = round(specificity * 0.4 + coverage * 0.3 + fp_score * 0.3)
    overall = max(1, min(5, overall))

    if overall >= 4:
        rationale.append("Overall: solid rule — consider submitting to SigmaHQ.")
    elif overall <= 2:
        rationale.append("Overall: needs tuning before production use.")

    return json.dumps(
        {
            "specificity": specificity,
            "coverage": coverage,
            "fp_risk": fp_risk,
            "overall": overall,
            "scale": "1 (low) → 5 (high); fp_risk: 1 (safe) → 5 (noisy)",
            "rationale": rationale,
        },
        indent=2,
    )


def score_sigma_from_technique(technique_id: str) -> str:
    """Score the built-in Sigma rule for a technique from the generate_sigma tool."""
    from threat_research_mcp.tools.generate_sigma import generate_sigma_for_technique

    sigma_yaml = generate_sigma_for_technique(technique_id)
    result = json.loads(score_sigma_rule(sigma_yaml))
    result["technique_id"] = technique_id.upper()
    return json.dumps(result, indent=2)


def get_atomic_tests(technique_id: str) -> str:
    """Return Atomic Red Team test IDs for a given ATT&CK technique.

    Loads from playbook/atomic_tests.yaml at repo root.
    Returns JSON with test IDs and a link to the ART repository.
    """
    import yaml
    from pathlib import Path

    # Search for playbook dir: repo root first, then package-relative
    candidates = [
        Path(__file__).parent.parent.parent.parent / "playbook",
        Path(__file__).parent.parent / "playbook",
    ]
    playbook_dir = next((p for p in candidates if p.exists()), None)

    if not playbook_dir:
        return json.dumps({"error": "playbook/ directory not found", "technique_id": technique_id})

    atomic_file = playbook_dir / "atomic_tests.yaml"
    if not atomic_file.exists():
        return json.dumps({"error": "atomic_tests.yaml not found", "technique_id": technique_id})

    with open(atomic_file) as f:
        data: dict[str, Any] = yaml.safe_load(f) or {}

    tid = technique_id.strip().upper()
    tests = data.get(tid, [])

    return json.dumps(
        {
            "technique_id": tid,
            "atomic_tests": tests,
            "count": len(tests),
            "art_url": f"https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/{tid}/{tid}.yaml",
            "note": "Run these tests to validate that your detection rules fire. Use Invoke-AtomicRedTeam or atomic-operator.",
        },
        indent=2,
    )
