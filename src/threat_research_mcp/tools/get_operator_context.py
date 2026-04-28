"""Operator context loader — reads operator.yaml and returns the SOC's environment profile.

This drives every downstream filter: which SIEMs to generate queries for,
which log sources are available, which confidence threshold to apply, etc.

If operator.yaml is not found, returns sensible defaults so the tool works
out-of-the-box for new users.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import yaml

_DEFAULT_OPERATOR: dict[str, Any] = {
    "org": "Unknown SOC",
    "team_size": 1,
    "attack_version": "14.1",
    "siem": {"primary": "sentinel", "secondary": None},
    "log_sources": [
        "sysmon_process",
        "sysmon_network",
        "windows_event_4624",
        "windows_event_4625",
        "proxy_logs",
        "dns_logs",
        "script_block_logging",
        "email_gateway",
    ],
    "environment": {"os": ["windows"], "cloud": [], "containers": False, "on_prem": True},
    "confidence_threshold": 0.45,
    "detection": {
        "tier1_review_required": False,
        "tier2_review_required": True,
        "sigma_output_dir": "./detections/sigma",
        "lifecycle_states": ["draft", "review", "staging", "production", "deprecated"],
    },
    "campaigns": {"store_dir": "./.campaigns"},
    "default_source_quality": "unknown",
    "integrations": {
        "misp": {"enabled": False},
        "thor_hunting_mcp": {"enabled": False},
        "mitre_attack_mcp": {"enabled": True},
        "security_detections_mcp": {"enabled": True},
    },
}


def _find_operator_yaml() -> Path | None:
    """Search for operator.yaml in cwd and up to 3 parent directories."""
    search_dirs = [Path.cwd()]
    search_dirs += list(Path.cwd().parents[:3])

    # Also check env override
    if env_path := os.environ.get("THREAT_RESEARCH_OPERATOR_YAML"):
        env_p = Path(env_path)
        if env_p.exists():
            return env_p

    for d in search_dirs:
        candidate = d / "operator.yaml"
        if candidate.exists():
            return candidate

    return None


def load_operator_context() -> dict[str, Any]:
    """Load operator.yaml and merge with defaults. Returns the operator context dict."""
    path = _find_operator_yaml()

    if path is None:
        ctx = dict(_DEFAULT_OPERATOR)
        ctx["_source"] = "defaults (no operator.yaml found)"
        ctx["_path"] = None
        return ctx

    try:
        with open(path, encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}
    except Exception as exc:
        ctx = dict(_DEFAULT_OPERATOR)
        ctx["_source"] = f"defaults (failed to parse {path}: {exc})"
        ctx["_path"] = str(path)
        return ctx

    # Deep-merge: raw overrides defaults but missing keys fall back to defaults
    merged = _deep_merge(_DEFAULT_OPERATOR, raw)
    merged["_source"] = str(path)
    merged["_path"] = str(path)
    return merged


def _deep_merge(base: dict, override: dict) -> dict:
    result = dict(base)
    for key, val in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(val, dict):
            result[key] = _deep_merge(result[key], val)
        else:
            result[key] = val
    return result


def get_operator_context_json() -> str:
    """MCP tool: return the loaded operator context as JSON.

    Reads operator.yaml from the working directory (or up to 3 parents).
    Falls back to safe defaults if not found — tool works without any config.

    Returns: JSON with org profile, SIEM, log sources, environment, thresholds.
    """
    ctx = load_operator_context()

    found = ctx["_path"] is not None
    summary = {
        "found": found,
        "config_path": ctx.get("_path"),
        "org": ctx.get("org", "Unknown"),
        "primary_siem": ctx.get("siem", {}).get("primary", "sentinel"),
        "secondary_siem": ctx.get("siem", {}).get("secondary"),
        "log_sources_count": len(ctx.get("log_sources", [])),
        "log_sources": ctx.get("log_sources", []),
        "os_mix": ctx.get("environment", {}).get("os", []),
        "cloud": ctx.get("environment", {}).get("cloud", []),
        "containers": ctx.get("environment", {}).get("containers", False),
        "confidence_threshold": ctx.get("confidence_threshold", 0.45),
        "attack_version": ctx.get("attack_version", "14.1"),
        "integrations": {
            k: v.get("enabled", False)
            for k, v in ctx.get("integrations", {}).items()
            if isinstance(v, dict)
        },
        "note": (
            "operator.yaml found and loaded."
            if found
            else "No operator.yaml found. Using defaults. "
            "Copy operator.yaml.example → operator.yaml and edit for your environment."
        ),
    }
    return json.dumps(summary, indent=2)
