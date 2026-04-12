"""Structural validation of Sigma rule YAML (offline, no Sigma CLI required)."""

from __future__ import annotations

import json
from typing import List, Tuple

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore[assignment]


REQUIRED_TOP = ("title", "logsource", "detection")


def validate_sigma_yaml(yaml_text: str) -> Tuple[bool, List[str]]:
    """
    Parse YAML and check required Sigma top-level keys and minimal detection.selection shape.

    Returns (ok, list of error messages).
    """
    errors: List[str] = []
    if yaml is None:
        return False, ["PyYAML is required for validate_sigma"]
    text = (yaml_text or "").strip()
    if not text:
        return False, ["empty input"]

    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        return False, [f"YAML parse error: {e}"]

    if not isinstance(data, dict):
        return False, ["root must be a mapping/object"]

    for key in REQUIRED_TOP:
        if key not in data or data[key] in (None, ""):
            errors.append(f"missing or empty required field: {key}")

    det = data.get("detection")
    if isinstance(det, dict):
        if "condition" not in det:
            errors.append("detection.condition is required")
        if "selection" not in det and not any(k.startswith("selection") for k in det):
            errors.append("detection.selection (or selection_*) is required")
    elif det is not None:
        errors.append("detection must be a mapping")

    ls = data.get("logsource")
    if isinstance(ls, dict):
        if not ls.get("category") and not ls.get("product"):
            errors.append("logsource should include category and/or product")
    elif ls is not None:
        errors.append("logsource must be a mapping")

    return (len(errors) == 0, errors)


def validate_sigma_json(yaml_text: str) -> str:
    ok, errs = validate_sigma_yaml(yaml_text)
    return json.dumps({"valid": ok, "errors": errs}, indent=2)
