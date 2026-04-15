"""SPL rule validator."""

from typing import Dict, List, Any, Tuple


class SPLValidator:
    """Validator for SPL detection rules."""

    def __init__(self):
        """Initialize SPL validator."""
        self.name = "SPL Validator"
        self.required_fields = [
            "name",
            "description",
            "search",
            "severity",
            "mitre_attack",
        ]
        self.valid_severities = ["low", "medium", "high", "critical"]

    def validate(self, rule: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Validate an SPL rule."""
        issues = []

        # Check required fields
        for field in self.required_fields:
            if field not in rule:
                issues.append(f"Missing required field: {field}")

        # Check severity
        if "severity" in rule and rule["severity"] not in self.valid_severities:
            issues.append(f"Invalid severity: {rule['severity']}")

        # Check search is not empty
        if "search" in rule and not rule["search"].strip():
            issues.append("Search cannot be empty")

        # Check mitre_attack is a list
        if "mitre_attack" in rule and not isinstance(rule["mitre_attack"], list):
            issues.append("mitre_attack must be a list")

        # Check for basic SPL syntax
        if "search" in rule:
            search = rule["search"]
            if "index=" not in search:
                issues.append("Warning: SPL search should typically include 'index='")

        is_valid = len(issues) == 0
        return is_valid, issues
