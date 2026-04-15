"""KQL rule validator."""

from typing import Dict, List, Any, Tuple


class KQLValidator:
    """Validator for KQL detection rules."""

    def __init__(self):
        """Initialize KQL validator."""
        self.name = "KQL Validator"
        self.required_fields = ["name", "description", "severity", "query", "tactics", "techniques"]
        self.valid_severities = ["Informational", "Low", "Medium", "High", "Critical"]

    def validate(self, rule: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Validate a KQL rule."""
        issues = []

        # Check required fields
        for field in self.required_fields:
            if field not in rule:
                issues.append(f"Missing required field: {field}")

        # Check severity
        if "severity" in rule and rule["severity"] not in self.valid_severities:
            issues.append(f"Invalid severity: {rule['severity']}")

        # Check query is not empty
        if "query" in rule and not rule["query"].strip():
            issues.append("Query cannot be empty")

        # Check tactics and techniques are lists
        if "tactics" in rule and not isinstance(rule["tactics"], list):
            issues.append("Tactics must be a list")
        if "techniques" in rule and not isinstance(rule["techniques"], list):
            issues.append("Techniques must be a list")

        is_valid = len(issues) == 0
        return is_valid, issues
