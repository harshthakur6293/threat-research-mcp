"""EQL rule validator."""

from typing import Dict, List, Any, Tuple


class EQLValidator:
    """Validator for EQL detection rules."""

    def __init__(self):
        """Initialize EQL validator."""
        self.name = "EQL Validator"
        self.required_fields = [
            "name",
            "description",
            "query",
            "severity",
            "risk_score",
            "mitre_attack",
        ]
        self.valid_severities = ["low", "medium", "high", "critical"]

    def validate(self, rule: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Validate an EQL rule."""
        issues = []

        # Check required fields
        for field in self.required_fields:
            if field not in rule:
                issues.append(f"Missing required field: {field}")

        # Check severity
        if "severity" in rule and rule["severity"] not in self.valid_severities:
            issues.append(f"Invalid severity: {rule['severity']}")

        # Check risk_score range
        if "risk_score" in rule:
            if not isinstance(rule["risk_score"], int) or not 0 <= rule["risk_score"] <= 100:
                issues.append("risk_score must be an integer between 0 and 100")

        # Check query is not empty
        if "query" in rule and not rule["query"].strip():
            issues.append("Query cannot be empty")

        # Check mitre_attack is a list
        if "mitre_attack" in rule and not isinstance(rule["mitre_attack"], list):
            issues.append("mitre_attack must be a list")

        # Check for basic EQL syntax
        if "query" in rule:
            query = rule["query"]
            if " where " not in query:
                issues.append("Warning: EQL query should typically include 'where' clause")

        is_valid = len(issues) == 0
        return is_valid, issues
