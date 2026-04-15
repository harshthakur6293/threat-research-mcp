"""
Sigma rule validator.

Validates Sigma rules for syntax, structure, and best practices.
"""

from typing import Dict, List, Any, Tuple
import re


class SigmaValidator:
    """
    Validator for Sigma detection rules.

    Checks for:
    - Required fields
    - Valid field values
    - Detection logic structure
    - Best practices
    """

    def __init__(self):
        """Initialize Sigma validator."""
        self.name = "Sigma Validator"

        self.required_fields = [
            "title",
            "id",
            "status",
            "description",
            "author",
            "date",
            "logsource",
            "detection",
            "level",
        ]

        self.valid_statuses = ["experimental", "testing", "stable", "deprecated"]
        self.valid_levels = ["informational", "low", "medium", "high", "critical"]

    def validate(self, rule: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Validate a Sigma rule.

        Args:
            rule: Sigma rule dictionary

        Returns:
            Tuple of (is_valid, list of issues)
        """
        issues = []

        # Check required fields
        issues.extend(self._check_required_fields(rule))

        # Check field values
        issues.extend(self._check_field_values(rule))

        # Check detection logic
        issues.extend(self._check_detection_logic(rule))

        # Check best practices
        issues.extend(self._check_best_practices(rule))

        is_valid = len(issues) == 0

        return is_valid, issues

    def _check_required_fields(self, rule: Dict[str, Any]) -> List[str]:
        """Check for required fields."""
        issues = []

        for field in self.required_fields:
            if field not in rule:
                issues.append(f"Missing required field: {field}")

        return issues

    def _check_field_values(self, rule: Dict[str, Any]) -> List[str]:
        """Check field values are valid."""
        issues = []

        # Check status
        if "status" in rule and rule["status"] not in self.valid_statuses:
            issues.append(f"Invalid status: {rule['status']}. Must be one of {self.valid_statuses}")

        # Check level
        if "level" in rule and rule["level"] not in self.valid_levels:
            issues.append(f"Invalid level: {rule['level']}. Must be one of {self.valid_levels}")

        # Check ID format (should be UUID)
        if "id" in rule:
            uuid_pattern = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
            if not re.match(uuid_pattern, rule["id"], re.IGNORECASE):
                issues.append(f"Invalid ID format: {rule['id']}. Should be a UUID")

        # Check date format (YYYY-MM-DD)
        if "date" in rule:
            date_pattern = r"^\d{4}-\d{2}-\d{2}$"
            if not re.match(date_pattern, rule["date"]):
                issues.append(f"Invalid date format: {rule['date']}. Should be YYYY-MM-DD")

        return issues

    def _check_detection_logic(self, rule: Dict[str, Any]) -> List[str]:
        """Check detection logic structure."""
        issues = []

        if "detection" not in rule:
            return issues

        detection = rule["detection"]

        # Check for condition
        if "condition" not in detection:
            issues.append("Detection missing 'condition' field")

        # Check for at least one selection
        has_selection = any(
            key.startswith("selection") or key.startswith("filter") for key in detection.keys()
        )
        if not has_selection:
            issues.append("Detection should have at least one 'selection' or 'filter' block")

        return issues

    def _check_best_practices(self, rule: Dict[str, Any]) -> List[str]:
        """Check for best practices."""
        issues = []

        # Check for tags
        if "tags" not in rule or not rule["tags"]:
            issues.append("Warning: No tags specified (best practice to include tags)")

        # Check for false positives
        if "falsepositives" not in rule or not rule["falsepositives"]:
            issues.append(
                "Warning: No false positives documented (best practice to document known FPs)"
            )

        # Check for references
        if "references" not in rule or not rule["references"]:
            issues.append("Warning: No references provided (best practice to include references)")

        # Check title length
        if "title" in rule and len(rule["title"]) > 100:
            issues.append("Warning: Title is very long (best practice: keep under 100 chars)")

        return issues
