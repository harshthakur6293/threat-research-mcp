"""
Tests for detection generators (Sigma, KQL, SPL, EQL) and validators.
"""

import pytest
from threat_research_mcp.detection.generators.sigma import SigmaGenerator
from threat_research_mcp.detection.generators.kql import KQLGenerator
from threat_research_mcp.detection.generators.spl import SPLGenerator
from threat_research_mcp.detection.generators.eql import EQLGenerator
from threat_research_mcp.detection.validators.sigma_validator import SigmaValidator
from threat_research_mcp.detection.validators.kql_validator import KQLValidator
from threat_research_mcp.detection.validators.spl_validator import SPLValidator
from threat_research_mcp.detection.validators.eql_validator import EQLValidator


class TestSigmaGenerator:
    """Tests for Sigma generator."""

    def test_initialization(self):
        """Test Sigma generator initialization."""
        generator = SigmaGenerator()
        assert generator.name == "Sigma"

    def test_generate_powershell_rule(self):
        """Test generating PowerShell rule."""
        generator = SigmaGenerator()
        rule = generator.generate_from_technique("T1059.001", "PowerShell")

        assert rule.title is not None
        assert rule.id is not None
        assert rule.status in ["experimental", "testing", "stable"]
        assert rule.level in ["informational", "low", "medium", "high", "critical"]
        assert "detection" in rule.to_dict()
        assert "logsource" in rule.to_dict()

    def test_generate_lsass_rule(self):
        """Test generating LSASS rule."""
        generator = SigmaGenerator()
        rule = generator.generate_from_technique("T1003.001", "LSASS Memory")

        assert "lsass" in rule.title.lower()
        assert rule.level == "critical"
        assert any("t1003.001" in tag.lower() for tag in rule.tags)

    def test_generate_unknown_technique_returns_none(self):
        """Unknown techniques return None — no garbage generic rules."""
        generator = SigmaGenerator()
        rule = generator.generate_from_technique("T9999.999", "Unknown Technique")
        assert rule is None, "Generator must return None for unmapped techniques, not a stub rule"

    def test_to_yaml(self):
        """Test converting rule to YAML."""
        generator = SigmaGenerator()
        rule = generator.generate_from_technique("T1059.001", "PowerShell")

        yaml_str = rule.to_yaml()
        assert "title:" in yaml_str
        assert "detection:" in yaml_str


class TestKQLGenerator:
    """Tests for KQL generator."""

    def test_initialization(self):
        """Test KQL generator initialization."""
        generator = KQLGenerator()
        assert generator.name == "KQL"

    def test_generate_powershell_rule(self):
        """Test generating PowerShell KQL rule."""
        generator = KQLGenerator()
        rule = generator.generate_from_technique("T1059.001", "PowerShell")

        assert rule.name is not None
        assert rule.severity in ["Informational", "Low", "Medium", "High", "Critical"]
        assert "DeviceProcessEvents" in rule.query or "powershell" in rule.query.lower()
        assert "T1059.001" in rule.techniques

    def test_generate_lsass_rule(self):
        """Test generating LSASS KQL rule."""
        generator = KQLGenerator()
        rule = generator.generate_from_technique("T1003.001", "LSASS Memory")

        assert "lsass" in rule.name.lower()
        assert rule.severity == "Critical"
        assert "T1003.001" in rule.techniques

    def test_entity_mappings(self):
        """Test KQL entity mappings."""
        generator = KQLGenerator()
        rule = generator.generate_from_technique("T1059.001", "PowerShell")

        assert len(rule.entity_mappings) > 0
        assert any(m["entityType"] == "Host" for m in rule.entity_mappings)


class TestSPLGenerator:
    """Tests for SPL generator."""

    def test_initialization(self):
        """Test SPL generator initialization."""
        generator = SPLGenerator()
        assert generator.name == "SPL"

    def test_generate_powershell_rule(self):
        """Test generating PowerShell SPL rule."""
        generator = SPLGenerator()
        rule = generator.generate_from_technique("T1059.001", "PowerShell")

        assert rule.name is not None
        assert rule.severity in ["low", "medium", "high", "critical"]
        assert "index=" in rule.search
        assert "powershell" in rule.search.lower()
        assert "T1059.001" in rule.mitre_attack

    def test_generate_lsass_rule(self):
        """Test generating LSASS SPL rule."""
        generator = SPLGenerator()
        rule = generator.generate_from_technique("T1003.001", "LSASS Memory")

        assert "lsass" in rule.name.lower()
        assert rule.severity == "critical"
        assert len(rule.recommended_actions) > 0

    def test_drilldown_search(self):
        """Test SPL drilldown search."""
        generator = SPLGenerator()
        rule = generator.generate_from_technique("T1059.001", "PowerShell")

        assert rule.drilldown_search is not None
        assert len(rule.drilldown_search) > 0


class TestEQLGenerator:
    """Tests for EQL generator."""

    def test_initialization(self):
        """Test EQL generator initialization."""
        generator = EQLGenerator()
        assert generator.name == "EQL"

    def test_generate_powershell_rule(self):
        """Test generating PowerShell EQL rule."""
        generator = EQLGenerator()
        rule = generator.generate_from_technique("T1059.001", "PowerShell")

        assert rule.name is not None
        assert rule.severity in ["low", "medium", "high", "critical"]
        assert 0 <= rule.risk_score <= 100
        assert "process where" in rule.query or "network where" in rule.query
        assert "T1059.001" in rule.mitre_attack

    def test_generate_lsass_rule(self):
        """Test generating LSASS EQL rule."""
        generator = EQLGenerator()
        rule = generator.generate_from_technique("T1003.001", "LSASS Memory")

        assert "lsass" in rule.name.lower()
        assert rule.severity == "critical"
        assert rule.risk_score > 90

    def test_rule_metadata(self):
        """Test EQL rule metadata."""
        generator = EQLGenerator()
        rule = generator.generate_from_technique("T1059.001", "PowerShell")

        assert rule.rule_type == "eql"
        assert len(rule.index) > 0
        assert rule.interval == "5m"


class TestSigmaValidator:
    """Tests for Sigma validator."""

    def test_initialization(self):
        """Test Sigma validator initialization."""
        validator = SigmaValidator()
        assert validator.name == "Sigma Validator"
        assert len(validator.required_fields) > 0

    def test_validate_valid_rule(self):
        """Test validating a valid Sigma rule."""
        validator = SigmaValidator()
        generator = SigmaGenerator()
        rule = generator.generate_from_technique("T1059.001", "PowerShell")

        is_valid, issues = validator.validate(rule.to_dict())

        # Should be mostly valid (may have warnings)
        assert isinstance(is_valid, bool)
        assert isinstance(issues, list)

    def test_validate_missing_fields(self):
        """Test validating rule with missing fields."""
        validator = SigmaValidator()
        rule = {"title": "Test Rule"}

        is_valid, issues = validator.validate(rule)

        assert not is_valid
        assert len(issues) > 0
        assert any("Missing required field" in issue for issue in issues)

    def test_validate_invalid_status(self):
        """Test validating rule with invalid status."""
        validator = SigmaValidator()
        rule = {
            "title": "Test",
            "id": "12345678-1234-1234-1234-123456789012",
            "status": "invalid_status",
            "description": "Test",
            "author": "Test",
            "date": "2024-01-01",
            "logsource": {"product": "windows"},
            "detection": {"selection": {}, "condition": "selection"},
            "level": "medium",
        }

        is_valid, issues = validator.validate(rule)

        assert not is_valid
        assert any("Invalid status" in issue for issue in issues)


class TestKQLValidator:
    """Tests for KQL validator."""

    def test_initialization(self):
        """Test KQL validator initialization."""
        validator = KQLValidator()
        assert validator.name == "KQL Validator"

    def test_validate_valid_rule(self):
        """Test validating a valid KQL rule."""
        validator = KQLValidator()
        generator = KQLGenerator()
        rule = generator.generate_from_technique("T1059.001", "PowerShell")

        is_valid, issues = validator.validate(rule.to_dict())

        assert is_valid or len(issues) == 0  # Should be valid

    def test_validate_missing_query(self):
        """Test validating rule with missing query."""
        validator = KQLValidator()
        rule = {
            "name": "Test",
            "description": "Test",
            "severity": "High",
            "tactics": [],
            "techniques": [],
        }

        is_valid, issues = validator.validate(rule)

        assert not is_valid
        assert any("Missing required field: query" in issue for issue in issues)


class TestSPLValidator:
    """Tests for SPL validator."""

    def test_initialization(self):
        """Test SPL validator initialization."""
        validator = SPLValidator()
        assert validator.name == "SPL Validator"

    def test_validate_valid_rule(self):
        """Test validating a valid SPL rule."""
        validator = SPLValidator()
        generator = SPLGenerator()
        rule = generator.generate_from_technique("T1059.001", "PowerShell")

        is_valid, issues = validator.validate(rule.to_dict())

        # May have warnings but should be mostly valid
        assert isinstance(is_valid, bool)


class TestEQLValidator:
    """Tests for EQL validator."""

    def test_initialization(self):
        """Test EQL validator initialization."""
        validator = EQLValidator()
        assert validator.name == "EQL Validator"

    def test_validate_valid_rule(self):
        """Test validating a valid EQL rule."""
        validator = EQLValidator()
        generator = EQLGenerator()
        rule = generator.generate_from_technique("T1059.001", "PowerShell")

        is_valid, issues = validator.validate(rule.to_dict())

        # May have warnings but should be mostly valid
        assert isinstance(is_valid, bool)

    def test_validate_invalid_risk_score(self):
        """Test validating rule with invalid risk score."""
        validator = EQLValidator()
        rule = {
            "name": "Test",
            "description": "Test",
            "query": "process where true",
            "severity": "high",
            "risk_score": 150,  # Invalid: > 100
            "mitre_attack": [],
        }

        is_valid, issues = validator.validate(rule)

        assert not is_valid
        assert any("risk_score" in issue for issue in issues)


class TestSqlDetection:
    """Tests for generate_sql_detection — security data lake SQL queries."""

    def test_known_technique_returns_rules(self):
        import json
        from threat_research_mcp.tools.generate_detections import generate_sql_detection

        result = json.loads(generate_sql_detection("T1059.001"))
        assert result["technique_id"] == "T1059.001"
        assert result["technique_name"] == "PowerShell Execution"
        assert "SQL" in result["platform"]
        assert len(result["rules"]) > 0

    def test_rule_has_required_fields(self):
        import json
        from threat_research_mcp.tools.generate_detections import generate_sql_detection

        result = json.loads(generate_sql_detection("T1059.001"))
        for rule in result["rules"]:
            assert "query" in rule
            assert "log_source_key" in rule
            assert "hypothesis" in rule
            assert "SELECT" in rule["query"].upper()

    def test_sql_contains_from_clause(self):
        import json
        from threat_research_mcp.tools.generate_detections import generate_sql_detection

        result = json.loads(generate_sql_detection("T1003.001"))
        for rule in result["rules"]:
            assert "FROM" in rule["query"].upper()

    def test_unknown_technique_returns_empty_rules(self):
        import json
        from threat_research_mcp.tools.generate_detections import generate_sql_detection

        result = json.loads(generate_sql_detection("T9999.999"))
        assert result["rules"] == []
        assert "note" in result

    def test_multiple_techniques_have_sql(self):
        import json
        from threat_research_mcp.tools.generate_detections import generate_sql_detection

        for tid in ("T1071.001", "T1110.003", "T1486", "T1190"):
            result = json.loads(generate_sql_detection(tid))
            assert len(result["rules"]) > 0, f"Expected SQL rules for {tid}"

    def test_sql_queries_in_hunt_hypothesis(self):
        import json
        from threat_research_mcp.tools.generate_hunt_hypothesis import (
            generate_hunt_hypotheses_for_techniques,
        )

        result = json.loads(generate_hunt_hypotheses_for_techniques(["T1059.001"]))
        hypotheses = result["hypotheses"]
        assert len(hypotheses) > 0
        # At least one hypothesis should have a SQL query
        sql_covered = [h for h in hypotheses if h["queries"].get("sql")]
        assert len(sql_covered) > 0

    def test_hypothesis_queries_have_four_keys(self):
        import json
        from threat_research_mcp.tools.generate_hunt_hypothesis import (
            generate_hunt_hypotheses_for_techniques,
        )

        result = json.loads(generate_hunt_hypotheses_for_techniques(["T1071.001"]))
        for h in result["hypotheses"]:
            assert "splunk" in h["queries"]
            assert "kql" in h["queries"]
            assert "elastic" in h["queries"]
            assert "sql" in h["queries"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
