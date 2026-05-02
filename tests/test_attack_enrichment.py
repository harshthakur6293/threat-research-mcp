"""Tests for attack_enrichment module — graceful degradation when STIX absent."""

from __future__ import annotations

import json


class TestStixStatus:
    def test_status_returns_dict(self):
        from threat_research_mcp.tools.attack_enrichment import stix_status

        result = stix_status()
        assert isinstance(result, dict)

    def test_status_has_required_keys(self):
        from threat_research_mcp.tools.attack_enrichment import stix_status

        result = stix_status()
        assert "mitreattack_python_installed" in result
        assert "stix_file_found" in result
        assert "enrichment_available" in result
        assert "setup_instructions" in result

    def test_status_json_is_valid(self):
        from threat_research_mcp.tools.attack_enrichment import stix_status_json

        result = json.loads(stix_status_json())
        assert "enrichment_available" in result


class TestEnrichmentGracefulDegradation:
    """When STIX file is absent, all functions return empty/safe values."""

    def test_enrich_technique_returns_dict(self):
        from threat_research_mcp.tools.attack_enrichment import enrich_technique

        result = enrich_technique("T1059.001")
        assert isinstance(result, dict)

    def test_enrich_technique_empty_when_no_stix(self):
        from threat_research_mcp.tools.attack_enrichment import enrich_technique, is_available

        if not is_available():
            result = enrich_technique("T1059.001")
            assert result == {}

    def test_enrich_batch_returns_dict(self):
        from threat_research_mcp.tools.attack_enrichment import enrich_techniques_batch

        result = enrich_techniques_batch(["T1059.001", "T1003.001"])
        assert isinstance(result, dict)
        assert "T1059.001" in result
        assert "T1003.001" in result

    def test_enrich_json_valid_when_unavailable(self):
        from threat_research_mcp.tools.attack_enrichment import enrich_techniques_json, is_available

        if not is_available():
            result = json.loads(enrich_techniques_json("T1059.001,T1003.001"))
            assert "error" in result
            assert "enrichment_available" in result

    def test_enrich_json_empty_input(self):
        from threat_research_mcp.tools.attack_enrichment import enrich_techniques_json

        result = json.loads(enrich_techniques_json(""))
        assert "error" in result

    def test_is_available_returns_bool(self):
        from threat_research_mcp.tools.attack_enrichment import is_available

        result = is_available()
        assert isinstance(result, bool)


class TestEnrichmentWithStix:
    """Tests that run only when STIX data is present."""

    def test_enrich_known_technique_has_fields(self):
        from threat_research_mcp.tools.attack_enrichment import enrich_technique, is_available

        if not is_available():
            return

        result = enrich_technique("T1059.001")
        assert result != {}
        assert "platforms" in result
        assert "data_sources" in result
        assert "detection" in result
        assert isinstance(result["platforms"], list)

    def test_enrich_technique_has_groups(self):
        from threat_research_mcp.tools.attack_enrichment import enrich_technique, is_available

        if not is_available():
            return

        result = enrich_technique("T1059.001")
        assert "groups" in result
        assert isinstance(result["groups"], list)

    def test_enrich_unknown_technique_returns_empty(self):
        from threat_research_mcp.tools.attack_enrichment import enrich_technique, is_available

        if not is_available():
            return

        result = enrich_technique("T9999.999")
        assert result == {}

    def test_enrich_json_found_count(self):
        from threat_research_mcp.tools.attack_enrichment import enrich_techniques_json, is_available

        if not is_available():
            return

        result = json.loads(enrich_techniques_json("T1059.001,T1003.001"))
        assert result["count"] >= 1
        assert "enriched" in result
        assert "source" in result
