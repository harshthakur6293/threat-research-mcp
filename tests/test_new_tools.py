"""Tests for new detection generators, YARA generator, list_log_sources, and run_pipeline."""

import json


from threat_research_mcp.tools.generate_detections import (
    generate_kql_detection,
    generate_spl_detection,
    generate_eql_detection,
    generate_yara_for_technique,
    generate_yara_rule,
    list_log_sources,
)
from threat_research_mcp.tools.run_pipeline import run_pipeline


# ── KQL ──────────────────────────────────────────────────────────────────────


class TestKQLDetection:
    def test_known_technique_returns_rules(self):
        result = json.loads(generate_kql_detection("T1059.001"))
        assert result["technique_id"] == "T1059.001"
        assert result["siem"] == "KQL (Microsoft Sentinel)"
        assert len(result["rules"]) > 0

    def test_each_rule_has_query(self):
        result = json.loads(generate_kql_detection("T1059.001"))
        for rule in result["rules"]:
            assert "query" in rule
            assert len(rule["query"]) > 0

    def test_sentinel_rule_metadata(self):
        result = json.loads(generate_kql_detection("T1003.001"))
        for rule in result["rules"]:
            sentinel = rule["sentinel_rule"]
            assert "displayName" in sentinel
            assert "severity" in sentinel
            assert "query" in sentinel
            assert "T1003.001" in sentinel["techniques"]

    def test_unknown_technique_fallback(self):
        result = json.loads(generate_kql_detection("T9999.999"))
        assert result["technique_id"] == "T9999.999"
        assert "note" in result
        assert len(result["rules"]) > 0

    def test_multiple_techniques_have_rules(self):
        for tid in ("T1053.005", "T1547.001", "T1486", "T1558.003", "T1046"):
            result = json.loads(generate_kql_detection(tid))
            assert len(result["rules"]) > 0, f"No KQL rules for {tid}"

    def test_lowercase_input_normalized(self):
        result = json.loads(generate_kql_detection("t1059.001"))
        assert result["technique_id"] == "T1059.001"


# ── SPL ──────────────────────────────────────────────────────────────────────


class TestSPLDetection:
    def test_known_technique_returns_rules(self):
        result = json.loads(generate_spl_detection("T1059.001"))
        assert result["technique_id"] == "T1059.001"
        assert result["siem"] == "SPL (Splunk)"
        assert len(result["rules"]) > 0

    def test_each_rule_has_search(self):
        result = json.loads(generate_spl_detection("T1059.001"))
        for rule in result["rules"]:
            assert "search" in rule
            assert len(rule["search"]) > 0

    def test_splunk_alert_metadata(self):
        result = json.loads(generate_spl_detection("T1003.001"))
        for rule in result["rules"]:
            alert = rule["splunk_alert"]
            assert "name" in alert
            assert "severity" in alert
            assert "search" in alert
            assert "T1003.001" in alert["mitre_attack"]
            assert len(alert["recommended_actions"]) > 0

    def test_unknown_technique_fallback(self):
        result = json.loads(generate_spl_detection("T9999.999"))
        assert "note" in result
        assert len(result["rules"]) > 0


# ── EQL / Elastic ─────────────────────────────────────────────────────────────


class TestEQLDetection:
    def test_known_technique_returns_rules(self):
        result = json.loads(generate_eql_detection("T1059.001"))
        assert result["technique_id"] == "T1059.001"
        assert "Elastic" in result["siem"]
        assert len(result["rules"]) > 0

    def test_each_rule_has_query(self):
        result = json.loads(generate_eql_detection("T1071.001"))
        for rule in result["rules"]:
            assert "query" in rule
            assert len(rule["query"]) > 0

    def test_elastic_rule_threat_mapping(self):
        result = json.loads(generate_eql_detection("T1003.001"))
        for rule in result["rules"]:
            er = rule["elastic_rule"]
            assert "risk_score" in er
            assert 0 <= er["risk_score"] <= 100
            assert "threat" in er
            assert er["threat"][0]["technique"][0]["id"] == "T1003.001"

    def test_unknown_technique_fallback(self):
        result = json.loads(generate_eql_detection("T9999.999"))
        assert "note" in result
        assert len(result["rules"]) > 0


# ── YARA ──────────────────────────────────────────────────────────────────────


class TestYARAForTechnique:
    def test_covered_technique_returns_rule(self):
        result = json.loads(generate_yara_for_technique("T1059.001"))
        assert result["covered"] is True
        assert result["yara_rule"] is not None
        assert "rule " in result["yara_rule"]

    def test_yara_rule_has_required_sections(self):
        result = json.loads(generate_yara_for_technique("T1003.001"))
        yara = result["yara_rule"]
        assert "meta:" in yara
        assert "strings:" in yara
        assert "condition:" in yara

    def test_uncovered_technique_returns_note(self):
        result = json.loads(generate_yara_for_technique("T1021.001"))
        assert result["covered"] is False
        assert result["yara_rule"] is None
        assert "note" in result

    def test_all_covered_techniques_produce_valid_yara(self):
        covered = [
            "T1059.001",
            "T1003.001",
            "T1055",
            "T1027",
            "T1486",
            "T1505.003",
            "T1566.001",
            "T1071.001",
            "T1547.001",
            "T1053.005",
        ]
        for tid in covered:
            result = json.loads(generate_yara_for_technique(tid))
            assert result["covered"] is True, f"Expected {tid} to be covered"
            assert "rule " in result["yara_rule"]


class TestGenerateYARARule:
    def test_basic_rule_generation(self):
        result = json.loads(generate_yara_rule("Test Rule", "mimikatz,sekurlsa,lsadump"))
        assert result["rule_name"] == "Test_Rule"
        assert result["string_count"] == 3
        assert "rule Test_Rule" in result["yara_rule"]

    def test_rule_contains_strings(self):
        result = json.loads(generate_yara_rule("IOC Hunt", "evil.exe,c2.domain.com"))
        yara = result["yara_rule"]
        assert "evil.exe" in yara
        assert "c2.domain.com" in yara

    def test_custom_condition(self):
        result = json.loads(generate_yara_rule("Multi Match", "str1,str2,str3", "2 of them"))
        assert "2 of them" in result["yara_rule"]

    def test_empty_strings_returns_error(self):
        result = json.loads(generate_yara_rule("Empty", ""))
        assert "error" in result

    def test_rule_name_sanitized(self):
        result = json.loads(generate_yara_rule("My Rule With Spaces!", "test"))
        assert " " not in result["rule_name"]
        assert "!" not in result["rule_name"]


# ── List Log Sources ──────────────────────────────────────────────────────────


class TestListLogSources:
    def test_returns_json_with_log_sources(self):
        result = json.loads(list_log_sources())
        assert "log_sources" in result
        assert len(result["log_sources"]) > 0

    def test_each_source_has_required_fields(self):
        result = json.loads(list_log_sources())
        for src in result["log_sources"]:
            assert "key" in src
            assert "label" in src
            assert "techniques" in src

    def test_environment_presets_present(self):
        result = json.loads(list_log_sources())
        assert "environment_presets" in result
        presets = result["environment_presets"]
        assert "windows_sysmon" in presets
        assert "windows_events" in presets
        assert "network" in presets

    def test_sysmon_process_in_catalog(self):
        result = json.loads(list_log_sources())
        keys = [s["key"] for s in result["log_sources"]]
        assert "sysmon_process" in keys

    def test_usage_hint_present(self):
        result = json.loads(list_log_sources())
        assert "usage" in result


# ── Run Pipeline ──────────────────────────────────────────────────────────────


class TestRunPipeline:
    def test_pipeline_with_text_returns_all_keys(self):
        text = "Adversary used powershell -enc to download and execute mimikatz."
        result = json.loads(run_pipeline(text=text))
        assert "iocs" in result
        assert "techniques" in result
        assert "hunt_hypotheses" in result
        assert "detections" in result
        assert "summary" in result

    def test_pipeline_detects_techniques(self):
        text = "The attacker used PowerShell encoded commands and Mimikatz to dump credentials."
        result = json.loads(run_pipeline(text=text))
        technique_ids = result["summary"]["technique_ids"]
        assert len(technique_ids) > 0
        # Should detect PowerShell and/or credential dumping techniques
        assert any(tid in technique_ids for tid in ("T1059.001", "T1003.001", "T1003"))

    def test_pipeline_generates_hypotheses(self):
        text = "Cobalt Strike beacon communicating over HTTP. Lateral movement via SMB."
        result = json.loads(run_pipeline(text=text))
        hypotheses = result["hunt_hypotheses"].get("hypotheses", [])
        assert len(hypotheses) > 0

    def test_pipeline_with_log_source_filter(self):
        text = "PowerShell encoded command execution detected via script block logging."
        result = json.loads(run_pipeline(text=text, log_sources="script_block_logging"))
        hypotheses = result["hunt_hypotheses"].get("hypotheses", [])
        # All hypotheses should be for script_block_logging
        for h in hypotheses:
            assert h["log_source_key"] == "script_block_logging"

    def test_pipeline_empty_text_returns_error(self):
        result = json.loads(run_pipeline(text=""))
        assert "error" in result

    def test_pipeline_generates_sigma_rules(self):
        text = "Attacker created a scheduled task for persistence using schtasks."
        result = json.loads(run_pipeline(text=text))
        sigma = result["detections"].get("sigma", {})
        # Should have at least one sigma rule
        assert "rules" in sigma

    def test_pipeline_summary_has_stages(self):
        text = "PowerShell download cradle used to fetch malware."
        result = json.loads(run_pipeline(text=text))
        stages = result["summary"]["stages_completed"]
        assert "ioc_extraction" in stages
        assert "ttp_mapping" in stages

    def test_pipeline_enrich_false_skips_enrichment(self):
        text = "Attack from 192.168.1.100 using powershell."
        result = json.loads(run_pipeline(text=text, enrich=False))
        enrichment = result.get("enrichment", {})
        assert "skipped" in enrichment
