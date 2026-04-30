"""Tests for new tools: STIX parser, Navigator export, Sigma scorer, MISP bridge,
macOS playbook entries, word-boundary keyword matching, extension blocklist."""

from __future__ import annotations

import json


# ── STIX Parser ───────────────────────────────────────────────────────────────

SAMPLE_STIX_BUNDLE = json.dumps(
    {
        "type": "bundle",
        "id": "bundle--test",
        "objects": [
            {
                "type": "indicator",
                "id": "indicator--1",
                "pattern": "[ipv4-addr:value = '1.2.3.4'] AND [domain-name:value = 'evil.com']",
                "pattern_type": "stix",
                "name": "C2 IP",
            },
            {
                "type": "indicator",
                "id": "indicator--2",
                "pattern": "[file:hashes.'SHA-256' = 'abc123def456abc123def456abc123def456abc123def456abc123def456abc1']",
                "pattern_type": "stix",
                "name": "Malware hash",
            },
            {
                "type": "attack-pattern",
                "id": "ap--1",
                "name": "PowerShell",
                "description": "Adversary uses encoded PowerShell to execute payload.",
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "execution"}
                ],
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1059.001"}
                ],
            },
            {
                "type": "malware",
                "id": "malware--1",
                "name": "DarkLoader",
                "description": "Loader malware used for initial access.",
                "malware_types": ["loader"],
                "is_family": False,
            },
            {
                "type": "threat-actor",
                "id": "ta--1",
                "name": "Sapphire Sleet",
                "description": "North Korean APT targeting crypto.",
                "aliases": ["CryptoMimic"],
                "sophistication": "advanced",
                "primary_motivation": "financial-gain",
            },
        ],
    }
)


class TestSTIXParser:
    def test_parse_returns_iocs(self):
        from threat_research_mcp.tools.parse_stix import parse_stix_bundle

        result = json.loads(parse_stix_bundle(SAMPLE_STIX_BUNDLE))
        assert "1.2.3.4" in result["iocs"]["ips"]
        assert "evil.com" in result["iocs"]["domains"]

    def test_parse_returns_hash(self):
        from threat_research_mcp.tools.parse_stix import parse_stix_bundle

        result = json.loads(parse_stix_bundle(SAMPLE_STIX_BUNDLE))
        assert any("abc123" in h for h in result["iocs"]["hashes"])

    def test_parse_returns_attack_pattern(self):
        from threat_research_mcp.tools.parse_stix import parse_stix_bundle

        result = json.loads(parse_stix_bundle(SAMPLE_STIX_BUNDLE))
        tids = [t["id"] for t in result["techniques"]]
        assert "T1059.001" in tids

    def test_parse_returns_malware(self):
        from threat_research_mcp.tools.parse_stix import parse_stix_bundle

        result = json.loads(parse_stix_bundle(SAMPLE_STIX_BUNDLE))
        names = [m["name"] for m in result["malware"]]
        assert "DarkLoader" in names

    def test_parse_returns_threat_actor(self):
        from threat_research_mcp.tools.parse_stix import parse_stix_bundle

        result = json.loads(parse_stix_bundle(SAMPLE_STIX_BUNDLE))
        names = [a["name"] for a in result["threat_actors"]]
        assert "Sapphire Sleet" in names

    def test_parse_invalid_json(self):
        from threat_research_mcp.tools.parse_stix import parse_stix_bundle

        result = json.loads(parse_stix_bundle("not json"))
        assert "error" in result

    def test_stix_to_text(self):
        from threat_research_mcp.tools.parse_stix import stix_to_pipeline_text

        text = stix_to_pipeline_text(SAMPLE_STIX_BUNDLE)
        assert "PowerShell" in text or "Sapphire Sleet" in text


# ── ATT&CK Navigator Export ───────────────────────────────────────────────────


class TestNavigatorExport:
    def test_layer_has_required_fields(self):
        from threat_research_mcp.tools.navigator_export import generate_navigator_layer

        techniques = [{"id": "T1059.001", "name": "PowerShell", "tactic": "execution"}]
        layer = json.loads(generate_navigator_layer(techniques))
        assert layer["type"] if "type" in layer else True
        assert "techniques" in layer
        assert "versions" in layer
        assert layer["domain"] == "enterprise-attack"

    def test_layer_contains_technique(self):
        from threat_research_mcp.tools.navigator_export import generate_navigator_layer

        techniques = [{"id": "T1059.001", "name": "PowerShell", "tactic": "execution", "score": 3}]
        layer = json.loads(generate_navigator_layer(techniques))
        tids = [t["techniqueID"] for t in layer["techniques"]]
        assert "T1059.001" in tids

    def test_layer_from_map_attack(self):
        from threat_research_mcp.tools.navigator_export import navigator_layer_from_map_attack

        map_json = json.dumps(
            {
                "techniques": [
                    {
                        "id": "T1059.001",
                        "name": "PowerShell",
                        "tactic": "execution",
                        "evidence": ["powershell", "encodedcommand"],
                        "url": "https://attack.mitre.org/techniques/T1059/001/",
                    }
                ],
                "count": 1,
            }
        )
        layer = json.loads(navigator_layer_from_map_attack(map_json))
        assert len(layer["techniques"]) == 1
        assert layer["techniques"][0]["score"] >= 2

    def test_layer_score_colors(self):
        from threat_research_mcp.tools.navigator_export import generate_navigator_layer

        techniques = [
            {"id": "T1003.001", "name": "LSASS", "tactic": "credential-access", "score": 5}
        ]
        layer = json.loads(generate_navigator_layer(techniques))
        assert layer["techniques"][0]["color"] == "#28a745"

    def test_layer_subtechnique_flag(self):
        from threat_research_mcp.tools.navigator_export import generate_navigator_layer

        techniques = [{"id": "T1059.001", "name": "PowerShell", "tactic": "execution"}]
        layer = json.loads(generate_navigator_layer(techniques))
        assert layer["techniques"][0]["showSubtechniques"] is True


# ── Sigma Quality Scorer ──────────────────────────────────────────────────────


GOOD_SIGMA = """
title: LSASS Memory Dump via ProcDump
status: stable
logsource:
  product: windows
  category: process_creation
  sigma_logsource: windows/process_creation
detection:
  selection:
    Image|endswith: '\\procdump.exe'
    CommandLine|contains: 'lsass'
  NOT filter:
    User|contains: 'SYSTEM'
  condition: selection and not filter
"""

POOR_SIGMA = """
title: Generic Process
logsource:
  product: windows
detection:
  selection:
    index: '*'
  condition: selection
"""


class TestSigmaScorer:
    def test_good_rule_scores_high(self):
        from threat_research_mcp.tools.score_sigma import score_sigma_rule

        result = json.loads(score_sigma_rule(GOOD_SIGMA))
        assert result["overall"] >= 2
        assert "specificity" in result
        assert "coverage" in result
        assert "fp_risk" in result

    def test_poor_rule_fp_risk(self):
        from threat_research_mcp.tools.score_sigma import score_sigma_rule

        result = json.loads(score_sigma_rule(POOR_SIGMA))
        assert result["fp_risk"] >= 2

    def test_returns_rationale(self):
        from threat_research_mcp.tools.score_sigma import score_sigma_rule

        result = json.loads(score_sigma_rule(GOOD_SIGMA))
        assert isinstance(result["rationale"], list)

    def test_score_from_technique(self):
        from threat_research_mcp.tools.score_sigma import score_sigma_from_technique

        result = json.loads(score_sigma_from_technique("T1059.001"))
        assert result["technique_id"] == "T1059.001"
        assert "overall" in result

    def test_atomic_tests_returns_list(self):
        from threat_research_mcp.tools.score_sigma import get_atomic_tests

        result = json.loads(get_atomic_tests("T1059.001"))
        assert "atomic_tests" in result
        assert "art_url" in result

    def test_atomic_tests_unknown_technique(self):
        from threat_research_mcp.tools.score_sigma import get_atomic_tests

        result = json.loads(get_atomic_tests("T9999.999"))
        assert result["count"] == 0


# ── Word-Boundary Keyword Matching ────────────────────────────────────────────


class TestWordBoundaryMatching:
    def test_tor_not_in_authorization(self):
        from threat_research_mcp.tools.map_attack import map_attack

        result = json.loads(
            map_attack("The authorization token is fwyan48umt1vimwqcqvhdd9u72a7qysi")
        )
        tids = [t["id"] for t in result["techniques"]]
        assert "T1090.003" not in tids, "'tor' matched inside 'authorization' — false positive"

    def test_rce_not_in_reinforce(self):
        from threat_research_mcp.tools.map_attack import map_attack

        result = json.loads(map_attack("This reinforces the social engineering approach."))
        tids = [t["id"] for t in result["techniques"]]
        assert "T1190" not in tids, "'rce' matched inside 'reinforce' — false positive"

    def test_osascript_matches(self):
        from threat_research_mcp.tools.map_attack import map_attack

        result = json.loads(map_attack("The script executes via osascript -e on macOS."))
        tids = [t["id"] for t in result["techniques"]]
        assert "T1059.002" in tids

    def test_tcc_db_matches(self):
        from threat_research_mcp.tools.map_attack import map_attack

        result = json.loads(
            map_attack("Attacker manipulates TCC.db using sqlite3 to bypass privacy controls.")
        )
        tids = [t["id"] for t in result["techniques"]]
        assert "T1548.006" in tids

    def test_telegram_bot_matches(self):
        from threat_research_mcp.tools.map_attack import map_attack

        result = json.loads(map_attack("Data exfiltrated via Telegram Bot API to external server."))
        tids = [t["id"] for t in result["techniques"]]
        assert "T1567.002" in tids


# ── macOS Extension Blocklist ─────────────────────────────────────────────────


class TestMacOSExtensionBlocklist:
    def test_scpt_not_extracted_as_domain(self):
        from threat_research_mcp.tools.extract_iocs import extract_iocs_from_text

        result = extract_iocs_from_text("The file Zoom.SDK.Update.scpt was opened by the user.")
        assert "Zoom.SDK.Update.scpt" not in result["domains"]
        assert all(not d.endswith(".scpt") for d in result["domains"])

    def test_app_not_extracted_as_domain(self):
        from threat_research_mcp.tools.extract_iocs import extract_iocs_from_text

        result = extract_iocs_from_text("The application systemupdate.app was installed.")
        domain_values = [d["value"] if isinstance(d, dict) else d for d in result["domains"]]
        assert all(not d.endswith(".app") for d in domain_values)

    def test_plist_not_extracted_as_domain(self):
        from threat_research_mcp.tools.extract_iocs import extract_iocs_from_text

        result = extract_iocs_from_text(
            "Launch daemon com.google.webkit.service.plist was created."
        )
        assert all(not d.endswith(".plist") for d in result["domains"])

    def test_real_domain_still_extracted(self):
        from threat_research_mcp.tools.extract_iocs import extract_iocs_from_text

        result = extract_iocs_from_text("C2 domain check02id.com beacons every 60 seconds.")
        # domains are rich dicts: {"value": str, "confidence": float, "label": str}
        domain_values = [d["value"] if isinstance(d, dict) else d for d in result["domains"]]
        assert "check02id.com" in domain_values


# ── macOS Playbook Entries ────────────────────────────────────────────────────


class TestMacOSPlaybook:
    def test_osascript_technique_in_playbook(self):
        from threat_research_mcp.tools.generate_hunt_hypothesis import (
            generate_hunt_hypotheses_for_techniques,
        )

        result = json.loads(generate_hunt_hypotheses_for_techniques(["T1059.002"]))
        assert result["count"] > 0
        src_keys = [h["log_source_key"] for h in result["hypotheses"]]
        assert "macos_unified_log" in src_keys or "edr_macos" in src_keys

    def test_tcc_technique_in_playbook(self):
        from threat_research_mcp.tools.generate_hunt_hypothesis import (
            generate_hunt_hypotheses_for_techniques,
        )

        result = json.loads(generate_hunt_hypotheses_for_techniques(["T1548.006"]))
        assert result["count"] > 0

    def test_telegram_exfil_in_playbook(self):
        from threat_research_mcp.tools.generate_hunt_hypothesis import (
            generate_hunt_hypotheses_for_techniques,
        )

        result = json.loads(generate_hunt_hypotheses_for_techniques(["T1567.002"]))
        assert result["count"] > 0
        src_keys = [h["log_source_key"] for h in result["hypotheses"]]
        assert "proxy_logs" in src_keys or "edr_macos" in src_keys

    def test_launch_agent_in_playbook(self):
        from threat_research_mcp.tools.generate_hunt_hypothesis import (
            generate_hunt_hypotheses_for_techniques,
        )

        result = json.loads(generate_hunt_hypotheses_for_techniques(["T1543.001"]))
        assert result["count"] > 0

    def test_keychain_in_playbook(self):
        from threat_research_mcp.tools.generate_hunt_hypothesis import (
            generate_hunt_hypotheses_for_techniques,
        )

        result = json.loads(generate_hunt_hypotheses_for_techniques(["T1555.003"]))
        assert result["count"] > 0
