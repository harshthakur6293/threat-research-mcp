"""Threat Research MCP — deterministic threat intelligence tools for Claude.

Pipeline:
  Feed Ingestion → IOC Extraction → TTP Mapping → Hunt Hypotheses → Detections

Pairs naturally with:
  - MHaggis/mitre-attack-mcp  (technique lookup, group attribution, mitigations)
  - MHaggis/Security-Detections-MCP  (search 8,200+ existing rules, coverage gaps)
"""

from __future__ import annotations

from threat_research_mcp.tools.extract_iocs import extract_iocs_json
from threat_research_mcp.tools.map_attack import map_attack
from threat_research_mcp.tools.generate_sigma import (
    generate_sigma,
    generate_sigma_for_technique,
    generate_sigma_bundle,
)
from threat_research_mcp.tools.generate_hunt_hypothesis import (
    generate_hunt_hypothesis,
    generate_hunt_hypotheses_for_techniques,
)
from threat_research_mcp.tools.validate_sigma import validate_sigma_json
from threat_research_mcp.tools.detection_gap_analysis import detection_gap_analysis
from threat_research_mcp.tools.reconstruct_timeline import reconstruct_timeline
from threat_research_mcp.tools.ingest_tools import (
    ingest_from_config_path_json,
    intel_to_analysis_product_json,
)
from threat_research_mcp.tools.intel_storage_tools import (
    get_stored_analysis_product_json,
    search_analysis_product_history_json,
    search_ingested_intel_json,
)
from threat_research_mcp.enrichment.enrich import enrich_ioc, enrich_iocs_bulk
from threat_research_mcp.tools.generate_detections import (
    generate_kql_detection,
    generate_spl_detection,
    generate_eql_detection,
    generate_yara_for_technique,
    generate_yara_rule,
    list_log_sources,
)
from threat_research_mcp.tools.run_pipeline import run_pipeline
from threat_research_mcp.tools.parse_stix import parse_stix_bundle, stix_to_pipeline_text
from threat_research_mcp.tools.navigator_export import (
    navigator_layer_from_map_attack,
)
from threat_research_mcp.tools.score_sigma import (
    score_sigma_rule,
    score_sigma_from_technique,
    get_atomic_tests,
)
from threat_research_mcp.tools.misp_bridge import (
    pull_misp_events,
    push_sigma_to_misp,
    create_misp_event_from_pipeline,
)

try:
    from mcp.server.fastmcp import FastMCP
except Exception:
    FastMCP = None


if FastMCP:
    mcp = FastMCP("Threat Research MCP")

    # ── Feed Ingestion ────────────────────────────────────────────────────────

    @mcp.tool()
    def ingest_feed(config_path: str) -> str:
        """Ingest threat intelligence feeds from a YAML/JSON sources config file.

        Supports TAXII 2.1, RSS/Atom, HTML reports, and local files.
        See configs/sources.example.yaml for format.

        Returns normalized documents ready for IOC extraction and TTP mapping.
        """
        return ingest_from_config_path_json(config_path)

    @mcp.tool()
    def analyze_intel(
        text: str = "",
        sources_config_path: str = "",
    ) -> str:
        """Run the full pipeline on threat intel text and/or ingested feed documents.

        Extracts IOCs and maps ATT&CK techniques from the combined input.
        Pass text, a sources_config_path, or both.

        Returns: AnalysisProduct JSON with IOCs, techniques, and metadata.
        """
        return intel_to_analysis_product_json(
            text=text,
            sources_config_path=sources_config_path,
            workflow="threat_research",
        )

    # ── IOC Extraction ────────────────────────────────────────────────────────

    @mcp.tool()
    def extract_iocs(text: str) -> str:
        """Extract all indicators of compromise from free-form text.

        Finds: IPv4 addresses, domains, URLs, MD5/SHA1/SHA256 hashes, email addresses.
        Returns JSON with each IOC type as a deduplicated list.
        """
        return extract_iocs_json(text)

    @mcp.tool()
    def enrich_ioc_tool(ioc: str) -> str:
        """Enrich a single IOC (IP, domain, URL, or hash) against threat intel sources.

        Queries: VirusTotal, AlienVault OTX, AbuseIPDB, URLhaus (free).
        API keys read from env: VIRUSTOTAL_API_KEY, OTX_API_KEY, ABUSEIPDB_API_KEY.
        URLhaus requires no key. All sources are optional — works without any keys.

        Returns: JSON with per-source reputation, detection rates, and overall verdict.
        """
        return enrich_ioc(ioc)

    @mcp.tool()
    def enrich_iocs_tool(iocs_csv: str) -> str:
        """Enrich multiple IOCs (comma-separated) in bulk. Capped at 20 to respect rate limits.

        Returns: JSON with per-IOC results and aggregate malicious/suspicious/clean counts.
        """
        iocs = [i.strip() for i in iocs_csv.split(",") if i.strip()]
        return enrich_iocs_bulk(iocs)

    # ── TTP Mapping ───────────────────────────────────────────────────────────

    @mcp.tool()
    def map_ttp(text: str) -> str:
        """Map free-form threat intelligence text to MITRE ATT&CK techniques.

        Uses a 100+ keyword index covering all ATT&CK tactics.
        For deeper technique context (descriptions, mitigations, data sources,
        threat actor attribution), pair with mitre-attack-mcp.

        Returns: JSON with matched technique IDs, names, tactics, ATT&CK URLs, and evidence.
        """
        return map_attack(text)

    # ── Hunt Hypothesis Generation ────────────────────────────────────────────

    @mcp.tool()
    def hunt_from_intel(text: str) -> str:
        """Generate hunt hypotheses directly from threat intel text.

        Internally maps text to ATT&CK techniques, then returns actionable
        hunt hypotheses with ready-to-run queries for every available log source.

        Returns: JSON with hypotheses, SPL/KQL/Elastic queries per technique+log source.
        """
        return generate_hunt_hypothesis(text)

    @mcp.tool()
    def hunt_for_techniques(
        technique_ids: str,
        log_sources: str = "",
    ) -> str:
        """Generate hunt hypotheses for specific ATT&CK technique IDs.

        Args:
            technique_ids: Comma-separated technique IDs (e.g. "T1059.001,T1003.001")
            log_sources: Optional comma-separated log source filter
                         (e.g. "sysmon_process,script_block_logging,dns_logs").
                         Leave empty to get all available log sources.

        Returns: JSON with per-technique hypotheses and SPL/KQL/Elastic queries.
        """
        ids = [t.strip() for t in technique_ids.split(",") if t.strip()]
        src_filter = [s.strip() for s in log_sources.split(",") if s.strip()] or None
        return generate_hunt_hypotheses_for_techniques(ids, src_filter)

    # ── Detection Generation ──────────────────────────────────────────────────

    @mcp.tool()
    def generate_sigma_rule(
        title: str,
        behavior: str,
        logsource: str = "process_creation",
    ) -> str:
        """Generate a Sigma detection rule from a title and behavior description.

        Args:
            title: Rule title (e.g. "Suspicious PowerShell Download Cradle")
            behavior: The specific behavior to detect (used in CommandLine contains)
            logsource: Sigma logsource category (default: process_creation)

        Returns: JSON with rule_yaml, valid flag, and any validation errors.
        """
        return generate_sigma(title, behavior, logsource)

    @mcp.tool()
    def sigma_for_technique(
        technique_id: str,
        environment: str = "windows",
    ) -> str:
        """Generate a ready-to-use Sigma rule for a specific ATT&CK technique ID.

        Covers: T1059.001, T1003.001, T1071.001, T1053.005, T1547.001, T1505.003,
                T1566.001, T1021.001, T1021.002, T1078, T1110.003, T1046, T1486,
                T1558.003, T1190, T1055 and more.

        Returns: JSON with technique_id, technique_name, rule_yaml, and rule dict.
        """
        return generate_sigma_for_technique(technique_id, environment)

    @mcp.tool()
    def sigma_bundle_for_techniques(technique_ids: str) -> str:
        """Generate Sigma rules for multiple ATT&CK technique IDs at once.

        Args:
            technique_ids: Comma-separated technique IDs (e.g. "T1059.001,T1003.001")

        Returns: JSON with a list of rules and total count.
        """
        ids = [t.strip() for t in technique_ids.split(",") if t.strip()]
        return generate_sigma_bundle(ids)

    @mcp.tool()
    def validate_sigma_rule(yaml_text: str) -> str:
        """Validate a Sigma rule YAML for required fields (offline, no CLI needed).

        Checks: title, logsource (category/product/service), detection, condition.
        Returns JSON: {valid: bool, errors: [str]}.
        """
        return validate_sigma_json(yaml_text)

    # ── Coverage & Gap Analysis ───────────────────────────────────────────────

    @mcp.tool()
    def detection_coverage_gap(
        techniques_csv: str,
        detections_csv: str,
    ) -> str:
        """Identify ATT&CK technique gaps — techniques you track but lack detections for.

        Args:
            techniques_csv: Comma-separated technique IDs observed/tracked
            detections_csv: Comma-separated technique IDs you have detections for

        Returns: JSON with covered, missing, and coverage percentage.

        Tip: Pair with Security-Detections-MCP (list_by_mitre) to populate detections_csv
        from 8,200+ existing community rules.
        """
        return detection_gap_analysis(techniques_csv, detections_csv)

    # ── Storage & Search ──────────────────────────────────────────────────────

    @mcp.tool()
    def search_intel_history(
        text_query: str = "",
        workflow: str = "",
        limit: int = 30,
        offset: int = 0,
    ) -> str:
        """Search previously analyzed intel products stored in the local SQLite database.

        Requires THREAT_RESEARCH_MCP_DB environment variable to be set.
        Returns: JSON list of matching analysis products with row IDs.
        """
        return search_analysis_product_history_json(
            text_query=text_query,
            workflow=workflow,
            limit=limit,
            offset=offset,
        )

    @mcp.tool()
    def get_intel_by_id(row_id: int) -> str:
        """Retrieve a full stored analysis product by its row ID from search_intel_history.

        Returns: Full AnalysisProduct JSON.
        """
        return get_stored_analysis_product_json(row_id)

    @mcp.tool()
    def search_ingested_docs(
        text_query: str = "",
        source_name: str = "",
        limit: int = 30,
        offset: int = 0,
    ) -> str:
        """Search normalized documents ingested from threat intel feeds.

        Requires THREAT_RESEARCH_MCP_DB environment variable to be set.
        Returns: JSON list of matching documents with source metadata.
        """
        return search_ingested_intel_json(
            text_query=text_query,
            source_name=source_name,
            fingerprint="",
            limit=limit,
            offset=offset,
        )

    # ── Utilities ─────────────────────────────────────────────────────────────

    @mcp.tool()
    def timeline(text: str) -> str:
        """Sort log lines or event notes into chronological order.

        Parses timestamps in common formats and returns events ordered by time.
        Returns: JSON with sorted events and any lines that couldn't be parsed.
        """
        return reconstruct_timeline(text)

    # ── Full Pipeline ─────────────────────────────────────────────────────────

    @mcp.tool()
    def run_pipeline_tool(
        text: str = "",
        sources_config: str = "",
        log_sources: str = "",
        enrich: bool = False,
    ) -> str:
        """Run the complete threat research pipeline in a single call.

        Chains: Feed Ingestion → IOC Extraction → Enrichment → TTP Mapping
                → Hunt Hypotheses → Sigma Detection Rules.

        Args:
            text: Raw threat intel text (paste from report, email, IR note, etc.)
            sources_config: Path to sources YAML for feed ingestion (optional).
                            See configs/sources.example.yaml for format.
            log_sources: Comma-separated log source keys to filter hypotheses.
                         Use list_log_sources() to see all available keys.
                         Leave empty to get all log sources.
                         Example: "sysmon_process,script_block_logging,dns_logs"
            enrich: Set True to query VirusTotal / OTX / AbuseIPDB / URLhaus
                    for the top extracted IOCs (default False — avoids surprise API calls).

        Returns: Comprehensive JSON with all pipeline stages and a summary.
        """
        return run_pipeline(
            text=text,
            sources_config=sources_config,
            log_sources=log_sources,
            enrich=enrich,
        )

    @mcp.tool()
    def list_log_sources_tool() -> str:
        """List all available log source keys for filtering hunt hypotheses.

        Use the returned keys with hunt_for_techniques(log_sources=...) or
        run_pipeline_tool(log_sources=...) to get only hypotheses relevant to
        your SIEM environment.

        Also returns environment presets (e.g. 'windows_sysmon', 'network')
        that group related log sources for common deployment scenarios.

        Returns: JSON with log_sources catalog and environment_presets.
        """
        return list_log_sources()

    # ── SIEM-Native Detection Generators ─────────────────────────────────────

    @mcp.tool()
    def kql_for_technique(technique_id: str) -> str:
        """Generate KQL detection rules for a specific ATT&CK technique.

        Returns Microsoft Sentinel Analytics Rule definitions with display name,
        severity, query frequency, and entity mappings.

        Covers all 20 techniques in the hunt playbook. For techniques not in the
        playbook, generates a generic rule with correct metadata.

        Returns: JSON with siem=KQL, technique metadata, and per-log-source rules.
        """
        return generate_kql_detection(technique_id)

    @mcp.tool()
    def spl_for_technique(technique_id: str) -> str:
        """Generate SPL detection searches for a specific ATT&CK technique.

        Returns Splunk Saved Search definitions with cron schedule, severity,
        drilldown search template, and recommended response actions.

        Covers all 20 techniques in the hunt playbook. For techniques not in the
        playbook, generates a generic rule.

        Returns: JSON with siem=SPL, technique metadata, and per-log-source rules.
        """
        return generate_spl_detection(technique_id)

    @mcp.tool()
    def eql_for_technique(technique_id: str) -> str:
        """Generate Elastic Security detection rules for a specific ATT&CK technique.

        Returns Elastic/Kibana Detection Engine rule definitions with risk score,
        threat mapping, index patterns, and MITRE ATT&CK metadata.

        Covers all 20 techniques in the hunt playbook. For techniques not in the
        playbook, generates a generic rule.

        Returns: JSON with siem=Elastic, technique metadata, and per-log-source rules.
        """
        return generate_eql_detection(technique_id)

    # ── YARA Generators ───────────────────────────────────────────────────────

    @mcp.tool()
    def yara_for_technique(technique_id: str) -> str:
        """Generate a YARA file-scanning rule for a specific ATT&CK technique.

        Covers: T1059.001, T1003.001, T1055, T1027, T1486, T1505.003,
                T1566.001, T1071.001, T1547.001, T1053.005.

        Useful for endpoint scanning, sandbox detonation, and hunting in memory/disk.

        Returns: JSON with rule_name and yara_rule (ready to save as .yar file).
        """
        return generate_yara_for_technique(technique_id)

    @mcp.tool()
    def generate_yara(
        rule_name: str,
        strings_csv: str,
        condition: str = "any of them",
    ) -> str:
        """Generate a custom YARA rule from free-form string patterns.

        Use this to create IOC-based YARA rules from strings found in malware
        samples, threat reports, or IOC analysis.

        Args:
            rule_name: Rule name (alphanumeric, spaces OK — will be sanitized)
            strings_csv: Comma-separated strings to search for in files.
                         Example: "mimikatz,sekurlsa::,lsadump::"
            condition: YARA condition expression (default: "any of them").
                       Examples: "2 of them", "all of them", "$s0 and $s1"

        Returns: JSON with rule_name and yara_rule (ready to save as .yar file).
        """
        return generate_yara_rule(rule_name, strings_csv, condition)

    # ── STIX 2.1 Parser ──────────────────────────────────────────────────────

    @mcp.tool()
    def parse_stix(bundle_json: str) -> str:
        """Parse a STIX 2.x bundle JSON string and extract IOCs and ATT&CK techniques.

        Supports STIX 2.0 and 2.1. No external stix2 library required.
        Extracts: indicator patterns (IP, domain, URL, hash, email),
        attack-pattern objects (with ATT&CK IDs), malware, and threat actors.

        Returns JSON with iocs, techniques, malware, threat_actors.
        Pipe techniques into hunt_for_techniques for hunt queries.
        """
        return parse_stix_bundle(bundle_json)

    @mcp.tool()
    def stix_to_text(bundle_json: str) -> str:
        """Convert a STIX 2.x bundle to flat text for use with run_pipeline_tool.

        Extracts names, descriptions, and pattern values from all STIX objects
        into a single text blob. Use this to feed a STIX bundle through the
        full keyword-based pipeline without writing a custom parser.
        """
        return stix_to_pipeline_text(bundle_json)

    # ── ATT&CK Navigator Export ───────────────────────────────────────────────

    @mcp.tool()
    def navigator_layer(
        map_attack_json: str,
        layer_name: str = "Threat Research MCP — Mapped Techniques",
        layer_description: str = "",
    ) -> str:
        """Generate an ATT&CK Navigator layer JSON from map_attack() output.

        Drag-and-drop the result into https://mitre-attack.github.io/attack-navigator/
        for an instant visual heatmap. Techniques with more evidence keywords get
        a higher score (color gradient: red → yellow → green).

        Args:
            map_attack_json:   JSON string from the map_attack tool.
            layer_name:        Display name for the layer (optional).
            layer_description: Description shown in Navigator (optional).
        """
        return navigator_layer_from_map_attack(
            map_attack_json,
            layer_name=layer_name,
            layer_description=layer_description,
        )

    # ── Sigma Quality Scorer ──────────────────────────────────────────────────

    @mcp.tool()
    def score_sigma(sigma_yaml: str) -> str:
        """Score a Sigma rule on specificity, coverage, and false-positive risk.

        Returns a 1–5 score on each dimension plus a rationale list:
        - specificity: how precisely targeted the detection condition is
        - coverage:    how many SIEMs / log sources the rule addresses
        - fp_risk:     1 = low risk, 5 = high false-positive risk
        - overall:     weighted composite score

        Use this to triage which rules to tune before production deployment.
        """
        return score_sigma_rule(sigma_yaml)

    @mcp.tool()
    def score_technique_sigma(technique_id: str) -> str:
        """Score the built-in Sigma rule for an ATT&CK technique.

        Generates the rule via generate_sigma_for_technique and immediately
        scores it. Quick way to evaluate playbook rule quality.
        """
        return score_sigma_from_technique(technique_id)

    @mcp.tool()
    def atomic_tests_for_technique(technique_id: str) -> str:
        """Return Atomic Red Team test IDs for an ATT&CK technique.

        Loads from playbook/atomic_tests.yaml. These tests let you validate
        that your detection rules actually fire against real adversary behaviour.

        Returns test IDs, count, and a direct link to the ART repository entry.
        """
        return get_atomic_tests(technique_id)

    # ── MISP Integration ──────────────────────────────────────────────────────

    @mcp.tool()
    def misp_pull(tags: str = "", limit: int = 10) -> str:
        """Pull recent MISP events and return IOCs + pipeline-ready text.

        Requires MISP_URL and MISP_KEY environment variables.

        Args:
            tags:  Comma-separated MISP tags to filter, e.g. "tlp:red,APT28"
            limit: Max number of events (default 10)

        Returns IOC lists and a pipeline_text field ready for run_pipeline_tool.
        """
        return pull_misp_events(tags=tags, limit=limit)

    @mcp.tool()
    def misp_push_sigma(event_id: str, sigma_yaml: str, technique_id: str = "") -> str:
        """Push a Sigma rule as an attribute to an existing MISP event.

        Requires MISP_URL and MISP_KEY environment variables.

        Args:
            event_id:     MISP event ID to attach the rule to.
            sigma_yaml:   Sigma rule YAML string (from generate_sigma tools).
            technique_id: ATT&CK technique ID for tagging (optional).
        """
        return push_sigma_to_misp(event_id, sigma_yaml, technique_id)

    @mcp.tool()
    def misp_create_event(pipeline_result: str) -> str:
        """Create a new MISP event from run_pipeline_tool output.

        Requires MISP_URL and MISP_KEY environment variables.
        Creates an event with all extracted IOCs as attributes and ATT&CK
        technique tags applied automatically.

        Args:
            pipeline_result: JSON string from run_pipeline_tool.
        """
        return create_misp_event_from_pipeline(pipeline_result)


def main() -> None:
    if FastMCP is None:
        raise RuntimeError("mcp package not available. Install with: pip install mcp")
    mcp.run(transport="stdio")
