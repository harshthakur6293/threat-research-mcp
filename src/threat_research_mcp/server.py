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


def main() -> None:
    if FastMCP is None:
        raise RuntimeError("mcp package not available. Install with: pip install mcp")
    mcp.run(transport="stdio")
