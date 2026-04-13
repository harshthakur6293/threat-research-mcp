from __future__ import annotations

from threat_research_mcp.tools.extract_iocs import extract_iocs_json
from threat_research_mcp.tools.ingest_tools import (
    ingest_from_config_path_json,
    intel_to_analysis_product_json,
)
from threat_research_mcp.tools.summarize_threat_report import summarize_threat_report
from threat_research_mcp.tools.map_attack import map_attack
from threat_research_mcp.tools.generate_sigma import generate_sigma
from threat_research_mcp.tools.explain_log import explain_log
from threat_research_mcp.tools.reconstruct_timeline import reconstruct_timeline
from threat_research_mcp.tools.generate_hunt_hypothesis import generate_hunt_hypothesis
from threat_research_mcp.tools.detection_gap_analysis import detection_gap_analysis
from threat_research_mcp.tools.validate_sigma import validate_sigma_json
from threat_research_mcp.tools.intel_storage_tools import (
    get_stored_analysis_product_json,
    search_analysis_product_history_json,
    search_ingested_intel_json,
)
from threat_research_mcp.tools.recommend_log_sources import recommend_log_sources_json
from threat_research_mcp.tools.intel_to_log_sources import intel_to_log_sources_json
from threat_research_mcp.tools.enhanced_analysis import (
    enhanced_intel_analysis,
    get_integration_status,
)

try:
    from mcp.server.fastmcp import FastMCP
except Exception:
    FastMCP = None


if FastMCP:
    mcp = FastMCP("Threat Research MCP")

    @mcp.tool()
    def extract_iocs(text: str) -> str:
        return extract_iocs_json(text)

    @mcp.tool()
    def summarize(text: str) -> str:
        return summarize_threat_report(text)

    @mcp.tool()
    def attack_map(text: str) -> str:
        return map_attack(text)

    @mcp.tool()
    def sigma(title: str, behavior: str, logsource: str = "process_creation") -> str:
        return generate_sigma(title, behavior, logsource)

    @mcp.tool()
    def explain(text: str) -> str:
        return explain_log(text)

    @mcp.tool()
    def timeline(text: str) -> str:
        return reconstruct_timeline(text)

    @mcp.tool()
    def hunt(text: str) -> str:
        return generate_hunt_hypothesis(text)

    @mcp.tool()
    def coverage(techniques_csv: str, detections_csv: str) -> str:
        return detection_gap_analysis(techniques_csv, detections_csv)

    @mcp.tool()
    def validate_sigma(yaml_text: str) -> str:
        """Check Sigma YAML for required fields (title, logsource, detection); returns JSON {valid, errors}."""
        return validate_sigma_json(yaml_text)

    @mcp.tool()
    def ingest_sources(config_path: str) -> str:
        """Load a YAML or JSON sources file (see configs/sources.example.yaml) and return normalized documents."""
        return ingest_from_config_path_json(config_path)

    @mcp.tool()
    def intel_to_analysis_product(
        text: str = "",
        sources_config_path: str = "",
        workflow: str = "threat_research",
    ) -> str:
        """Merge optional analyst `text` with documents from `sources_config_path`, then return AnalysisProduct JSON."""
        return intel_to_analysis_product_json(
            text=text,
            sources_config_path=sources_config_path,
            workflow=workflow,
        )

    @mcp.tool()
    def analysis_product(text: str, workflow: str = "threat_research") -> str:
        """Run the workflow on `text` only; return canonical AnalysisProduct JSON (v1 schema)."""
        return intel_to_analysis_product_json(text=text, sources_config_path="", workflow=workflow)

    @mcp.tool()
    def search_ingested_intel(
        text_query: str = "",
        source_name: str = "",
        fingerprint: str = "",
        limit: int = 30,
        offset: int = 0,
    ) -> str:
        """Search persisted normalized documents (requires THREAT_RESEARCH_MCP_DB)."""
        return search_ingested_intel_json(
            text_query=text_query,
            source_name=source_name,
            fingerprint=fingerprint,
            limit=limit,
            offset=offset,
        )

    @mcp.tool()
    def search_analysis_product_history(
        text_query: str = "",
        workflow: str = "",
        limit: int = 30,
        offset: int = 0,
    ) -> str:
        """Search persisted analysis products by narrative or JSON substring."""
        return search_analysis_product_history_json(
            text_query=text_query,
            workflow=workflow,
            limit=limit,
            offset=offset,
        )

    @mcp.tool()
    def get_stored_analysis_product(row_id: int) -> str:
        """Load full AnalysisProduct JSON by `row_id` from search_analysis_product_history results."""
        return get_stored_analysis_product_json(row_id)

    @mcp.tool()
    def recommend_log_sources(
        technique_ids: str,
        environment: str = "hybrid",
        siem_platforms: str = "splunk,sentinel,elastic",
    ) -> str:
        """Get specific log source recommendations and ready-to-run hunt queries for ATT&CK techniques.

        Args:
            technique_ids: Comma-separated ATT&CK technique IDs (e.g., "T1059.001,T1566.001")
            environment: Target environment (aws, azure, gcp, on-prem, hybrid)
            siem_platforms: Comma-separated SIEM platforms (splunk, sentinel, elastic, athena, chronicle)

        Returns:
            JSON with prioritized log sources, SIEM-specific queries, and deployment checklist
        """
        return recommend_log_sources_json(technique_ids, environment, siem_platforms)

    @mcp.tool()
    def intel_to_log_sources(
        intel_text: str,
        environment: str = "hybrid",
        siem_platforms: str = "splunk,sentinel,elastic",
        manual_techniques: str = "",
    ) -> str:
        """Automatically analyze threat intel, detect ATT&CK techniques, and get log source recommendations.

        This is the complete automated pipeline:
        1. Analyze threat intelligence text
        2. Auto-detect relevant ATT&CK techniques (can be supplemented with manual_techniques)
        3. Generate log source recommendations
        4. Provide ready-to-run SIEM queries
        5. Create prioritized deployment checklist

        Args:
            intel_text: Threat intelligence text to analyze (incident reports, IOCs, TTPs, etc.)
            environment: Target environment (aws, azure, gcp, on-prem, hybrid)
            siem_platforms: Comma-separated SIEM platforms (splunk, sentinel, elastic, athena, chronicle)
            manual_techniques: Optional comma-separated technique IDs to supplement auto-detection

        Returns:
            JSON with detected techniques, log sources, queries, and deployment guidance

        Example:
            intel_text="ICP Canister C2 using blockchain for censorship-resistant command and control"
            Returns: Detected techniques (T1071.001, T1090), log sources, and queries
        """
        return intel_to_log_sources_json(intel_text, environment, siem_platforms, manual_techniques)

    @mcp.tool()
    def enhanced_intel_analysis_tool(
        intel_text: str,
        environment: str = "hybrid",
        siem_platforms: str = "splunk,sentinel,elastic",
        enrich_iocs: bool = True,
        check_coverage: bool = True,
        generate_behavioral_hunts: bool = True,
    ) -> str:
        """Enhanced threat intelligence analysis using all available MCP integrations.

        This tool orchestrates multiple MCPs to provide comprehensive analysis:
        - Auto-detect ATT&CK techniques (built-in)
        - Generate log sources and SIEM queries (built-in)
        - Enrich IOCs (fastmcp-threatintel, if available)
        - Check existing coverage (Security-Detections-MCP, if available)
        - Generate behavioral hunts (threat-hunting-mcp, if available)

        All integrations are OPTIONAL. The tool works standalone and gracefully
        degrades when optional MCPs are not installed.

        Args:
            intel_text: Threat intelligence text to analyze
            environment: Target environment (aws, azure, gcp, on-prem, hybrid)
            siem_platforms: Comma-separated SIEM platforms
            enrich_iocs: Enable IOC enrichment (requires fastmcp-threatintel)
            check_coverage: Enable coverage check (requires Security-Detections-MCP)
            generate_behavioral_hunts: Enable behavioral hunts (requires threat-hunting-mcp)

        Returns:
            JSON with comprehensive analysis including all available integrations
        """
        return enhanced_intel_analysis(
            intel_text=intel_text,
            environment=environment,
            siem_platforms=siem_platforms,
            enrich_iocs=enrich_iocs,
            check_coverage=check_coverage,
            generate_behavioral_hunts=generate_behavioral_hunts,
        )

    @mcp.tool()
    def get_integration_status_tool() -> str:
        """Get status of all optional MCP integrations.

        Returns:
            JSON with integration availability and setup instructions
        """
        return get_integration_status()


def main() -> None:
    if FastMCP is None:
        raise RuntimeError("mcp package not available. Install dependencies.")
    mcp.run(transport="stdio")
