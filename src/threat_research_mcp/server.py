from __future__ import annotations

from threat_research_mcp.tools.extract_iocs import extract_iocs_json
from threat_research_mcp.tools.ingest_tools import ingest_from_config_path_json, intel_to_analysis_product_json
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


def main() -> None:
    if FastMCP is None:
        raise RuntimeError("mcp package not available. Install dependencies.")
    mcp.run(transport="stdio")
