from __future__ import annotations

from threat_research_mcp.tools.extract_iocs import extract_iocs_json
from threat_research_mcp.tools.summarize_threat_report import summarize_threat_report
from threat_research_mcp.tools.map_attack import map_attack
from threat_research_mcp.tools.generate_sigma import generate_sigma
from threat_research_mcp.tools.explain_log import explain_log
from threat_research_mcp.tools.reconstruct_timeline import reconstruct_timeline
from threat_research_mcp.tools.generate_hunt_hypothesis import generate_hunt_hypothesis
from threat_research_mcp.tools.detection_gap_analysis import detection_gap_analysis

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


def main() -> None:
    if FastMCP is None:
        raise RuntimeError("mcp package not available. Install dependencies.")
    mcp.run(transport="stdio")
