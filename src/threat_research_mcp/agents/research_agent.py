from threat_research_mcp.tools.extract_iocs import extract_iocs_from_text
from threat_research_mcp.tools.summarize_threat_report import summarize_threat_report
from threat_research_mcp.tools.map_attack import map_attack


def run_research(text: str) -> dict:
    return {
        "summary": summarize_threat_report(text),
        "iocs": extract_iocs_from_text(text),
        "attack": map_attack(text),
    }
