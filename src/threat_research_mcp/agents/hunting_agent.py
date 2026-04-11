from threat_research_mcp.tools.generate_hunt_hypothesis import generate_hunt_hypothesis
from threat_research_mcp.tools.explain_log import explain_log
from threat_research_mcp.tools.reconstruct_timeline import reconstruct_timeline


def run_hunting(text: str) -> dict:
    return {
        "hypothesis": generate_hunt_hypothesis(text),
        "timeline": reconstruct_timeline(text),
        "log_explanation": explain_log(text),
    }
