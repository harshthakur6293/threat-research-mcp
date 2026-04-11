from threat_research_mcp.tools.generate_sigma import generate_sigma
from threat_research_mcp.tools.generate_detection_ideas import generate_detection_ideas


def run_detection(text: str) -> dict:
    return {
        "sigma": generate_sigma("Generated Detection", text[:80]),
        "ideas": generate_detection_ideas(text),
    }
