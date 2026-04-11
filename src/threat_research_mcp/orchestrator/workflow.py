from threat_research_mcp.agents.research_agent import run_research
from threat_research_mcp.agents.hunting_agent import run_hunting
from threat_research_mcp.agents.detection_agent import run_detection
from threat_research_mcp.agents.reviewer_agent import run_review
from threat_research_mcp.orchestrator.router import route_workflow
from threat_research_mcp.orchestrator.policy import defensive_policy_ok
from threat_research_mcp.orchestrator.formatter import format_output


def run_workflow(workflow: str, text: str) -> str:
    routed = route_workflow(workflow)
    if not defensive_policy_ok(text):
        return format_output({"status": "blocked", "reason": "defensive policy violation"})

    research = run_research(text)
    hunting = run_hunting(text) if routed in {"hunt_generation", "timeline_reconstruction", "log_explanation", "coverage_analysis"} else {}
    detection = run_detection(text) if routed in {"threat_research", "detection_generation", "coverage_analysis"} else {}
    review = run_review(research, hunting, detection)

    return format_output({
        "workflow": routed,
        "research": research,
        "hunting": hunting,
        "detection": detection,
        "review": review,
    })
