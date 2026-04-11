def route_workflow(workflow: str) -> str:
    allowed = {
        "threat_research",
        "hunt_generation",
        "detection_generation",
        "timeline_reconstruction",
        "log_explanation",
        "coverage_analysis",
        "report_comparison",
    }
    return workflow if workflow in allowed else "threat_research"
