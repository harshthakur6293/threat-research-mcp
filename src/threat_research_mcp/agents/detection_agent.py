from __future__ import annotations

from typing import Any, Dict, Optional

from threat_research_mcp.detection.cross_siem_drafts import build_detection_sidecar
from threat_research_mcp.tools.generate_detection_ideas import generate_detection_ideas
from threat_research_mcp.tools.generate_sigma import generate_sigma


def run_detection(text: str, research: Optional[Dict[str, Any]] = None) -> dict:
    research = research or {}
    side = build_detection_sidecar(text, research)
    title = "Generated Detection"
    if side.get("technique_ids"):
        title = f"Generated Detection ({', '.join(side['technique_ids'][:3])})"
    return {
        "sigma": generate_sigma(title, (text or "")[:400], "process_creation"),
        "ideas": generate_detection_ideas(text),
        "kql": side["kql"],
        "spl": side["spl"],
        "technique_ids": side["technique_ids"],
        "data_source_recommendations": side["data_source_recommendations"],
    }
