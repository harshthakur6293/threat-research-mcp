"""
LangGraph workflow state schema for multi-agent threat analysis.

This module defines the shared state that flows between agents in the
LangGraph workflow. Each agent reads from and writes to this state.
"""

from typing import TypedDict, Optional, Dict, List, Any
import operator

try:
    from typing import Annotated
except ImportError:
    from typing_extensions import Annotated


class ThreatAnalysisState(TypedDict, total=False):
    """
    Shared state for the threat analysis workflow.

    This state is passed between agents and updated as the analysis progresses.
    Each agent reads relevant fields and updates its output fields.

    Attributes:
        # Input fields
        intel_text: Raw threat intelligence text to analyze
        api_keys: Dictionary of API keys for enrichment sources (BYOK)
        target_platforms: List of target SIEM platforms (e.g., ["splunk", "sentinel"])
        framework: Hunting framework to use (e.g., "PEAK", "TaHiTI", "SQRRL")
        environment: Environment type (e.g., "aws", "azure", "on-prem")

        # Agent output fields
        research_findings: Output from Research Agent (IOCs, enrichment, confidence)
        hunt_plan: Output from Hunting Agent (hypotheses, queries, expected behaviors)
        detections: Output from Detection Agent (rules, validation, tuning)
        review_report: Output from Reviewer Agent (validation, confidence, issues)

        # Control flow fields
        iteration: Current iteration number (for validation loops)
        needs_refinement: Whether the analysis needs refinement
        human_feedback: Optional feedback from human reviewer
        max_iterations: Maximum number of refinement iterations (default: 3)

        # Metadata fields
        analysis_id: Unique identifier for this analysis
        timestamp: ISO timestamp when analysis started
        agent_history: List of agents that have processed this state
    """

    # Input fields
    intel_text: str
    api_keys: Dict[str, str]
    target_platforms: List[str]
    framework: str
    environment: str

    # Agent output fields
    research_findings: Optional[Dict[str, Any]]
    hunt_plan: Optional[Dict[str, Any]]
    detections: Optional[Dict[str, Any]]
    review_report: Optional[Dict[str, Any]]

    # Control flow fields
    iteration: int
    needs_refinement: bool
    human_feedback: Optional[str]
    max_iterations: int

    # Metadata fields
    analysis_id: Optional[str]
    timestamp: Optional[str]
    agent_history: Annotated[List[str], operator.add]  # Use operator.add to concatenate lists


def create_initial_state(
    intel_text: str,
    api_keys: Optional[Dict[str, str]] = None,
    target_platforms: Optional[List[str]] = None,
    framework: str = "PEAK",
    environment: str = "hybrid",
    max_iterations: int = 3,
) -> ThreatAnalysisState:
    """
    Create an initial state for the threat analysis workflow.

    Args:
        intel_text: Raw threat intelligence text to analyze
        api_keys: Optional dictionary of API keys for enrichment sources
        target_platforms: Optional list of target SIEM platforms
        framework: Hunting framework to use (default: "PEAK")
        environment: Environment type (default: "hybrid")
        max_iterations: Maximum number of refinement iterations (default: 3)

    Returns:
        Initial ThreatAnalysisState ready for workflow execution
    """
    import uuid
    from datetime import datetime, timezone

    return ThreatAnalysisState(
        # Input
        intel_text=intel_text,
        api_keys=api_keys or {},
        target_platforms=target_platforms or ["splunk", "sentinel"],
        framework=framework,
        environment=environment,
        # Agent outputs (initially None)
        research_findings=None,
        hunt_plan=None,
        detections=None,
        review_report=None,
        # Control flow
        iteration=0,
        needs_refinement=False,
        human_feedback=None,
        max_iterations=max_iterations,
        # Metadata
        analysis_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc).isoformat(),
        agent_history=[],
    )
