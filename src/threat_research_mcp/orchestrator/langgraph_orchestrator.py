"""
LangGraph-based orchestrator for multi-agent threat intelligence workflows.

This module implements the true multi-agent system using LangGraph, replacing
the sequential pipeline approach from v0.4.
"""

from typing import Literal, Optional
import logging

try:
    from langgraph.graph import StateGraph, END
    from langgraph.checkpoint.memory import MemorySaver

    LANGGRAPH_AVAILABLE = True
except ImportError:
    LANGGRAPH_AVAILABLE = False
    StateGraph = None
    END = None
    MemorySaver = None

from threat_research_mcp.schemas.workflow_state import ThreatAnalysisState
from threat_research_mcp.agents.base_agent import BaseAgent


logger = logging.getLogger(__name__)


class LangGraphOrchestrator:
    """
    LangGraph-based orchestrator for multi-agent threat intelligence workflows.

    This orchestrator manages the flow between Research, Hunting, Detection,
    and Reviewer agents using LangGraph's state management and conditional edges.

    Features:
    - True multi-agent collaboration (agents communicate via shared state)
    - Validation loops (automatic refinement when confidence < threshold)
    - Human-in-the-loop (prompts for feedback when needed)
    - Memory/checkpointing (context retention across analyses)
    - Conditional routing (dynamic workflow based on state)
    """

    def __init__(
        self,
        research_agent: Optional[BaseAgent] = None,
        hunting_agent: Optional[BaseAgent] = None,
        detection_agent: Optional[BaseAgent] = None,
        reviewer_agent: Optional[BaseAgent] = None,
        enable_memory: bool = True,
    ):
        """
        Initialize the LangGraph orchestrator.

        Args:
            research_agent: Agent for IOC extraction and enrichment
            hunting_agent: Agent for hunt hypothesis generation
            detection_agent: Agent for detection rule generation
            reviewer_agent: Agent for quality assurance and validation
            enable_memory: Whether to enable memory/checkpointing

        Raises:
            ImportError: If LangGraph is not installed
        """
        if not LANGGRAPH_AVAILABLE:
            raise ImportError(
                "LangGraph is not installed. Install with: "
                "pip install langgraph langchain langchain-core"
            )

        self.research_agent = research_agent
        self.hunting_agent = hunting_agent
        self.detection_agent = detection_agent
        self.reviewer_agent = reviewer_agent
        self.enable_memory = enable_memory

        # Build the workflow
        self.workflow = self._build_workflow()
        self.app = self._compile_workflow()

        logger.info("LangGraph orchestrator initialized")

    def _build_workflow(self) -> StateGraph:
        """
        Build the LangGraph workflow with agents and edges.

        Returns:
            Configured StateGraph
        """
        # Create workflow with ThreatAnalysisState
        workflow = StateGraph(ThreatAnalysisState)

        # Add agent nodes
        workflow.add_node("research", self._research_node)
        workflow.add_node("hunting", self._hunting_node)
        workflow.add_node("detection", self._detection_node)
        workflow.add_node("reviewer", self._reviewer_node)
        workflow.add_node("human_review", self._human_review_node)

        # Set entry point
        workflow.set_entry_point("research")

        # Define workflow edges
        # Research agent runs first
        workflow.add_edge("research", "hunting")
        workflow.add_edge("research", "detection")

        # Hunting and Detection run in parallel (both depend on Research)
        # Then both feed into Reviewer
        workflow.add_edge("hunting", "reviewer")
        workflow.add_edge("detection", "reviewer")

        # Conditional edges from Reviewer
        workflow.add_conditional_edges(
            "reviewer",
            self._should_refine_or_complete,
            {
                "refine": "research",  # Loop back for refinement
                "human_review": "human_review",  # Needs human input
                "complete": END,  # Analysis complete
            },
        )

        # After human review, go back to reviewer
        workflow.add_edge("human_review", "reviewer")

        return workflow

    def _compile_workflow(self):
        """
        Compile the workflow with optional memory/checkpointing.

        Returns:
            Compiled LangGraph application
        """
        if self.enable_memory:
            memory = MemorySaver()
            app = self.workflow.compile(checkpointer=memory)
            logger.info("Workflow compiled with memory enabled")
        else:
            app = self.workflow.compile()
            logger.info("Workflow compiled without memory")

        return app

    # Agent node functions

    def _research_node(self, state: ThreatAnalysisState) -> dict:
        """
        Execute the Research Agent.

        Args:
            state: Current workflow state

        Returns:
            Partial state update with research findings
        """
        logger.info("Executing Research Agent")

        if self.research_agent:
            result = self.research_agent.execute(state)
            # Only return the fields that were modified
            return {
                "research_findings": result.get("research_findings"),
                "agent_history": result.get("agent_history", state.get("agent_history", [])),
            }
        else:
            # Mock implementation for testing
            agent_history = state.get("agent_history", [])
            agent_history.append("research")
            return {
                "research_findings": {
                    "agent": "Research Agent",
                    "findings": {"iocs": [], "techniques": []},
                    "confidence": 0.8,
                },
                "agent_history": agent_history,
            }

    def _hunting_node(self, state: ThreatAnalysisState) -> dict:
        """
        Execute the Hunting Agent.

        Args:
            state: Current workflow state

        Returns:
            Partial state update with hunt plan
        """
        logger.info("Executing Hunting Agent")

        if self.hunting_agent:
            result = self.hunting_agent.execute(state)
            # Only return the fields that were modified
            return {
                "hunt_plan": result.get("hunt_plan"),
                "agent_history": result.get("agent_history", state.get("agent_history", [])),
            }
        else:
            # Mock implementation for testing
            agent_history = state.get("agent_history", [])
            agent_history.append("hunting")
            return {
                "hunt_plan": {
                    "agent": "Hunting Agent",
                    "findings": {"hypotheses": [], "queries": []},
                    "confidence": 0.75,
                },
                "agent_history": agent_history,
            }

    def _detection_node(self, state: ThreatAnalysisState) -> dict:
        """
        Execute the Detection Agent.

        Args:
            state: Current workflow state

        Returns:
            Partial state update with detection rules
        """
        logger.info("Executing Detection Agent")

        if self.detection_agent:
            result = self.detection_agent.execute(state)
            # Only return the fields that were modified
            return {
                "detections": result.get("detections"),
                "agent_history": result.get("agent_history", state.get("agent_history", [])),
            }
        else:
            # Mock implementation for testing
            agent_history = state.get("agent_history", [])
            agent_history.append("detection")
            return {
                "detections": {
                    "agent": "Detection Agent",
                    "findings": {"rules": []},
                    "confidence": 0.85,
                },
                "agent_history": agent_history,
            }

    def _reviewer_node(self, state: ThreatAnalysisState) -> dict:
        """
        Execute the Reviewer Agent.

        Args:
            state: Current workflow state

        Returns:
            Partial state update with review report
        """
        logger.info("Executing Reviewer Agent")

        if self.reviewer_agent:
            result = self.reviewer_agent.execute(state)
            # Only return the fields that were modified
            return {
                "review_report": result.get("review_report"),
                "needs_refinement": result.get("needs_refinement", False),
                "iteration": result.get("iteration", state.get("iteration", 0)),
                "agent_history": result.get("agent_history", state.get("agent_history", [])),
            }
        else:
            # Mock implementation for testing
            # Calculate overall confidence
            confidences = []
            if state.get("research_findings"):
                confidences.append(state["research_findings"].get("confidence", 0))
            if state.get("hunt_plan"):
                confidences.append(state["hunt_plan"].get("confidence", 0))
            if state.get("detections"):
                confidences.append(state["detections"].get("confidence", 0))

            overall_confidence = sum(confidences) / len(confidences) if confidences else 0
            needs_refinement = overall_confidence < 0.7

            agent_history = state.get("agent_history", [])
            agent_history.append("reviewer")

            # Increment iteration if refinement is needed
            iteration = state.get("iteration", 0)
            if needs_refinement:
                iteration += 1

            return {
                "review_report": {
                    "agent": "Reviewer Agent",
                    "findings": {
                        "overall_confidence": overall_confidence,
                        "issues": [],
                        "validation_passed": overall_confidence >= 0.7,
                    },
                    "confidence": overall_confidence,
                },
                "needs_refinement": needs_refinement,
                "iteration": iteration,
                "agent_history": agent_history,
            }

    def _human_review_node(self, state: ThreatAnalysisState) -> dict:
        """
        Handle human-in-the-loop review.

        Args:
            state: Current workflow state

        Returns:
            Partial state update with human feedback
        """
        logger.info("Human review required")

        # In a real implementation, this would prompt the user
        # For now, we'll just log and continue
        iteration = state.get("iteration", 0) + 1
        agent_history = state.get("agent_history", [])
        agent_history.append("human_review")

        return {
            "human_feedback": "Human review completed",
            "needs_refinement": False,
            "iteration": iteration,
            "agent_history": agent_history,
        }

    def _should_refine_or_complete(
        self, state: ThreatAnalysisState
    ) -> Literal["refine", "human_review", "complete"]:
        """
        Determine whether to refine, request human review, or complete.

        Args:
            state: Current workflow state

        Returns:
            Next step: "refine", "human_review", or "complete"
        """
        iteration = state.get("iteration", 0)
        max_iterations = state.get("max_iterations", 3)
        needs_refinement = state.get("needs_refinement", False)

        review_report = state.get("review_report", {})
        overall_confidence = review_report.get("findings", {}).get("overall_confidence", 0)

        # Check if we've hit max iterations
        if iteration >= max_iterations:
            logger.warning(f"Max iterations ({max_iterations}) reached")
            return "complete"

        # Check if refinement is needed
        if needs_refinement and overall_confidence < 0.7:
            logger.info(f"Refinement needed (iteration {iteration + 1})")
            return "refine"

        # Check if human review is needed
        if overall_confidence < 0.5:
            logger.info("Low confidence, requesting human review")
            return "human_review"

        # Analysis complete
        logger.info("Analysis complete")
        return "complete"

    def run(self, state: ThreatAnalysisState, config: Optional[dict] = None) -> ThreatAnalysisState:
        """
        Run the workflow with the given initial state.

        Args:
            state: Initial workflow state
            config: Optional LangGraph configuration (for thread_id, etc.)

        Returns:
            Final workflow state after all agents have executed
        """
        logger.info(f"Starting workflow for analysis {state.get('analysis_id')}")

        # Run the workflow
        final_state = self.app.invoke(state, config=config or {})

        logger.info("Workflow completed")
        return final_state

    async def arun(
        self, state: ThreatAnalysisState, config: Optional[dict] = None
    ) -> ThreatAnalysisState:
        """
        Run the workflow asynchronously.

        Args:
            state: Initial workflow state
            config: Optional LangGraph configuration

        Returns:
            Final workflow state
        """
        logger.info(f"Starting async workflow for analysis {state.get('analysis_id')}")

        # Run the workflow asynchronously
        final_state = await self.app.ainvoke(state, config=config or {})

        logger.info("Async workflow completed")
        return final_state


def create_orchestrator(
    research_agent: Optional[BaseAgent] = None,
    hunting_agent: Optional[BaseAgent] = None,
    detection_agent: Optional[BaseAgent] = None,
    reviewer_agent: Optional[BaseAgent] = None,
    enable_memory: bool = True,
) -> LangGraphOrchestrator:
    """
    Factory function to create a LangGraph orchestrator.

    Args:
        research_agent: Agent for IOC extraction and enrichment
        hunting_agent: Agent for hunt hypothesis generation
        detection_agent: Agent for detection rule generation
        reviewer_agent: Agent for quality assurance and validation
        enable_memory: Whether to enable memory/checkpointing

    Returns:
        Configured LangGraphOrchestrator instance
    """
    return LangGraphOrchestrator(
        research_agent=research_agent,
        hunting_agent=hunting_agent,
        detection_agent=detection_agent,
        reviewer_agent=reviewer_agent,
        enable_memory=enable_memory,
    )
