"""
Base agent class for the multi-agent threat intelligence system.

All agents in the system inherit from BaseAgent and implement the execute method.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
import logging

from threat_research_mcp.schemas.workflow_state import ThreatAnalysisState


logger = logging.getLogger(__name__)


class BaseAgent(ABC):
    """
    Abstract base class for all agents in the threat intelligence system.
    
    Each agent:
    1. Reads from the shared ThreatAnalysisState
    2. Performs its specialized analysis
    3. Updates the state with its findings
    4. Returns the updated state
    
    Agents should be stateless and idempotent where possible.
    """
    
    def __init__(self, name: str):
        """
        Initialize the base agent.
        
        Args:
            name: Human-readable name for this agent (e.g., "Research Agent")
        """
        self.name = name
        self.logger = logging.getLogger(f"{__name__}.{name}")
    
    @abstractmethod
    def execute(self, state: ThreatAnalysisState) -> ThreatAnalysisState:
        """
        Execute the agent's logic and update the state.
        
        This method must be implemented by all concrete agents.
        
        Args:
            state: Current workflow state
        
        Returns:
            Updated workflow state with agent's findings
        
        Raises:
            Exception: If agent execution fails
        """
        pass
    
    def _record_execution(self, state: ThreatAnalysisState) -> ThreatAnalysisState:
        """
        Record this agent's execution in the state history.
        
        Args:
            state: Current workflow state
        
        Returns:
            State with updated agent_history
        """
        if state.get("agent_history") is None:
            state["agent_history"] = []
        
        state["agent_history"].append(self.name)
        self.logger.info(f"{self.name} executed (iteration {state.get('iteration', 0)})")
        
        return state
    
    def _validate_input(self, state: ThreatAnalysisState, required_fields: list) -> None:
        """
        Validate that required fields are present in the state.
        
        Args:
            state: Current workflow state
            required_fields: List of required field names
        
        Raises:
            ValueError: If any required field is missing
        """
        missing_fields = [field for field in required_fields if not state.get(field)]
        
        if missing_fields:
            raise ValueError(
                f"{self.name} missing required fields: {', '.join(missing_fields)}"
            )
    
    def _create_output(
        self,
        findings: Dict[str, Any],
        confidence: float,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Create a standardized output structure for agent findings.
        
        Args:
            findings: The agent's analysis findings
            confidence: Confidence score (0.0-1.0)
            metadata: Optional additional metadata
        
        Returns:
            Standardized output dictionary
        """
        output = {
            "agent": self.name,
            "findings": findings,
            "confidence": confidence,
            "metadata": metadata or {},
        }
        
        return output


class MockAgent(BaseAgent):
    """
    Mock agent for testing purposes.
    
    This agent simply echoes back the input with a mock finding.
    """
    
    def __init__(self, name: str = "Mock Agent", output_field: str = "mock_output"):
        """
        Initialize the mock agent.
        
        Args:
            name: Agent name
            output_field: State field to write output to
        """
        super().__init__(name)
        self.output_field = output_field
    
    def execute(self, state: ThreatAnalysisState) -> ThreatAnalysisState:
        """
        Execute mock analysis.
        
        Args:
            state: Current workflow state
        
        Returns:
            State with mock findings
        """
        self._validate_input(state, ["intel_text"])
        
        # Create mock output
        output = self._create_output(
            findings={"message": f"{self.name} processed the input"},
            confidence=0.95,
            metadata={"intel_length": len(state["intel_text"])}
        )
        
        # Update state
        state[self.output_field] = output
        
        # Record execution
        return self._record_execution(state)
