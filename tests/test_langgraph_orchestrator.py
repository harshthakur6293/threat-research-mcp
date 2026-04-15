"""
Tests for the LangGraph orchestrator.

These tests verify the multi-agent workflow, state management,
validation loops, and agent communication.
"""

import pytest
from unittest.mock import patch

# Import with fallback for when LangGraph is not installed
try:
    from threat_research_mcp.orchestrator.langgraph_orchestrator import (
        LangGraphOrchestrator,
        create_orchestrator,
        LANGGRAPH_AVAILABLE,
    )
    from threat_research_mcp.schemas.workflow_state import (
        ThreatAnalysisState,
        create_initial_state,
    )
    from threat_research_mcp.agents.base_agent import BaseAgent, MockAgent
except ImportError as e:
    pytest.skip(f"LangGraph not available: {e}", allow_module_level=True)


# Skip all tests if LangGraph is not available
pytestmark = pytest.mark.skipif(
    not LANGGRAPH_AVAILABLE,
    reason="LangGraph not installed (requires Python 3.9+)"
)


class TestWorkflowState:
    """Tests for the ThreatAnalysisState schema."""
    
    def test_create_initial_state(self):
        """Test creating an initial workflow state."""
        state = create_initial_state(
            intel_text="Test threat intelligence",
            api_keys={"virustotal": "test_key"},
            target_platforms=["splunk"],
            framework="PEAK",
        )
        
        # Check input fields
        assert state["intel_text"] == "Test threat intelligence"
        assert state["api_keys"] == {"virustotal": "test_key"}
        assert state["target_platforms"] == ["splunk"]
        assert state["framework"] == "PEAK"
        
        # Check agent outputs are None
        assert state["research_findings"] is None
        assert state["hunt_plan"] is None
        assert state["detections"] is None
        assert state["review_report"] is None
        
        # Check control flow
        assert state["iteration"] == 0
        assert state["needs_refinement"] is False
        assert state["human_feedback"] is None
        assert state["max_iterations"] == 3
        
        # Check metadata
        assert "analysis_id" in state
        assert "timestamp" in state
        assert state["agent_history"] == []
    
    def test_create_initial_state_defaults(self):
        """Test creating initial state with default values."""
        state = create_initial_state(intel_text="Test")
        
        assert state["api_keys"] == {}
        assert state["target_platforms"] == ["splunk", "sentinel"]
        assert state["framework"] == "PEAK"
        assert state["environment"] == "hybrid"
        assert state["max_iterations"] == 3


class TestBaseAgent:
    """Tests for the BaseAgent abstract class."""
    
    def test_mock_agent_execution(self):
        """Test MockAgent execution."""
        agent = MockAgent(name="Test Agent", output_field="test_output")
        
        state = create_initial_state(intel_text="Test intelligence")
        result = agent.execute(state)
        
        # Check output was created
        assert "test_output" in result
        assert result["test_output"]["agent"] == "Test Agent"
        assert result["test_output"]["confidence"] == 0.95
        
        # Check agent history
        assert "Test Agent" in result["agent_history"]
    
    def test_mock_agent_validation(self):
        """Test MockAgent input validation."""
        agent = MockAgent()
        
        # Missing required field
        state = ThreatAnalysisState()
        
        with pytest.raises(ValueError, match="missing required fields"):
            agent.execute(state)


class TestLangGraphOrchestrator:
    """Tests for the LangGraph orchestrator."""
    
    def test_orchestrator_initialization(self):
        """Test orchestrator initialization."""
        orchestrator = LangGraphOrchestrator(enable_memory=True)
        
        assert orchestrator.enable_memory is True
        assert orchestrator.workflow is not None
        assert orchestrator.app is not None
    
    def test_orchestrator_without_memory(self):
        """Test orchestrator without memory/checkpointing."""
        orchestrator = LangGraphOrchestrator(enable_memory=False)
        
        assert orchestrator.enable_memory is False
        assert orchestrator.app is not None
    
    def test_simple_workflow_execution(self):
        """Test simple workflow execution with mock agents."""
        orchestrator = LangGraphOrchestrator(enable_memory=False)
        
        state = create_initial_state(
            intel_text="APT29 using PowerShell for initial access"
        )
        
        result = orchestrator.run(state)
        
        # Check all agents executed
        assert result["research_findings"] is not None
        assert result["hunt_plan"] is not None
        assert result["detections"] is not None
        assert result["review_report"] is not None
        
        # Check review report
        review = result["review_report"]
        assert "overall_confidence" in review["findings"]
        assert "validation_passed" in review["findings"]
    
    def test_workflow_with_custom_agents(self):
        """Test workflow with custom agent implementations."""
        # Create custom agents
        research_agent = MockAgent(name="Custom Research", output_field="research_findings")
        hunting_agent = MockAgent(name="Custom Hunting", output_field="hunt_plan")
        detection_agent = MockAgent(name="Custom Detection", output_field="detections")
        reviewer_agent = MockAgent(name="Custom Reviewer", output_field="review_report")
        
        orchestrator = LangGraphOrchestrator(
            research_agent=research_agent,
            hunting_agent=hunting_agent,
            detection_agent=detection_agent,
            reviewer_agent=reviewer_agent,
            enable_memory=False,
        )
        
        state = create_initial_state(intel_text="Test intelligence")
        result = orchestrator.run(state)
        
        # Check custom agents executed
        assert result["research_findings"]["agent"] == "Custom Research"
        assert result["hunt_plan"]["agent"] == "Custom Hunting"
        assert result["detections"]["agent"] == "Custom Detection"
        assert result["review_report"]["agent"] == "Custom Reviewer"
    
    def test_validation_loop_trigger(self):
        """Test that validation loop triggers on low confidence."""
        # Create a reviewer that always returns low confidence
        class LowConfidenceReviewer(BaseAgent):
            def execute(self, state: ThreatAnalysisState) -> ThreatAnalysisState:
                state["review_report"] = {
                    "agent": "Low Confidence Reviewer",
                    "findings": {
                        "overall_confidence": 0.5,
                        "issues": ["Low confidence"],
                        "validation_passed": False
                    },
                    "confidence": 0.5
                }
                state["needs_refinement"] = True
                return self._record_execution(state)
        
        orchestrator = LangGraphOrchestrator(
            reviewer_agent=LowConfidenceReviewer("Low Confidence Reviewer"),
            enable_memory=False,
        )
        
        state = create_initial_state(
            intel_text="Test",
            max_iterations=2  # Limit iterations for test
        )
        
        result = orchestrator.run(state)
        
        # Check that iteration count increased
        assert result["iteration"] > 0
        assert result["iteration"] <= 2  # Should stop at max_iterations
    
    def test_conditional_routing_complete(self):
        """Test conditional routing to completion."""
        orchestrator = LangGraphOrchestrator(enable_memory=False)
        
        state = create_initial_state(intel_text="Test")
        
        # Manually set high confidence
        state["review_report"] = {
            "findings": {"overall_confidence": 0.9, "validation_passed": True}
        }
        state["needs_refinement"] = False
        
        decision = orchestrator._should_refine_or_complete(state)
        assert decision == "complete"
    
    def test_conditional_routing_refine(self):
        """Test conditional routing to refinement."""
        orchestrator = LangGraphOrchestrator(enable_memory=False)
        
        state = create_initial_state(intel_text="Test")
        
        # Set low confidence
        state["review_report"] = {
            "findings": {"overall_confidence": 0.6, "validation_passed": False}
        }
        state["needs_refinement"] = True
        state["iteration"] = 0
        state["max_iterations"] = 3
        
        decision = orchestrator._should_refine_or_complete(state)
        assert decision == "refine"
        assert state["iteration"] == 1  # Should increment
    
    def test_conditional_routing_human_review(self):
        """Test conditional routing to human review."""
        orchestrator = LangGraphOrchestrator(enable_memory=False)
        
        state = create_initial_state(intel_text="Test")
        
        # Set very low confidence
        state["review_report"] = {
            "findings": {"overall_confidence": 0.4, "validation_passed": False}
        }
        state["needs_refinement"] = True
        
        decision = orchestrator._should_refine_or_complete(state)
        assert decision == "human_review"
    
    def test_max_iterations_limit(self):
        """Test that workflow stops at max iterations."""
        orchestrator = LangGraphOrchestrator(enable_memory=False)
        
        state = create_initial_state(intel_text="Test", max_iterations=2)
        
        # Set conditions for refinement
        state["review_report"] = {
            "findings": {"overall_confidence": 0.6, "validation_passed": False}
        }
        state["needs_refinement"] = True
        state["iteration"] = 2  # At max
        
        decision = orchestrator._should_refine_or_complete(state)
        assert decision == "complete"  # Should complete despite low confidence
    
    def test_factory_function(self):
        """Test the create_orchestrator factory function."""
        orchestrator = create_orchestrator(enable_memory=True)
        
        assert isinstance(orchestrator, LangGraphOrchestrator)
        assert orchestrator.enable_memory is True
    
    def test_agent_communication(self):
        """Test that agents can communicate via shared state."""
        # Create an agent that reads from research_findings
        class DependentAgent(BaseAgent):
            def execute(self, state: ThreatAnalysisState) -> ThreatAnalysisState:
                # Read from research findings
                research = state.get("research_findings", {})
                
                # Create output based on research
                state["hunt_plan"] = {
                    "agent": self.name,
                    "findings": {
                        "based_on_research": research.get("findings", {})
                    },
                    "confidence": 0.8
                }
                
                return self._record_execution(state)
        
        research_agent = MockAgent(name="Research", output_field="research_findings")
        hunting_agent = DependentAgent("Dependent Hunting")
        
        orchestrator = LangGraphOrchestrator(
            research_agent=research_agent,
            hunting_agent=hunting_agent,
            enable_memory=False,
        )
        
        state = create_initial_state(intel_text="Test")
        result = orchestrator.run(state)
        
        # Check that hunting agent received research findings
        hunt_plan = result["hunt_plan"]
        assert "based_on_research" in hunt_plan["findings"]
    
    @pytest.mark.asyncio
    async def test_async_workflow_execution(self):
        """Test asynchronous workflow execution."""
        orchestrator = LangGraphOrchestrator(enable_memory=False)
        
        state = create_initial_state(intel_text="Test async")
        result = await orchestrator.arun(state)
        
        # Check workflow completed
        assert result["research_findings"] is not None
        assert result["review_report"] is not None


class TestMemoryAndCheckpointing:
    """Tests for memory and checkpointing functionality."""
    
    def test_memory_enabled(self):
        """Test that memory is enabled when requested."""
        orchestrator = LangGraphOrchestrator(enable_memory=True)
        assert orchestrator.enable_memory is True
    
    def test_workflow_with_thread_id(self):
        """Test workflow execution with thread_id for memory."""
        orchestrator = LangGraphOrchestrator(enable_memory=True)
        
        state = create_initial_state(intel_text="Test with memory")
        
        # Run with thread_id
        config = {"configurable": {"thread_id": "test-thread-1"}}
        result = orchestrator.run(state, config=config)
        
        assert result is not None
        assert result["research_findings"] is not None


class TestErrorHandling:
    """Tests for error handling and edge cases."""
    
    def test_missing_langgraph_import(self):
        """Test graceful handling when LangGraph is not installed."""
        with patch("threat_research_mcp.orchestrator.langgraph_orchestrator.LANGGRAPH_AVAILABLE", False):
            with pytest.raises(ImportError, match="LangGraph is not installed"):
                LangGraphOrchestrator()
    
    def test_empty_intel_text(self):
        """Test handling of empty intel text."""
        orchestrator = LangGraphOrchestrator(enable_memory=False)
        
        state = create_initial_state(intel_text="")
        result = orchestrator.run(state)
        
        # Should still complete workflow
        assert result is not None
    
    def test_invalid_state_fields(self):
        """Test handling of invalid state fields."""
        orchestrator = LangGraphOrchestrator(enable_memory=False)
        
        # Create state with missing fields
        state = ThreatAnalysisState(
            intel_text="Test",
            iteration=0,
            needs_refinement=False,
            max_iterations=3,
        )
        
        # Should still work with defaults
        result = orchestrator.run(state)
        assert result is not None


# Integration test
class TestEndToEndWorkflow:
    """End-to-end integration tests."""
    
    def test_complete_analysis_workflow(self):
        """Test a complete analysis workflow from start to finish."""
        orchestrator = create_orchestrator(enable_memory=False)
        
        # Create realistic initial state
        state = create_initial_state(
            intel_text="""
            APT29 (Cozy Bear) campaign detected using PowerShell for initial access.
            Observed IOCs:
            - IP: 185.220.101.45
            - Domain: malicious-c2.com
            - Hash: 1234567890abcdef
            
            Techniques:
            - T1059.001: PowerShell
            - T1071.001: Web Protocol C2
            """,
            api_keys={"virustotal": "test_key"},
            target_platforms=["splunk", "sentinel"],
            framework="PEAK",
            environment="hybrid",
        )
        
        # Run workflow
        result = orchestrator.run(state)
        
        # Verify all stages completed
        assert result["research_findings"] is not None
        assert result["hunt_plan"] is not None
        assert result["detections"] is not None
        assert result["review_report"] is not None
        
        # Verify metadata
        assert result["analysis_id"] is not None
        assert result["timestamp"] is not None
        
        # Verify workflow completed
        review = result["review_report"]
        assert "overall_confidence" in review["findings"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
