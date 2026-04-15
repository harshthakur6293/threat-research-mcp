#!/usr/bin/env python3
"""
Demo script for the LangGraph multi-agent workflow.

This script demonstrates the new LangGraph-based orchestrator
with a realistic threat intelligence analysis scenario.

Usage:
    python examples/demo_langgraph_workflow.py
"""

import sys
import json
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

try:
    from threat_research_mcp.orchestrator.langgraph_orchestrator import (
        create_orchestrator,
        LANGGRAPH_AVAILABLE,
    )
    from threat_research_mcp.schemas.workflow_state import create_initial_state
except ImportError as e:
    print(f"❌ Error: {e}")
    print("\n💡 Make sure to install the project:")
    print("   pip install -e .")
    print("\n💡 And install LangGraph (requires Python 3.9+):")
    print("   pip install langgraph langchain langchain-core")
    sys.exit(1)


def print_section(title: str):
    """Print a formatted section header."""
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def print_result(label: str, data: dict):
    """Print formatted result data."""
    print(f"\n{label}:")
    print(json.dumps(data, indent=2))


def demo_simple_workflow():
    """Demo 1: Simple workflow with mock agents."""
    print_section("Demo 1: Simple Workflow with Mock Agents")

    # Create orchestrator
    print("\n📊 Creating LangGraph orchestrator...")
    orchestrator = create_orchestrator(enable_memory=False)

    # Create initial state
    print("📝 Creating initial state...")
    state = create_initial_state(
        intel_text="""
        APT29 (Cozy Bear) campaign detected using PowerShell for initial access.
        
        Observed IOCs:
        - IP: 185.220.101.45
        - Domain: malicious-c2.com
        - Hash: 1234567890abcdef1234567890abcdef
        
        ATT&CK Techniques:
        - T1059.001: PowerShell
        - T1071.001: Application Layer Protocol - Web Protocols
        - T1566.001: Phishing - Spearphishing Attachment
        
        The adversary used encoded PowerShell commands to download and execute
        a second-stage payload from the C2 server.
        """,
        target_platforms=["splunk", "sentinel"],
        framework="PEAK",
        environment="hybrid",
    )

    print(f"   Analysis ID: {state['analysis_id']}")
    print(f"   Framework: {state['framework']}")
    print(f"   Platforms: {', '.join(state['target_platforms'])}")

    # Run workflow
    print("\n🚀 Running workflow...")
    result = orchestrator.run(state)

    # Display results
    print("\n✅ Workflow completed!")
    print(f"   Iterations: {result.get('iteration', 0)}")
    print(f"   Agents executed: {len(result.get('agent_history', []))}")

    print_result("Research Findings", result.get("research_findings", {}))
    print_result("Hunt Plan", result.get("hunt_plan", {}))
    print_result("Detections", result.get("detections", {}))
    print_result("Review Report", result.get("review_report", {}))


def demo_validation_loop():
    """Demo 2: Validation loop with low confidence."""
    print_section("Demo 2: Validation Loop (Low Confidence)")

    from threat_research_mcp.agents.base_agent import BaseAgent
    from threat_research_mcp.schemas.workflow_state import ThreatAnalysisState

    # Create a reviewer that returns low confidence
    class LowConfidenceReviewer(BaseAgent):
        def __init__(self):
            super().__init__("Low Confidence Reviewer")
            self.call_count = 0

        def execute(self, state: ThreatAnalysisState) -> ThreatAnalysisState:
            self.call_count += 1

            # Gradually increase confidence with each iteration
            confidence = 0.5 + (state.get("iteration", 0) * 0.15)

            state["review_report"] = {
                "agent": self.name,
                "findings": {
                    "overall_confidence": confidence,
                    "issues": [f"Iteration {state.get('iteration', 0)}: Confidence too low"],
                    "validation_passed": confidence >= 0.7,
                },
                "confidence": confidence,
            }

            state["needs_refinement"] = confidence < 0.7

            print(f"   🔄 Reviewer iteration {self.call_count}: confidence = {confidence:.2f}")

            return self._record_execution(state)

    # Create orchestrator with custom reviewer
    print("\n📊 Creating orchestrator with low-confidence reviewer...")
    reviewer = LowConfidenceReviewer()
    orchestrator = create_orchestrator(reviewer_agent=reviewer, enable_memory=False)

    # Create state with max 3 iterations
    print("📝 Creating initial state (max 3 iterations)...")
    state = create_initial_state(
        intel_text="Test intelligence for validation loop demo",
        max_iterations=3,
    )

    # Run workflow
    print("\n🚀 Running workflow with validation loops...")
    result = orchestrator.run(state)

    # Display results
    print("\n✅ Workflow completed after validation loops!")
    print(f"   Total iterations: {result.get('iteration', 0)}")
    print(f"   Final confidence: {result['review_report']['findings']['overall_confidence']:.2f}")
    print(f"   Reviewer called: {reviewer.call_count} times")


def demo_with_memory():
    """Demo 3: Workflow with memory/checkpointing."""
    print_section("Demo 3: Workflow with Memory/Checkpointing")

    # Create orchestrator with memory
    print("\n📊 Creating orchestrator with memory enabled...")
    orchestrator = create_orchestrator(enable_memory=True)

    # First analysis
    print("\n📝 Running first analysis (thread-1)...")
    state1 = create_initial_state(
        intel_text="First threat intelligence report",
    )

    config1 = {"configurable": {"thread_id": "thread-1"}}
    result1 = orchestrator.run(state1, config=config1)

    print("   ✅ First analysis complete")
    print(f"   Analysis ID: {result1['analysis_id']}")

    # Second analysis (different thread)
    print("\n📝 Running second analysis (thread-2)...")
    state2 = create_initial_state(
        intel_text="Second threat intelligence report",
    )

    config2 = {"configurable": {"thread_id": "thread-2"}}
    result2 = orchestrator.run(state2, config=config2)

    print("   ✅ Second analysis complete")
    print(f"   Analysis ID: {result2['analysis_id']}")

    print("\n💡 Memory allows context retention across analyses")
    print("   Each thread maintains its own state history")


def demo_agent_communication():
    """Demo 4: Agent communication via shared state."""
    print_section("Demo 4: Agent Communication via Shared State")

    from threat_research_mcp.agents.base_agent import BaseAgent
    from threat_research_mcp.schemas.workflow_state import ThreatAnalysisState

    # Create custom agents that communicate
    class ResearchAgentV2(BaseAgent):
        def execute(self, state: ThreatAnalysisState) -> ThreatAnalysisState:
            print("   🔍 Research Agent: Extracting IOCs...")

            state["research_findings"] = self._create_output(
                findings={
                    "iocs": ["185.220.101.45", "malicious-c2.com"],
                    "techniques": ["T1059.001", "T1071.001"],
                    "enrichment": {
                        "185.220.101.45": {"reputation": "malicious", "threat_actor": "APT29"}
                    },
                },
                confidence=0.85,
            )

            return self._record_execution(state)

    class HuntingAgentV2(BaseAgent):
        def execute(self, state: ThreatAnalysisState) -> ThreatAnalysisState:
            # Read from research findings
            research = state.get("research_findings", {}).get("findings", {})
            iocs = research.get("iocs", [])
            techniques = research.get("techniques", [])

            print(
                f"   🎯 Hunting Agent: Using {len(iocs)} IOCs and {len(techniques)} techniques from Research"
            )

            state["hunt_plan"] = self._create_output(
                findings={
                    "hypotheses": [f"Hunt for {technique} activity" for technique in techniques],
                    "based_on_iocs": iocs,
                    "queries": [f"index=windows EventCode=4688 | search {ioc}" for ioc in iocs],
                },
                confidence=0.80,
            )

            return self._record_execution(state)

    # Create orchestrator with custom agents
    print("\n📊 Creating orchestrator with communicating agents...")
    research_agent = ResearchAgentV2("Research Agent v2")
    hunting_agent = HuntingAgentV2("Hunting Agent v2")

    orchestrator = create_orchestrator(
        research_agent=research_agent, hunting_agent=hunting_agent, enable_memory=False
    )

    # Run workflow
    print("\n🚀 Running workflow...")
    state = create_initial_state(
        intel_text="APT29 PowerShell campaign",
    )

    result = orchestrator.run(state)

    # Show communication
    print("\n✅ Agent communication successful!")
    print("\n📊 Research Agent output:")
    print(f"   IOCs: {result['research_findings']['findings']['iocs']}")
    print(f"   Techniques: {result['research_findings']['findings']['techniques']}")

    print("\n📊 Hunting Agent used Research output:")
    print(f"   Hypotheses: {result['hunt_plan']['findings']['hypotheses']}")
    print(f"   Based on IOCs: {result['hunt_plan']['findings']['based_on_iocs']}")


def main():
    """Run all demos."""
    print("\n" + "=" * 70)
    print("  LangGraph Multi-Agent Workflow Demo")
    print("  threat-research-mcp v0.5.0-dev")
    print("=" * 70)

    # Check if LangGraph is available
    if not LANGGRAPH_AVAILABLE:
        print("\n❌ LangGraph is not installed!")
        print("\n💡 Install with:")
        print("   pip install langgraph langchain langchain-core")
        print("\n⚠️  Note: Requires Python 3.9+")
        sys.exit(1)

    print("\n✅ LangGraph is available")
    print("🚀 Running demos...\n")

    try:
        # Run demos
        demo_simple_workflow()
        input("\n⏸️  Press Enter to continue to Demo 2...")

        demo_validation_loop()
        input("\n⏸️  Press Enter to continue to Demo 3...")

        demo_with_memory()
        input("\n⏸️  Press Enter to continue to Demo 4...")

        demo_agent_communication()

        # Summary
        print_section("Summary")
        print("\n✅ All demos completed successfully!")
        print("\n📚 Next steps:")
        print("   1. Review the code in examples/demo_langgraph_workflow.py")
        print("   2. Read docs/LANGGRAPH-QUICKSTART.md for more details")
        print("   3. Start implementing Phase 1, Week 3-4: Research Agent v2")
        print("\n🎯 See docs/ROADMAP-V2-PLAN.md for the complete roadmap")

    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
