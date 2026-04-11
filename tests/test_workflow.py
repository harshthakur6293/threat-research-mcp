from threat_research_mcp.orchestrator.workflow import run_workflow


def test_workflow_contains_expected_keys() -> None:
    out = run_workflow("threat_research", "Phishing led to PowerShell execution")
    assert "workflow" in out
    assert "research" in out
    assert "review" in out
