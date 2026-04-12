import json

from threat_research_mcp.orchestrator.workflow import run_workflow
from threat_research_mcp.schemas import AnalysisProduct


def test_workflow_contains_expected_keys() -> None:
    out = run_workflow("threat_research", "Phishing led to PowerShell execution")
    data = json.loads(out)
    assert "request_id" in data
    assert data["workflow"] == "threat_research"
    assert "research" in data
    assert "review" in data
    assert "analysis_product" in data
    product = AnalysisProduct.model_validate(data["analysis_product"])
    assert product.product_id == data["request_id"]
    assert product.narrative_summary
    formats = {r.rule_format for r in product.detection_bundle.rules}
    assert "sigma" in formats
    assert "kql" in formats
    assert "spl" in formats
