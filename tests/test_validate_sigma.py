from threat_research_mcp.tools.generate_sigma import generate_sigma
from threat_research_mcp.tools.validate_sigma import validate_sigma_yaml


def test_generated_sigma_passes_validator() -> None:
    yml = generate_sigma("Test Rule", "powershell -enc", "process_creation")
    ok, errs = validate_sigma_yaml(yml)
    assert ok, errs


def test_validate_sigma_catches_missing_detection() -> None:
    ok, errs = validate_sigma_yaml("title: x\nlogsource:\n  category: process_creation\n  product: windows\n")
    assert not ok
    assert any("detection" in e.lower() for e in errs)
