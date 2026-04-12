from threat_research_mcp.extensions import (
    RECOMMENDED_EXTERNAL_MCPS,
    CapabilityDomain,
    list_external_mcp_keys,
    this_project_domains,
)


def test_catalog_lists_four_peers() -> None:
    keys = list_external_mcp_keys()
    assert "mitre-attack-mcp" in keys
    assert "security-detections-mcp" in keys
    assert "threat-hunting-mcp-server" in keys
    assert "fastmcp-threatintel" in keys
    assert len(RECOMMENDED_EXTERNAL_MCPS) == 4


def test_this_project_claims_workflow_and_ingestion() -> None:
    domains = this_project_domains()
    assert CapabilityDomain.WORKFLOW_ORCHESTRATION in domains
    assert CapabilityDomain.INTEL_INGESTION in domains
