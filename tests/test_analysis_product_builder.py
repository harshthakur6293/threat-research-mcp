from threat_research_mcp.orchestrator.analysis_product_builder import (
    build_analysis_product,
    ioc_dict_to_objects,
)
from threat_research_mcp.schemas import AnalysisProduct


def test_ioc_dict_to_objects_maps_ips_and_hashes() -> None:
    d = {
        "ips": ["8.8.8.8"],
        "domains": ["evil.test"],
        "urls": ["https://evil.test/a"],
        "emails": ["a@b.co"],
        "hashes": ["a" * 32, "b" * 40, "c" * 64],
    }
    objs = ioc_dict_to_objects(d, snippet="beacon to 8.8.8.8")
    kinds = {o.kind for o in objs}
    assert "ipv4" in kinds
    assert "domain" in kinds
    assert "url" in kinds
    assert "email" in kinds
    assert "hash" in kinds


def test_build_analysis_product_from_agent_dicts() -> None:
    research = {
        "summary": "Summary: test",
        "iocs": {"ips": ["1.1.1.1"], "domains": [], "urls": [], "hashes": [], "emails": []},
        "attack": '{"techniques": [{"id": "T1059.001", "name": "PowerShell", "evidence": "x"}]}',
    }
    hunting: dict = {}
    detection = {
        "sigma": "title: t\nstatus: experimental\n",
        "ideas": '{"ideas": ["watch parent-child"]}',
    }
    review = {"status": "pass", "notes": [], "confidence": "medium"}
    p = build_analysis_product(
        workflow="threat_research",
        input_text="powershell encoded",
        research=research,
        hunting=hunting,
        detection=detection,
        review=review,
        request_id="rid-1",
    )
    assert isinstance(p, AnalysisProduct)
    assert p.product_id == "rid-1"
    assert p.technique_alignments[0].technique_id == "T1059.001"
    assert len(p.detection_bundle.rules) >= 2
