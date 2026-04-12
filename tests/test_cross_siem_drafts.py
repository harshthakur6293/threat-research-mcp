from threat_research_mcp.detection.cross_siem_drafts import (
    build_detection_sidecar,
    parse_technique_ids_from_research,
)
from threat_research_mcp.detection.technique_data_sources import data_sources_for_techniques


def test_parse_technique_ids() -> None:
    r = {"attack": '{"techniques": [{"id": "T1059.001", "name": "PS"}]}'}
    assert parse_technique_ids_from_research(r) == ["T1059.001"]


def test_data_sources_lookup() -> None:
    ds = data_sources_for_techniques(["T1059.001", "T1566.001"])
    assert any("Process Creation" in d for d in ds)


def test_build_detection_sidecar_includes_kql_spl() -> None:
    r = {"attack": '{"techniques": [{"id": "T1059.001"}]}'}
    side = build_detection_sidecar("malicious -enc payload", r)
    assert "DeviceProcessEvents" in side["kql"]
    assert "index=windows" in side["spl"]
    assert side["technique_ids"] == ["T1059.001"]
    assert side["data_source_recommendations"]
