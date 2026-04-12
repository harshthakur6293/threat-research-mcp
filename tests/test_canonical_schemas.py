import json

from threat_research_mcp.schemas import (
    AnalysisProduct,
    DetectionRuleArtifact,
    HuntOpportunity,
    HuntQueryArtifact,
    IocIpv4,
    IocUrl,
    TechniqueAlignment,
)


def test_analysis_product_roundtrip_json() -> None:
    product = AnalysisProduct(
        narrative_summary="APT used encoded PowerShell.",
        provenance=[{"source_name": "feed-a", "source_type": "rss"}],
        extracted_iocs=[
            IocIpv4(value="203.0.113.10", source_snippet="beacon to 203.0.113.10"),
            IocUrl(value="https://evil.example/payload", context="download"),
        ],
        technique_alignments=[
            TechniqueAlignment(
                technique_id="T1059.001",
                technique_name="PowerShell",
                evidence="encoded command",
                confidence="high",
                data_source_hints=["process_creation"],
            )
        ],
        hunt_pack={
            "opportunities": [
                HuntOpportunity(
                    title="Encoded PowerShell",
                    hypothesis="Adversary used -enc to evade naive detections.",
                    related_technique_ids=["T1059.001"],
                    required_telemetry=["process_creation"],
                    queries=[
                        HuntQueryArtifact(
                            language="kql",
                            title="DeviceProcessEvents sample",
                            body="DeviceProcessEvents | where ProcessCommandLine has \"-enc\"",
                            log_source_hints=["DeviceProcessEvents"],
                        ),
                        HuntQueryArtifact(
                            language="spl",
                            title="Process with encoded command",
                            body="index=windows EventCode=4688 \"-enc\"",
                            log_source_hints=["Windows Security 4688"],
                        ),
                    ],
                )
            ]
        },
        detection_bundle={
            "rules": [
                DetectionRuleArtifact(
                    rule_format="sigma",
                    title="Suspicious Encoded PowerShell",
                    body="title: test\nlogsource:\n  category: process_creation\n...",
                    technique_ids=["T1059.001"],
                    logsource_category="process_creation",
                    data_source_recommendations=["process_creation"],
                ),
                DetectionRuleArtifact(
                    rule_format="kql",
                    title="Same behavior in KQL",
                    body="DeviceProcessEvents | where ...",
                    technique_ids=["T1059.001"],
                    platform_hints=["windows", "sentinel"],
                ),
            ]
        },
    )

    dumped = product.model_dump(mode="json")
    text = json.dumps(dumped)
    restored = AnalysisProduct.model_validate_json(text)

    assert restored.narrative_summary == product.narrative_summary
    assert len(restored.extracted_iocs) == 2
    assert restored.extracted_iocs[0].kind == "ipv4"
    assert restored.extracted_iocs[1].kind == "url"
    assert restored.technique_alignments[0].technique_id == "T1059.001"
    assert len(restored.hunt_pack.opportunities[0].queries) == 2
    assert len(restored.detection_bundle.rules) == 2
    assert {r.rule_format for r in restored.detection_bundle.rules} == {"sigma", "kql"}
