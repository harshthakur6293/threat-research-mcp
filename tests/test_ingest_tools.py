import json
from pathlib import Path

from threat_research_mcp.schemas import AnalysisProduct
from threat_research_mcp.orchestrator.provenance_merge import merge_ingestion_provenance
from threat_research_mcp.tools.ingest_tools import (
    combine_intel_for_workflow,
    ingest_from_config_path_json,
    intel_to_analysis_product_json,
)


def test_ingest_from_config_path_json_local_file(tmp_path: Path) -> None:
    f = tmp_path / "a.txt"
    f.write_text("malware beacon 203.0.113.1", encoding="utf-8")
    cfg = tmp_path / "s.json"
    cfg.write_text(
        json.dumps(
            {
                "sources": [
                    {
                        "name": "t",
                        "type": "local_file",
                        "path": str(f),
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    out = json.loads(ingest_from_config_path_json(str(cfg)))
    assert out["count"] == 1
    assert out["documents"][0]["source_name"] == "t"
    assert "203.0.113.1" in out["documents"][0]["normalized_text"]


def test_intel_to_analysis_product_text_only() -> None:
    js = intel_to_analysis_product_json(
        text="Phishing with powershell -enc",
        sources_config_path="",
        workflow="threat_research",
    )
    data = json.loads(js)
    assert "error" not in data
    AnalysisProduct.model_validate(data)


def test_merge_ingestion_provenance_appends() -> None:
    from threat_research_mcp.schemas.intel_document import NormalizedDocument

    ap = {"provenance": [{"source_name": "workflow", "source_type": "threat_research"}], "schema_version": "1.0"}
    doc = NormalizedDocument(
        source_name="feed",
        source_type="local_file",
        title="t",
        raw_text="x",
        normalized_text="x",
        fingerprint="fp1",
    )
    merged = merge_ingestion_provenance(ap, [doc])
    assert len(merged["provenance"]) == 2
    assert merged["provenance"][1]["document_fingerprint"] == "fp1"


def test_combine_intel_prefers_text_then_docs(tmp_path: Path) -> None:
    f = tmp_path / "b.txt"
    f.write_text("body from file", encoding="utf-8")
    cfg = tmp_path / "c.yaml"
    cfg.write_text(
        "sources:\n  - name: x\n    type: local_file\n    path: " + str(f).replace("\\", "/") + "\n",
        encoding="utf-8",
    )
    combined, docs = combine_intel_for_workflow(
        text="prefix line",
        sources_config_path=str(cfg),
    )
    assert combined.startswith("prefix line")
    assert "body from file" in combined
    assert len(docs) == 1
