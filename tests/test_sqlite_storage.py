import json
import sqlite3

from threat_research_mcp.schemas.intel_document import NormalizedDocument
from threat_research_mcp.storage.sqlite import (
    get_analysis_product_by_row_id,
    init_schema,
    save_analysis_product,
    save_normalized_documents,
    save_workflow_run,
    search_analysis_products,
    search_normalized_documents,
)


def test_save_workflow_run_inserts_row(tmp_path) -> None:
    db = tmp_path / "runs.sqlite"
    payload = {
        "request_id": "test-id",
        "workflow": "threat_research",
        "research": {"summary": "x"},
        "hunting": {},
        "detection": {},
        "review": {},
    }
    save_workflow_run(
        db,
        run_id="test-id",
        workflow_type="threat_research",
        input_text="hello world",
        output_payload=payload,
    )

    conn = sqlite3.connect(str(db))
    try:
        init_schema(conn)
        row = conn.execute("SELECT id, workflow_type, output_json FROM workflow_runs").fetchone()
        assert row is not None
        assert row[0] == "test-id"
        assert row[1] == "threat_research"
        assert json.loads(row[2]) == payload
    finally:
        conn.close()


def test_save_and_search_normalized_documents(tmp_path) -> None:
    db = tmp_path / "intel.sqlite"
    doc = NormalizedDocument(
        source_name="feed-a",
        source_type="local_file",
        title="Ransomware report",
        raw_text="x",
        normalized_text="Conti ransomware IOC 203.0.113.9",
        fingerprint="fp-search-1",
    )
    n = save_normalized_documents(db, [doc])
    assert n == 1
    hits = search_normalized_documents(db, text_query="Conti")
    assert len(hits) == 1
    assert hits[0]["fingerprint"] == "fp-search-1"
    by_fp = search_normalized_documents(db, fingerprint="fp-search-1")
    assert len(by_fp) == 1


def test_save_search_roundtrip_analysis_product(tmp_path) -> None:
    db = tmp_path / "ap.sqlite"
    save_analysis_product(
        db,
        workflow_type="threat_research",
        product={
            "product_id": "pid-1",
            "schema_version": "1.0",
            "narrative_summary": "T1059 PowerShell abuse",
            "provenance": [],
        },
    )
    rows = search_analysis_products(db, text_query="T1059")
    assert len(rows) == 1
    assert rows[0]["product_id"] == "pid-1"
    full = get_analysis_product_by_row_id(db, rows[0]["row_id"])
    assert full is not None
    assert full["narrative_summary"].startswith("T1059")
