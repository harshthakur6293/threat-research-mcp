import json
import os
import sqlite3

from threat_research_mcp.orchestrator.workflow import run_workflow


def test_run_workflow_persists_when_env_db_set(tmp_path, monkeypatch) -> None:
    db = tmp_path / "w.sqlite"
    monkeypatch.setenv("THREAT_RESEARCH_MCP_DB", str(db))
    out = run_workflow("threat_research", "Phishing led to PowerShell execution")
    data = json.loads(out)
    rid = data["request_id"]

    conn = sqlite3.connect(str(db))
    try:
        row = conn.execute(
            "SELECT id, output_json FROM workflow_runs WHERE id = ?", (rid,)
        ).fetchone()
        assert row is not None
        stored = json.loads(row[1])
        assert stored["request_id"] == rid
        assert stored["workflow"] == "threat_research"
        ap_row = conn.execute(
            "SELECT product_id, workflow_type FROM analysis_products WHERE product_id = ?",
            (rid,),
        ).fetchone()
        assert ap_row is not None
        assert ap_row[1] == "threat_research"
    finally:
        conn.close()

    monkeypatch.delenv("THREAT_RESEARCH_MCP_DB", raising=False)


def test_run_workflow_no_db_file_without_env(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("THREAT_RESEARCH_MCP_DB", raising=False)
    db = tmp_path / "should_not_exist.sqlite"
    run_workflow("threat_research", "safe text")
    assert not db.exists()
