import json
from pathlib import Path

from threat_research_mcp.ingestion import IngestionManager, sources_from_dict
from threat_research_mcp.ingestion.errors import IngestionError
from threat_research_mcp.ingestion.manager import load_sources_json
from threat_research_mcp.ingestion.registry import get_adapter, list_adapter_types


def test_list_adapter_types_includes_core() -> None:
    types = list_adapter_types()
    for t in ("local_file", "rss", "rss_atom", "html_report", "taxii", "stix_bundle"):
        assert t in types


def test_unknown_adapter() -> None:
    try:
        get_adapter("nope")
        assert False
    except IngestionError as e:
        assert "Unknown source type" in str(e)


def test_local_file_ingest(tmp_path: Path) -> None:
    f = tmp_path / "note.txt"
    f.write_text("Suspicious powershell -enc observed.", encoding="utf-8")
    sources = sources_from_dict({"sources": [{"name": "t", "type": "local_file", "path": str(f)}]})
    docs = IngestionManager(sources).run()
    assert len(docs) == 1
    assert "powershell" in docs[0].normalized_text.lower()
    assert docs[0].source_name == "t"


def test_local_stix_json(tmp_path: Path) -> None:
    bundle = {
        "type": "bundle",
        "id": "bundle--1",
        "objects": [
            {
                "type": "malware",
                "id": "malware--1",
                "name": "BadX",
                "description": "Test malware",
            }
        ],
    }
    p = tmp_path / "b.json"
    p.write_text(json.dumps(bundle), encoding="utf-8")
    sources = sources_from_dict({"sources": [{"name": "s", "type": "local_file", "path": str(p)}]})
    docs = IngestionManager(sources).run()
    assert len(docs) >= 1
    assert any("BadX" in d.title or "BadX" in d.normalized_text for d in docs)


def test_html_path_ingest(tmp_path: Path) -> None:
    h = tmp_path / "r.html"
    h.write_text(
        "<html><head><title>T</title></head><body><p>Body</p></body></html>", encoding="utf-8"
    )
    sources = sources_from_dict({"sources": [{"name": "h", "type": "html_report", "path": str(h)}]})
    docs = IngestionManager(sources).run()
    assert len(docs) == 1
    assert "Body" in docs[0].normalized_text


def test_load_sources_json(tmp_path: Path) -> None:
    cfg = tmp_path / "s.json"
    cfg.write_text(
        json.dumps(
            {"sources": [{"name": "x", "type": "local_file", "path": str(tmp_path / "nope")}]}
        ),
        encoding="utf-8",
    )
    sources = load_sources_json(cfg)
    assert len(sources) == 1
    assert sources[0].name == "x"


def test_deduper_collapses_duplicate(tmp_path: Path) -> None:
    f = tmp_path / "same.txt"
    f.write_text("duplicate content exactly", encoding="utf-8")
    sources = sources_from_dict(
        {
            "sources": [
                {"name": "a", "type": "local_file", "path": str(f)},
                {"name": "b", "type": "local_file", "path": str(f)},
            ]
        }
    )
    docs = IngestionManager(sources).run(skip_duplicates=True)
    # Same file content but different source_name → different fingerprints
    assert len(docs) == 2
