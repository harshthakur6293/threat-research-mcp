from pathlib import Path

from threat_research_mcp.ingestion.manager import load_sources_yaml


def test_load_sources_yaml(tmp_path: Path) -> None:
    y = tmp_path / "cfg.yaml"
    y.write_text(
        """
sources:
  - name: one
    type: local_file
    path: /tmp/x
""",
        encoding="utf-8",
    )
    sources = load_sources_yaml(y)
    assert len(sources) == 1
    assert sources[0].name == "one"
    assert sources[0].type == "local_file"
