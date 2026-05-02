"""Tests for generate_html_report — graph escaping and structure."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from threat_research_mcp.tools.generate_html_report import generate_html_report


def _minimal_pipeline_json(**overrides) -> str:
    base = {
        "iocs": {"ips": [], "domains": [], "urls": [], "hashes": [], "emails": []},
        "techniques": {"techniques": [], "suppressed": [], "confidence_threshold": 0.45},
        "hunt_hypotheses": {"hypotheses": []},
        "detections": {"sigma": {"rules": []}},
        "summary": {"stages_completed": [], "text_chars_analyzed": 0},
    }
    base.update(overrides)
    return json.dumps(base)


def _tmpfile() -> str:
    fd, path = tempfile.mkstemp(suffix=".html", dir=Path(__file__).parent.parent / "tests")
    os.close(fd)
    return path


class TestHtmlReportEscaping:
    def test_script_tag_injection_does_not_break_html(self):
        """</script> in threat data must not close the script block early."""
        evil_url = "http://evil.com/path?x=</script><script>alert(1)</script>"
        data = _minimal_pipeline_json(
            iocs={
                "ips": [],
                "domains": [{"value": "evil.com", "confidence": 0.8, "label": "MALICIOUS"}],
                "urls": [{"value": evil_url, "confidence": 0.8, "label": "URL"}],
                "hashes": [],
                "emails": [],
            }
        )
        out_path = _tmpfile()
        try:
            result = json.loads(generate_html_report(data, output_path=out_path))
            html = Path(out_path).read_text(encoding="utf-8")
            # The closing script tag must be escaped inside the embedded JSON block.
            # The first <script> opens D3, the second opens our data block.
            # If </script> leaks unescaped into the data, the third </script>
            # would close prematurely and the page would show broken JS.
            script_sections = html.split("<script")
            # Find the section containing our JSON data (has "const D =")
            data_section = next((s for s in script_sections if "const D =" in s), "")
            assert "</script>" not in data_section, (
                "Unescaped </script> found inside embedded JSON block — "
                "this would break the graph in browsers"
            )
            assert result["bytes"] > 0
        finally:
            os.unlink(out_path)

    def test_html_contains_d3_script_tag(self):
        out_path = _tmpfile()
        try:
            generate_html_report(_minimal_pipeline_json(), output_path=out_path)
            html = Path(out_path).read_text(encoding="utf-8")
            assert "d3js.org/d3.v7.min.js" in html
        finally:
            os.unlink(out_path)

    def test_html_contains_d3_fallback_guard(self):
        out_path = _tmpfile()
        try:
            generate_html_report(_minimal_pipeline_json(), output_path=out_path)
            html = Path(out_path).read_text(encoding="utf-8")
            assert "_d3Failed" in html
            assert "CDN blocked" in html
        finally:
            os.unlink(out_path)

    def test_invalid_json_returns_error(self):
        result = json.loads(generate_html_report("not json"))
        assert "error" in result

    def test_ioc_rows_appear_in_output(self):
        data = _minimal_pipeline_json(
            iocs={
                "ips": [{"value": "1.2.3.4", "confidence": 0.9, "label": "MALICIOUS"}],
                "domains": [],
                "urls": [],
                "hashes": [],
                "emails": [],
            }
        )
        out_path = _tmpfile()
        try:
            result = json.loads(generate_html_report(data, output_path=out_path))
            assert result["summary"]["ioc_count"] == 1
        finally:
            os.unlink(out_path)

    def test_technique_nodes_appear_in_graph_data(self):
        data = _minimal_pipeline_json(
            techniques={
                "techniques": [
                    {
                        "id": "T1059.001",
                        "name": "PowerShell",
                        "tactic": "execution",
                        "confidence": 0.8,
                        "confidence_label": "HIGH",
                        "evidence": [],
                    }
                ],
                "suppressed": [],
                "confidence_threshold": 0.45,
            }
        )
        out_path = _tmpfile()
        try:
            result = json.loads(generate_html_report(data, output_path=out_path))
            html = Path(out_path).read_text(encoding="utf-8")
            assert result["summary"]["technique_count"] == 1
            assert "T1059.001" in html
        finally:
            os.unlink(out_path)
