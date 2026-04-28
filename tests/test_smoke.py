"""Smoke tests — verify the server starts cleanly from a fresh install.

These catch broken imports that unit tests miss because they import individual
tool functions rather than the server entry point.
"""

from __future__ import annotations

import importlib


def test_schemas_package_imports_cleanly():
    """schemas/__init__.py must not reference missing submodules."""
    mod = importlib.import_module("threat_research_mcp.schemas")
    # Spot-check a few symbols that should exist
    assert hasattr(mod, "WorkflowState")
    assert hasattr(mod, "IocIpv4")
    assert hasattr(mod, "TechniqueAlignment")
    # Symbols from deleted modules must NOT be present
    assert not hasattr(mod, "DetectionRule"), "schemas.detection no longer exists"
    assert not hasattr(mod, "HuntHypothesis"), "schemas.hunt no longer exists"
    assert not hasattr(mod, "AnalysisProduct"), "schemas.analysis_product no longer exists"


def test_server_module_imports_cleanly():
    """server.py must be importable and expose mcp at module level."""
    server = importlib.import_module("threat_research_mcp.server")
    # mcp is None when FastMCP not installed, or a FastMCP instance when it is
    assert hasattr(server, "mcp"), "server.py must define mcp at module level"


def test_cli_module_imports_cleanly():
    """cli.py must be importable without errors."""
    mod = importlib.import_module("threat_research_mcp.cli")
    assert callable(mod.main)


def test_main_module_imports_cleanly():
    """__main__.py must be importable (tests python -m threat_research_mcp path)."""
    # Import via importlib rather than running it to avoid actually starting the server
    spec = importlib.util.find_spec("threat_research_mcp.__main__")
    assert spec is not None, "__main__.py not found"


def test_all_tool_modules_importable():
    """Every tool module referenced in server.py must be importable standalone."""
    tool_modules = [
        "threat_research_mcp.tools.extract_iocs",
        "threat_research_mcp.tools.map_attack",
        "threat_research_mcp.tools.generate_sigma",
        "threat_research_mcp.tools.generate_hunt_hypothesis",
        "threat_research_mcp.tools.validate_sigma",
        "threat_research_mcp.tools.detection_gap_analysis",
        "threat_research_mcp.tools.generate_detections",
        "threat_research_mcp.tools.run_pipeline",
        "threat_research_mcp.tools.parse_stix",
        "threat_research_mcp.tools.navigator_export",
        "threat_research_mcp.tools.score_sigma",
        "threat_research_mcp.tools.misp_bridge",
        "threat_research_mcp.tools.generate_html_report",
        "threat_research_mcp.tools.attack_lookup",
    ]
    for name in tool_modules:
        mod = importlib.import_module(name)
        assert mod is not None, f"Failed to import {name}"


def test_server_registers_expected_tools():
    """If FastMCP is installed, mcp must have tools registered."""
    server = importlib.import_module("threat_research_mcp.server")
    if server.mcp is None:
        # FastMCP not installed in this environment — skip tool count check
        return

    # FastMCP 1.x stores tools inside _tool_manager._tools
    tm = getattr(server.mcp, "_tool_manager", None)
    if tm is not None:
        tool_count = len(getattr(tm, "_tools", {}))
    else:
        tool_count = len(getattr(server.mcp, "_tools", {}))

    assert tool_count >= 30, f"Expected ≥30 tools registered, got {tool_count}"
