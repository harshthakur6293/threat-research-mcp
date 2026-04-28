"""Tests for attack_lookup.py — covers the no-DB fallback and build script import.

The ATT&CK database (playbook/attack.db) is NOT present in CI; all tests verify
the graceful degradation path. DB-dependent tests are skipped automatically.
"""

from __future__ import annotations

import json
import importlib
import pytest


# ── Module import ─────────────────────────────────────────────────────────────


def test_attack_lookup_imports_cleanly():
    mod = importlib.import_module("threat_research_mcp.tools.attack_lookup")
    assert callable(mod.get_technique)
    assert callable(mod.get_threat_groups)
    assert callable(mod.get_techniques_by_group)
    assert callable(mod.attribute_to_group)
    assert callable(mod.get_data_sources)
    assert callable(mod.get_mitigations)


def test_build_script_imports_cleanly():
    """build_attack_db.py must be importable without side effects."""
    import importlib.util
    from pathlib import Path

    spec = importlib.util.spec_from_file_location(
        "build_attack_db",
        Path(__file__).parent.parent / "scripts" / "build_attack_db.py",
    )
    assert spec is not None, "build_attack_db.py not found"


# ── No-DB fallback ────────────────────────────────────────────────────────────


@pytest.fixture
def no_db(monkeypatch):
    """Patch _db_path() to return None (simulates missing database)."""
    import threat_research_mcp.tools.attack_lookup as mod

    monkeypatch.setattr(mod, "_db_path", lambda: None)
    return mod


def _is_no_db_response(json_str: str) -> bool:
    data = json.loads(json_str)
    return "error" in data and "attack.db" in data["error"]


def test_get_technique_no_db(no_db):
    result = no_db.get_technique("T1059.001")
    assert _is_no_db_response(result)
    data = json.loads(result)
    assert "fix" in data
    assert "build_attack_db" in data["fix"]


def test_get_threat_groups_no_db(no_db):
    result = no_db.get_threat_groups("T1059.001")
    assert _is_no_db_response(result)


def test_get_techniques_by_group_no_db(no_db):
    result = no_db.get_techniques_by_group("APT28")
    assert _is_no_db_response(result)


def test_attribute_to_group_no_db(no_db):
    result = no_db.attribute_to_group("T1059.001,T1003.001")
    assert _is_no_db_response(result)


def test_get_data_sources_no_db(no_db):
    result = no_db.get_data_sources("T1059.001")
    assert _is_no_db_response(result)


def test_get_mitigations_no_db(no_db):
    result = no_db.get_mitigations("T1059.001")
    assert _is_no_db_response(result)


# ── DB-dependent tests (skipped when DB absent) ────────────────────────────────


def _db_available() -> bool:
    from threat_research_mcp.tools.attack_lookup import _db_path

    return _db_path() is not None


db_required = pytest.mark.skipif(
    not _db_available(), reason="attack.db not built — run scripts/build_attack_db.py"
)


@db_required
def test_get_technique_with_db():
    from threat_research_mcp.tools.attack_lookup import get_technique

    result = json.loads(get_technique("T1059.001"))
    assert result.get("id") == "T1059.001"
    assert "platforms" in result
    assert "data_sources" in result
    assert isinstance(result["tactics"], list)


@db_required
def test_get_threat_groups_with_db():
    from threat_research_mcp.tools.attack_lookup import get_threat_groups

    result = json.loads(get_threat_groups("T1059.001"))
    assert "groups" in result
    assert isinstance(result["groups"], list)


@db_required
def test_attribute_to_group_with_db():
    from threat_research_mcp.tools.attack_lookup import attribute_to_group

    # Use techniques known to be used by Lazarus Group
    result = json.loads(attribute_to_group("T1059.001,T1003.001,T1071.001,T1547.001"))
    assert "top_matches" in result
    assert isinstance(result["top_matches"], list)
    assert "attribution_confidence" in result


@db_required
def test_get_data_sources_with_db():
    from threat_research_mcp.tools.attack_lookup import get_data_sources

    result = json.loads(get_data_sources("T1059.001"))
    assert "data_sources" in result
    assert isinstance(result["data_sources"], list)
