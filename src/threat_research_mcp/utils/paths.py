"""Path helpers for bundled and editable project data files."""

from __future__ import annotations

import os
from pathlib import Path


def repo_root() -> Path:
    """Return the repository root when running from an editable checkout."""
    return Path(__file__).resolve().parents[3]


def package_root() -> Path:
    """Return the installed ``threat_research_mcp`` package directory."""
    return Path(__file__).resolve().parents[1]


def playbook_file(*parts: str) -> Path | None:
    """Find a playbook file in editable, cwd, or packaged installs.

    This makes the server work when launched via an installed console script
    (including ``uvx threat-research-mcp`` after publication), where there is no
    repository-relative ``playbook/`` directory next to the current working dir.
    """
    candidates = [
        repo_root() / "playbook" / Path(*parts),
        Path(os.getcwd()) / "playbook" / Path(*parts),
        package_root() / "playbook" / Path(*parts),
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def playbook_dir() -> Path | None:
    """Find the playbook directory in editable, cwd, or packaged installs."""
    candidates = [
        repo_root() / "playbook",
        Path(os.getcwd()) / "playbook",
        package_root() / "playbook",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None
