"""File and path helpers."""

from __future__ import annotations

from pathlib import Path


def ensure_dir(path: str | Path) -> Path:
    """Ensure a directory exists and return it as ``Path``."""
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


def read_text(path: str | Path) -> str:
    """Read UTF-8 text file with replacement for decode errors."""
    return Path(path).read_text(encoding="utf-8", errors="replace")


def write_text(path: str | Path, content: str) -> None:
    """Write UTF-8 text to file, creating parent directories if needed."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
