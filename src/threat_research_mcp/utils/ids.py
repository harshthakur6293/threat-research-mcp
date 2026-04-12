"""ID helpers."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone


def new_id(prefix: str = "obj") -> str:
    """Generate a compact prefixed identifier."""
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def run_id(prefix: str = "run") -> str:
    """Generate monotonic-ish run ID with UTC timestamp + random suffix."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{prefix}_{ts}_{uuid.uuid4().hex[:8]}"
