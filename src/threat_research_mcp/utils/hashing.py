"""Hashing helpers used for deduplication and IDs."""

from __future__ import annotations

import hashlib


def sha256_hex(value: str) -> str:
    """Compute SHA256 hex digest for a string."""
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()
