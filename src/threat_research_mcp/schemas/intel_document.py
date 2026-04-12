"""Normalized intel document and source configuration (ingestion pipeline)."""

from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


class SourceConfig(BaseModel):
    """One configured feed or file source (YAML / dict)."""

    model_config = ConfigDict(extra="ignore")

    name: str
    type: str

    @field_validator("type")
    @classmethod
    def normalize_type(cls, v: str) -> str:
        return (v or "").strip().lower()
    path: Optional[str] = None
    url: Optional[str] = None
    api_root: Optional[str] = None
    collection_id: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    api_key: Optional[str] = None
    api_key_header: str = "Authorization"
    api_key_prefix: str = "Bearer "
    pattern: str = "*"
    source_trust: str = "unknown"
    timeout_seconds: int = 60


class RawDocument(BaseModel):
    """Pre-normalization payload from an adapter."""

    model_config = ConfigDict(extra="ignore")

    body: str
    title: str = ""
    url: str = ""
    published_at: Optional[str] = None
    mime_hint: str = "text/plain"
    tags: List[str] = Field(default_factory=list)


class NormalizedDocument(BaseModel):
    """Canonical document handed to workflows and storage."""

    source_name: str
    source_type: str
    title: str
    url: str = ""
    published_at: Optional[str] = None
    raw_text: str
    normalized_text: str
    tags: List[str] = Field(default_factory=list)
    fingerprint: str
    source_trust: str = "unknown"
