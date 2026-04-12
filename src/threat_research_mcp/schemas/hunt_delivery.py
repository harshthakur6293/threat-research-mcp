"""Hunt opportunities with multi-language query artifacts."""

from __future__ import annotations

import uuid
from typing import List, Literal

from pydantic import BaseModel, ConfigDict, Field

QueryLanguage = Literal["kql", "spl", "sigma", "eql", "yara", "pseudo", "other"]


class HuntQueryArtifact(BaseModel):
    """Executable or copy-paste hunt logic for a given analytics language."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    language: QueryLanguage = "pseudo"
    title: str = ""
    body: str = ""
    log_source_hints: List[str] = Field(
        default_factory=list,
        description="Vendor-agnostic hints: e.g. Microsoft Sentinel tables, Splunk sourcetypes.",
    )


class HuntOpportunity(BaseModel):
    """One prioritized hunt thread derived from intel + TTP alignment."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    hypothesis: str = ""
    priority: str = "medium"
    related_technique_ids: List[str] = Field(default_factory=list)
    required_telemetry: List[str] = Field(default_factory=list)
    hunt_steps: List[str] = Field(default_factory=list)
    queries: List[HuntQueryArtifact] = Field(default_factory=list)
    analyst_notes: List[str] = Field(default_factory=list)


class HuntDeliveryPack(BaseModel):
    """Collection of hunt opportunities for handoff to a hunt team."""

    model_config = ConfigDict(extra="forbid")

    opportunities: List[HuntOpportunity] = Field(default_factory=list)
    summary: str = ""
    pack_version: str = "1.0"
