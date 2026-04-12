"""TTP and MITRE ATT&CK alignment records."""

from __future__ import annotations

import uuid
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field


class TechniqueAlignment(BaseModel):
    """One technique (or sub-technique) tied to evidence from intel or analysis."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    technique_id: str = ""
    technique_name: Optional[str] = None
    tactic_ids: List[str] = Field(default_factory=list)
    procedure_hint: Optional[str] = None
    evidence: str = ""
    confidence: str = "medium"  # low | medium | high
    data_source_hints: List[str] = Field(
        default_factory=list,
        description="MITRE-style data components or log categories (e.g. process_creation, network_connection).",
    )
