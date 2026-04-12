"""End-to-end deliverable: intel in → IOC/TTP + ATT&CK + hunt + detection out."""

from __future__ import annotations

import uuid
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field

from threat_research_mcp.schemas.detection_delivery import DetectionDeliveryBundle
from threat_research_mcp.schemas.hunt_delivery import HuntDeliveryPack
from threat_research_mcp.schemas.ioc_objects import IocObject
from threat_research_mcp.schemas.ttp_alignment import TechniqueAlignment


class IntelProvenance(BaseModel):
    """Where normalized intel for this product came from."""

    model_config = ConfigDict(extra="forbid")

    source_name: str = ""
    source_type: str = ""
    document_fingerprint: Optional[str] = None
    document_title: Optional[str] = None
    ingested_at: Optional[str] = None  # ISO-8601 string


class AnalysisProduct(BaseModel):
    """Canonical MCP handoff object for hunt + detection consumers."""

    model_config = ConfigDict(extra="forbid")

    product_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    schema_version: str = "1.0"
    provenance: List[IntelProvenance] = Field(default_factory=list)
    narrative_summary: str = ""
    extracted_iocs: List[IocObject] = Field(default_factory=list)
    technique_alignments: List[TechniqueAlignment] = Field(default_factory=list)
    hunt_pack: HuntDeliveryPack = Field(default_factory=HuntDeliveryPack)
    detection_bundle: DetectionDeliveryBundle = Field(default_factory=DetectionDeliveryBundle)
    review_status: Optional[str] = None
    review_notes: List[str] = Field(default_factory=list)
