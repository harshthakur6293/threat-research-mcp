"""Detection rules in multiple formats with ATT&CK and log-source hints."""

from __future__ import annotations

import uuid
from typing import List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

RuleFormat = Literal["sigma", "kql", "spl", "eql", "yara", "other"]


class DetectionRuleArtifact(BaseModel):
    """Single draft rule or use case in a specific language."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    rule_format: RuleFormat = "sigma"
    title: str = ""
    body: str = ""
    description: Optional[str] = None
    technique_ids: List[str] = Field(default_factory=list)
    tactic_ids: List[str] = Field(default_factory=list)
    logsource_category: Optional[str] = None
    platform_hints: List[str] = Field(default_factory=list)
    data_source_recommendations: List[str] = Field(
        default_factory=list,
        description="Suggested MITRE data sources / log channels for validation.",
    )
    false_positives: List[str] = Field(default_factory=list)
    severity: str = "medium"
    status: str = "draft"


class LogSourceGuidance(BaseModel):
    """Log source recommendations and hunt queries for detected techniques."""

    model_config = ConfigDict(extra="forbid")

    techniques: List[str] = Field(default_factory=list)
    environment: str = "hybrid"
    priority_summary: dict = Field(
        default_factory=dict,
        description="Critical, high, and medium priority log sources",
    )
    log_sources: dict = Field(
        default_factory=dict,
        description="Detailed log sources by platform (windows, aws, azure, gcp, etc.)",
    )
    hunt_queries: dict = Field(
        default_factory=dict,
        description="Ready-to-run SIEM queries by technique and platform",
    )
    deployment_checklist: List[dict] = Field(
        default_factory=list,
        description="Prioritized deployment tasks for required log sources",
    )
    blind_spots: List[str] = Field(
        default_factory=list,
        description="Techniques without specific log source mappings",
    )


class DetectionDeliveryBundle(BaseModel):
    """Bundle of rules + telemetry guidance for detection engineering."""

    model_config = ConfigDict(extra="forbid")

    rules: List[DetectionRuleArtifact] = Field(default_factory=list)
    log_source_guidance: Optional[LogSourceGuidance] = None
    bundle_version: str = "1.0"
    notes: List[str] = Field(default_factory=list)
