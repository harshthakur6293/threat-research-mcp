from __future__ import annotations

import uuid

from pydantic import BaseModel, Field


class WorkflowState(BaseModel):
    """Single workflow run: orchestrator-owned state (spec: request memory)."""

    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    workflow_type: str
    input_text: str
    research: dict = Field(default_factory=dict)
    hunting: dict = Field(default_factory=dict)
    detection: dict = Field(default_factory=dict)
    review: dict = Field(default_factory=dict)

    def to_output_dict(self) -> dict:
        return {
            "request_id": self.request_id,
            "workflow": self.workflow_type,
            "research": self.research,
            "hunting": self.hunting,
            "detection": self.detection,
            "review": self.review,
        }
