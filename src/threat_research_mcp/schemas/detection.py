from __future__ import annotations

from typing import List

from pydantic import BaseModel, Field


class DetectionRule(BaseModel):
    title: str
    rule_type: str = "sigma"
    logic: str
    false_positives: List[str] = Field(default_factory=list)
