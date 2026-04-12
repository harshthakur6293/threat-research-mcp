from __future__ import annotations

from typing import List

from pydantic import BaseModel, Field


class HuntHypothesis(BaseModel):
    title: str
    hypothesis: str
    related_techniques: List[str] = Field(default_factory=list)
