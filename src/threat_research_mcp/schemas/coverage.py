from __future__ import annotations

from pydantic import BaseModel


class CoverageRecord(BaseModel):
    technique_id: str
    coverage_status: str
