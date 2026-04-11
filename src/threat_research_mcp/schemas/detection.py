from pydantic import BaseModel, Field


class DetectionRule(BaseModel):
    title: str
    rule_type: str = "sigma"
    logic: str
    false_positives: list[str] = Field(default_factory=list)
