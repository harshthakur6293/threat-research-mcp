from pydantic import BaseModel, Field


class HuntHypothesis(BaseModel):
    title: str
    hypothesis: str
    related_techniques: list[str] = Field(default_factory=list)
