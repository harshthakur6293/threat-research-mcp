from pydantic import BaseModel, Field


class WorkflowState(BaseModel):
    workflow_type: str
    input_text: str
    extracted_iocs: dict = Field(default_factory=dict)
    summary: str = ""
    attack_mapping: list[dict] = Field(default_factory=list)
    hunt_hypothesis: str = ""
    sigma_draft: str = ""
    reviewer_notes: list[str] = Field(default_factory=list)
