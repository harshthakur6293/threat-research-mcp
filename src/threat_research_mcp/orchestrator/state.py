from threat_research_mcp.schemas.workflow import WorkflowState


def init_state(workflow_type: str, input_text: str) -> WorkflowState:
    return WorkflowState(workflow_type=workflow_type, input_text=input_text)
