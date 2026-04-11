def requires_human_approval(action: str) -> bool:
    return action not in {"analyze", "summarize", "draft"}
