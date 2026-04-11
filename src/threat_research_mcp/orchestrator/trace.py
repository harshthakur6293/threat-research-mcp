def record_trace(step: str, payload: dict) -> dict:
    return {"step": step, "keys": sorted(payload.keys())}
