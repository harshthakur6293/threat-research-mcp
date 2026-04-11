def run_review(research: dict, hunting: dict, detection: dict) -> dict:
    notes = []
    if not research.get("summary"):
        notes.append("Missing research summary")
    if "sigma" not in detection:
        notes.append("Missing sigma draft")
    return {"status": "pass_with_notes" if notes else "pass", "notes": notes, "confidence": "medium"}
