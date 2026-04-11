def summarize_threat_report(text: str) -> str:
    cleaned = " ".join(text.split())
    if not cleaned:
        return "Empty input report."
    return f"Summary: {cleaned[:400]}"
