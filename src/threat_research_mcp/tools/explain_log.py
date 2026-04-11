def explain_log(event_text: str) -> str:
    return (
        "Log explanation: review event context, process lineage, command line, and "
        f"network behavior. Input excerpt: {event_text[:180]}"
    )
