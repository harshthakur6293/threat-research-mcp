def defensive_policy_ok(text: str) -> bool:
    blocked = ["autonomous exploitation", "deploy malware", "credential theft"]
    low = text.lower()
    return not any(token in low for token in blocked)
