def generate_sigma(title: str, behavior: str, logsource: str = "process_creation") -> str:
    return (
        f"title: {title}\n"
        "status: experimental\n"
        "logsource:\n"
        f"  category: {logsource}\n"
        "  product: windows\n"
        "detection:\n"
        "  selection:\n"
        f"    CommandLine|contains: '{behavior}'\n"
        "  condition: selection\n"
        "level: medium\n"
    )
