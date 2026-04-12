def _yaml_escape_double_quoted(value: str) -> str:
    return (value or "").replace("\\", "\\\\").replace('"', '\\"')[:400]


def generate_sigma(title: str, behavior: str, logsource: str = "process_creation") -> str:
    """Emit Sigma with double-quoted contains to survive quotes/newlines in behavior text."""
    beh = _yaml_escape_double_quoted(behavior)
    safe_title = (title or "Untitled").replace('"', '\\"')[:200]
    return (
        f'title: "{safe_title}"\n'
        "status: experimental\n"
        "logsource:\n"
        f"  category: {logsource}\n"
        "  product: windows\n"
        "detection:\n"
        "  selection:\n"
        f'    CommandLine|contains: "{beh}"\n'
        "  condition: selection\n"
        "level: medium\n"
        "falsepositives:\n"
        "  - Legitimate administrative scripts (tune for your estate)\n"
    )
