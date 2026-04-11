import json

KEYWORDS = {
    "powershell": ("T1059.001", "PowerShell"),
    "phishing": ("T1566.001", "Spearphishing Attachment"),
    "scheduled task": ("T1053.005", "Scheduled Task"),
    "javascript": ("T1059.007", "JavaScript"),
}


def map_attack(text: str) -> str:
    out = []
    low = text.lower()
    for token, (tid, name) in KEYWORDS.items():
        if token in low:
            out.append({"id": tid, "name": name, "evidence": token})
    return json.dumps({"techniques": out}, indent=2)
