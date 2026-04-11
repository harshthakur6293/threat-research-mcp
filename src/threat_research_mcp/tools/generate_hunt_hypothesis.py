import json


def generate_hunt_hypothesis(text: str) -> str:
    return json.dumps(
        {
            "title": "Generated Hunt Hypothesis",
            "hypothesis": "Potential suspicious behavior should be validated across telemetry.",
            "evidence": text[:220],
            "required_telemetry": ["process_creation", "network_connections"],
        },
        indent=2,
    )
