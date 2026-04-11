import json


def generate_detection_ideas(text: str) -> str:
    return json.dumps(
        {
            "input_excerpt": text[:180],
            "ideas": [
                "Detect suspicious parent-child process relationships",
                "Correlate command line anomalies with outbound network",
                "Flag persistence artifacts shortly after suspicious execution",
            ],
        },
        indent=2,
    )
