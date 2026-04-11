import json


def format_output(data: dict) -> str:
    return json.dumps(data, indent=2)
