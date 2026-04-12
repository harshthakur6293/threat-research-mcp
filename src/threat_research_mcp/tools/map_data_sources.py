import json

MAPPING = {
    "T1059.001": ["process_creation", "powershell_script_block"],
    "T1053.005": ["scheduled_task_events"],
    "T1566.001": ["email_gateway", "endpoint_process_events"],
}


def map_data_sources(technique_id: str) -> str:
    return json.dumps(
        {"technique_id": technique_id, "data_sources": MAPPING.get(technique_id, [])}, indent=2
    )
