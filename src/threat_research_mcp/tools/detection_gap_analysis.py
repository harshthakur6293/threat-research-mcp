import json


def detection_gap_analysis(techniques_csv: str, detections_csv: str) -> str:
    techniques = [x.strip() for x in techniques_csv.split(",") if x.strip()]
    detections = [x.strip() for x in detections_csv.split(",") if x.strip()]
    gaps = [t for t in techniques if t not in detections]
    return json.dumps({"techniques": techniques, "detections": detections, "gaps": gaps}, indent=2)
