from unittest.mock import patch

from threat_research_mcp.ingestion.adapters.taxii_adapter import (
    fetch_taxii_objects,
    list_taxii_collections,
)
from threat_research_mcp.schemas.intel_document import SourceConfig


def test_list_taxii_collections_parses() -> None:
    cfg = SourceConfig(name="t", type="taxii", api_root="https://x/api1/")
    payload = {"collections": [{"id": "col-1", "title": "All"}]}
    with patch(
        "threat_research_mcp.ingestion.adapters.taxii_adapter.http_get_json",
        return_value=payload,
    ):
        cols = list_taxii_collections("https://x/api1/", cfg)
    assert len(cols) == 1
    assert cols[0]["id"] == "col-1"


def test_fetch_taxii_objects_follows_next() -> None:
    cfg = SourceConfig(name="t", type="taxii", api_root="https://x/api1/")
    obj1 = {"type": "report", "id": "r1", "name": "R1"}
    responses = [
        {"objects": [obj1], "next": "https://x/api1/collections/c1/objects/?part=2"},
        {"objects": [{"type": "report", "id": "r2", "name": "R2"}]},
    ]

    def fake_get(url, **kwargs):
        return responses.pop(0)

    with patch(
        "threat_research_mcp.ingestion.adapters.taxii_adapter.http_get_json",
        side_effect=fake_get,
    ):
        objs = fetch_taxii_objects("https://x/api1/", "c1", cfg)
    assert len(objs) == 2
    assert objs[0]["id"] == "r1"
    assert objs[1]["id"] == "r2"
