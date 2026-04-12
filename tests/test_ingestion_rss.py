from unittest.mock import patch

from threat_research_mcp.ingestion import IngestionManager, sources_from_dict

RSS_SAMPLE = """<?xml version="1.0"?>
<rss version="2.0"><channel><title>S</title>
<item><title>Alert: Phishing</title><link>https://example.com/a1</link>
<description>Details</description></item></channel></rss>"""


def test_rss_adapter_with_mocked_http() -> None:
    sources = sources_from_dict(
        {"sources": [{"name": "feed", "type": "rss", "url": "https://example.com/feed"}]}
    )
    with patch(
        "threat_research_mcp.ingestion.adapters.rss_adapter.http_get_text",
        return_value=RSS_SAMPLE,
    ):
        docs = IngestionManager(sources).run()
    assert len(docs) == 1
    assert docs[0].title == "Alert: Phishing"
    assert "feed" == docs[0].source_name
