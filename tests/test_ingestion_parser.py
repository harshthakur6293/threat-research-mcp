import json

from threat_research_mcp.ingestion.errors import IngestionError
from threat_research_mcp.ingestion.parser import (
    parse_feed_xml,
    parse_html_title,
    parse_html_to_text,
    parse_stix_bundle_json,
    stix_objects_to_entries,
)


RSS_SAMPLE = """<?xml version="1.0"?>
<rss version="2.0">
  <channel>
    <title>Sec Feed</title>
    <item>
      <title>Alert: Phishing</title>
      <link>https://example.com/a1</link>
      <pubDate>Mon, 01 Jan 2024 00:00:00 GMT</pubDate>
      <description><![CDATA[<p>Malware campaign details.</p>]]></description>
    </item>
  </channel>
</rss>
"""

ATOM_SAMPLE = """<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Atom Feed</title>
  <entry>
    <title>Entry One</title>
    <link href="https://example.com/e1" rel="alternate"/>
    <published>2024-02-01T12:00:00Z</published>
    <summary type="html">Summary text</summary>
  </entry>
</feed>
"""


def test_parse_rss_items() -> None:
    items = parse_feed_xml(RSS_SAMPLE)
    assert len(items) == 1
    assert items[0]["title"] == "Alert: Phishing"
    assert items[0]["url"] == "https://example.com/a1"


def test_parse_atom_entries() -> None:
    items = parse_feed_xml(ATOM_SAMPLE)
    assert len(items) == 1
    assert items[0]["title"] == "Entry One"
    assert items[0]["url"] == "https://example.com/e1"


def test_parse_html() -> None:
    html = "<html><head><title>Threat Report</title></head><body><p>Hello</p></body></html>"
    assert parse_html_title(html) == "Threat Report"
    assert "Hello" in parse_html_to_text(html)


def test_parse_stix_bundle() -> None:
    bundle = {
        "type": "bundle",
        "id": "bundle--1",
        "objects": [
            {
                "type": "report",
                "id": "report--x",
                "created": "2024-01-01T00:00:00Z",
                "name": "Test Report",
                "description": "Ransomware activity",
            }
        ],
    }
    entries = parse_stix_bundle_json(json.dumps(bundle))
    assert len(entries) == 1
    assert entries[0]["title"] == "Test Report"
    assert "Ransomware" in entries[0]["body"]


def test_stix_objects_to_entries_skips_bundle_type() -> None:
    objs = [{"type": "bundle", "id": "b1"}, {"type": "indicator", "id": "i1", "name": "Ind1"}]
    ent = stix_objects_to_entries(objs)
    assert len(ent) == 1
    assert ent[0]["title"] == "Ind1"


def test_invalid_feed_raises() -> None:
    try:
        parse_feed_xml("not xml")
        assert False, "expected IngestionError"
    except IngestionError:
        pass
