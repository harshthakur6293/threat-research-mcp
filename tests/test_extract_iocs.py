from threat_research_mcp.tools.extract_iocs import extract_iocs_from_text


def test_extracts_ip_and_hash() -> None:
    text = "Beacon to 203.0.113.10 and hash deadbeefdeadbeefdeadbeefdeadbeef"
    r = extract_iocs_from_text(text)
    # IOCs are now rich dicts: {"value": str, "confidence": float, "label": str}
    ip_values = [i["value"] if isinstance(i, dict) else i for i in r["ips"]]
    assert "203.0.113.10" in ip_values
    hash_values = [h["value"] if isinstance(h, dict) else h for h in r["hashes"]]
    assert any(h.lower() == "deadbeefdeadbeefdeadbeefdeadbeef" for h in hash_values)


def test_empty_input() -> None:
    r = extract_iocs_from_text("")
    assert r["ips"] == []
    assert "empty" in r["notes"].lower()
