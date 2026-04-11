from threat_research_mcp.tools.extract_iocs import extract_iocs_from_text


def test_extracts_ip_and_hash() -> None:
    text = "Beacon to 203.0.113.10 and hash deadbeefdeadbeefdeadbeefdeadbeef"
    r = extract_iocs_from_text(text)
    assert "203.0.113.10" in r["ips"]
    assert any(h.lower() == "deadbeefdeadbeefdeadbeefdeadbeef" for h in r["hashes"])


def test_empty_input() -> None:
    r = extract_iocs_from_text("")
    assert r["ips"] == []
    assert "empty" in r["notes"].lower()
