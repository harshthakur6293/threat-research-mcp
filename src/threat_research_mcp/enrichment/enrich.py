"""Real IOC enrichment via VirusTotal, AlienVault OTX, and AbuseIPDB.

All API keys are read from environment variables — never hardcoded.
Each source is optional: if the key is absent the source is skipped.
Results are merged into a single dict with a summary reputation field.
"""

from __future__ import annotations

import json
import os
import urllib.request
import urllib.error
from typing import Any


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get(url: str, headers: dict[str, str], timeout: int = 10) -> dict[str, Any] | None:
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        return {"_error": f"HTTP {exc.code}", "_source_url": url}
    except Exception as exc:
        return {"_error": str(exc), "_source_url": url}


def _ioc_type(value: str) -> str:
    import re
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", value):
        return "ip"
    if re.match(r"^[0-9a-fA-F]{32}$", value) or re.match(r"^[0-9a-fA-F]{40}$", value) or re.match(r"^[0-9a-fA-F]{64}$", value):
        return "hash"
    if re.match(r"^https?://", value):
        return "url"
    if re.match(r"^[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}(\.[a-zA-Z]{2,})?$", value):
        return "domain"
    return "unknown"


# ── VirusTotal ────────────────────────────────────────────────────────────────

def _virustotal(ioc: str, ioc_type: str) -> dict[str, Any] | None:
    key = os.environ.get("VIRUSTOTAL_API_KEY", "")
    if not key:
        return None

    base = "https://www.virustotal.com/api/v3"
    path = {
        "ip":     f"/ip_addresses/{ioc}",
        "domain": f"/domains/{ioc}",
        "hash":   f"/files/{ioc}",
        "url":    f"/urls/{ioc}",
    }.get(ioc_type)
    if not path:
        return None

    raw = _get(f"{base}{path}", {"x-apikey": key})
    if not raw or "_error" in raw:
        return raw

    stats = raw.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    total = sum(stats.values()) or 1
    return {
        "source": "VirusTotal",
        "malicious": malicious,
        "suspicious": stats.get("suspicious", 0),
        "clean": stats.get("undetected", 0),
        "total_engines": total,
        "detection_rate": f"{malicious}/{total}",
        "reputation": "malicious" if malicious > 5 else ("suspicious" if malicious > 0 else "clean"),
        "link": f"https://www.virustotal.com/gui/{'ip-address' if ioc_type=='ip' else ioc_type}/{ioc}",
    }


# ── AlienVault OTX ────────────────────────────────────────────────────────────

def _otx(ioc: str, ioc_type: str) -> dict[str, Any] | None:
    key = os.environ.get("OTX_API_KEY", "")
    if not key:
        return None

    base = "https://otx.alienvault.com/api/v1/indicators"
    section = "general"
    path = {
        "ip":     f"/IPv4/{ioc}/{section}",
        "domain": f"/domain/{ioc}/{section}",
        "hash":   f"/file/{ioc}/{section}",
        "url":    f"/url/{ioc}/{section}",
    }.get(ioc_type)
    if not path:
        return None

    raw = _get(f"{base}{path}", {"X-OTX-API-KEY": key})
    if not raw or "_error" in raw:
        return raw

    pulse_count = raw.get("pulse_info", {}).get("count", 0)
    return {
        "source": "AlienVault OTX",
        "pulse_count": pulse_count,
        "reputation": "malicious" if pulse_count > 3 else ("suspicious" if pulse_count > 0 else "clean"),
        "tags": raw.get("pulse_info", {}).get("tags", [])[:10],
        "link": f"https://otx.alienvault.com/indicator/{ioc_type}/{ioc}",
    }


# ── AbuseIPDB ─────────────────────────────────────────────────────────────────

def _abuseipdb(ioc: str, ioc_type: str) -> dict[str, Any] | None:
    if ioc_type != "ip":
        return None
    key = os.environ.get("ABUSEIPDB_API_KEY", "")
    if not key:
        return None

    raw = _get(
        f"https://api.abuseipdb.com/api/v2/check?ipAddress={ioc}&maxAgeInDays=90",
        {"Key": key, "Accept": "application/json"},
    )
    if not raw or "_error" in raw:
        return raw

    data = raw.get("data", {})
    score = data.get("abuseConfidenceScore", 0)
    return {
        "source": "AbuseIPDB",
        "abuse_confidence_score": score,
        "total_reports": data.get("totalReports", 0),
        "country": data.get("countryCode", ""),
        "isp": data.get("isp", ""),
        "reputation": "malicious" if score > 50 else ("suspicious" if score > 10 else "clean"),
        "link": f"https://www.abuseipdb.com/check/{ioc}",
    }


# ── URLhaus ───────────────────────────────────────────────────────────────────

def _urlhaus(ioc: str, ioc_type: str) -> dict[str, Any] | None:
    """URLhaus is free — no API key required for basic lookups."""
    if ioc_type not in ("url", "domain", "ip"):
        return None

    payload = json.dumps({"url" if ioc_type == "url" else "host": ioc}).encode()
    req = urllib.request.Request(
        "https://urlhaus-api.abuse.ch/v1/" + ("url/" if ioc_type == "url" else "host/"),
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = json.loads(resp.read().decode())
    except Exception:
        return None

    if raw.get("query_status") in ("no_results", "invalid_url"):
        return {"source": "URLhaus", "reputation": "clean", "hits": 0}

    urls = raw.get("urls", [])
    return {
        "source": "URLhaus",
        "hits": len(urls),
        "reputation": "malicious" if urls else "clean",
        "tags": list({t for u in urls for t in u.get("tags", []) if t})[:10],
        "link": f"https://urlhaus.abuse.ch/browse.php?search={ioc}",
    }


# ── Public API ────────────────────────────────────────────────────────────────

def enrich_ioc(ioc: str) -> str:
    """Enrich a single IOC against all configured sources. Returns JSON."""
    ioc = ioc.strip()
    ioc_type = _ioc_type(ioc)

    sources: list[dict[str, Any]] = []
    for fn in (_virustotal, _otx, _abuseipdb, _urlhaus):
        result = fn(ioc, ioc_type)
        if result:
            sources.append(result)

    reputations = [s.get("reputation", "unknown") for s in sources if not s.get("_error")]
    if "malicious" in reputations:
        overall = "malicious"
    elif "suspicious" in reputations:
        overall = "suspicious"
    elif reputations:
        overall = "clean"
    else:
        overall = "no_data"

    configured = [
        k for k in ("VIRUSTOTAL_API_KEY", "OTX_API_KEY", "ABUSEIPDB_API_KEY")
        if os.environ.get(k)
    ]
    if ioc_type in ("url", "domain", "ip"):
        configured.append("URLhaus (free, no key)")

    return json.dumps({
        "ioc": ioc,
        "ioc_type": ioc_type,
        "overall_reputation": overall,
        "sources_queried": len(sources),
        "sources": sources,
        "configured_sources": configured,
        "missing_keys": [
            k for k in ("VIRUSTOTAL_API_KEY", "OTX_API_KEY", "ABUSEIPDB_API_KEY")
            if not os.environ.get(k)
        ],
    }, indent=2)


def enrich_iocs_bulk(iocs: list[str]) -> str:
    """Enrich a list of IOCs. Returns JSON array."""
    results = [json.loads(enrich_ioc(ioc)) for ioc in iocs[:20]]  # cap at 20 to respect rate limits
    return json.dumps({
        "enriched": results,
        "count": len(results),
        "malicious": sum(1 for r in results if r["overall_reputation"] == "malicious"),
        "suspicious": sum(1 for r in results if r["overall_reputation"] == "suspicious"),
        "clean": sum(1 for r in results if r["overall_reputation"] == "clean"),
    }, indent=2)
