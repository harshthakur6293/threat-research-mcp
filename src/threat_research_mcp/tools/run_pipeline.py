"""Full threat research pipeline — single call from feed to detections.

Chains: feed ingestion → IOC extraction → enrichment → TTP mapping →
        hunt hypotheses → Sigma detection bundle.

All steps are optional and gracefully degrade when not configured:
- Feed ingestion is skipped if sources_config is empty
- IOC enrichment is skipped unless enrich=True (to avoid unexpected API calls)
- Hunt hypotheses are filtered to log_sources if provided
"""

from __future__ import annotations

import json
import re
from typing import Any

# Ordered by specificity — first match wins
_SOURCE_QUALITY_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"cisa\.gov", re.I), "cisa_advisory"),
    (re.compile(r"ncsc\.(gov\.uk|nl|no|fi|ie)", re.I), "ncsc_advisory"),
    (re.compile(r"(msrc|microsoft)\.com", re.I), "vendor_blog"),
    (re.compile(r"(cloud\.google|mandiant|chronicle)\.com", re.I), "vendor_blog"),
    (re.compile(r"(crowdstrike|sentinelone|paloaltonetworks|unit42)\.com", re.I), "vendor_blog"),
    (re.compile(r"(securelist|kaspersky)\.com", re.I), "vendor_blog"),
    (re.compile(r"(recordedfuture|threatfabric|proofpoint)\.com", re.I), "vendor_blog"),
    (re.compile(r"(isac|information-sharing|h-isac|fs-isac)\.org", re.I), "isac_advisory"),
]


def _detect_source_quality(text: str) -> str:
    """Infer source quality from URLs or attribution phrases in the text."""
    for pattern, quality in _SOURCE_QUALITY_PATTERNS:
        if pattern.search(text):
            return quality
    return "unknown"


def run_pipeline(
    text: str = "",
    sources_config: str = "",
    log_sources: str = "",
    enrich: bool = False,
    source_quality: str = "",
) -> str:
    """Run the full threat research pipeline in a single call.

    Steps:
      1. Feed ingestion (if sources_config path is provided)
      2. IOC extraction from combined text
      3. IOC enrichment against VT / OTX / AbuseIPDB / URLhaus (if enrich=True)
      4. ATT&CK technique mapping (with IOC corroboration and source quality)
      5. Hunt hypothesis generation (filtered to log_sources if provided)
      6. Sigma rule bundle for detected techniques

    Args:
        text: Raw threat intel text (paste from report, email, IR note, etc.)
        sources_config: Path to sources YAML/JSON for feed ingestion.
                        See configs/sources.example.yaml for format.
        log_sources: Comma-separated log source keys to filter hypotheses.
                     Leave empty to get all available log sources.
                     Use list_log_sources() to see available keys.
                     Example: "sysmon_process,script_block_logging,dns_logs"
        enrich: Set True to query VirusTotal, OTX, AbuseIPDB, URLhaus for
                the top IOCs extracted. Requires API keys in environment.
                Default False to avoid unexpected external API calls.
        source_quality: Intelligence source type for confidence scoring.
                        One of: cisa_advisory, ncsc_advisory, isac_advisory,
                        vendor_blog, researcher_blog, open_source_report,
                        pastebin_forum. Leave empty to auto-detect from URLs
                        in the text (Microsoft/Mandiant/CISA domains recognized).

    Returns: Comprehensive JSON with all pipeline stages and a summary.
    """
    result: dict[str, Any] = {
        "pipeline_stages": [],
        "summary": {},
    }

    combined_text = text.strip()

    # Resolve source quality — explicit param wins, otherwise auto-detect
    resolved_quality = source_quality.strip() or _detect_source_quality(combined_text)

    # ── Stage 1: Feed ingestion ───────────────────────────────────────────────
    if sources_config.strip():
        from threat_research_mcp.tools.ingest_tools import ingest_from_config_path_json

        try:
            ingest_raw = json.loads(ingest_from_config_path_json(sources_config.strip()))
            result["ingestion"] = ingest_raw
            result["pipeline_stages"].append("feed_ingestion")

            # Append document text to combined analysis text
            docs = ingest_raw.get("documents", [])
            if docs:
                doc_text = " ".join(
                    d.get("content", "") or d.get("text", "") or d.get("title", "") for d in docs
                )
                combined_text = (combined_text + " " + doc_text).strip()
        except Exception as exc:
            result["ingestion"] = {"error": str(exc)}
    else:
        result["ingestion"] = {"skipped": "No sources_config provided."}

    if not combined_text:
        return json.dumps(
            {
                **result,
                "error": "No text to analyze — provide text or a valid sources_config path.",
            },
            indent=2,
        )

    # ── Stage 2: IOC extraction ───────────────────────────────────────────────
    from threat_research_mcp.tools.extract_iocs import extract_iocs_json

    iocs_raw = json.loads(extract_iocs_json(combined_text))
    result["iocs"] = iocs_raw
    result["pipeline_stages"].append("ioc_extraction")

    # Build flat list for enrichment
    all_iocs: list[str] = []
    for key in ("ips", "domains", "urls", "hashes"):
        for item in iocs_raw.get(key, []):
            all_iocs.append(item.get("value", "") if isinstance(item, dict) else item)

    # ── Stage 3: IOC enrichment (optional) ────────────────────────────────────
    if enrich and all_iocs:
        from threat_research_mcp.enrichment.enrich import enrich_iocs_bulk

        top_iocs = all_iocs[:5]  # cap at 5 to stay within free-tier rate limits
        enrich_raw = json.loads(enrich_iocs_bulk(top_iocs))
        result["enrichment"] = enrich_raw
        result["pipeline_stages"].append("ioc_enrichment")
    else:
        result["enrichment"] = {
            "skipped": (
                "Set enrich=True to query VirusTotal / OTX / AbuseIPDB / URLhaus."
                if not enrich
                else "No IOCs found to enrich."
            )
        }

    # ── Stage 4: ATT&CK TTP mapping ──────────────────────────────────────────
    from threat_research_mcp.tools.map_attack import map_attack

    ttp_raw = json.loads(map_attack(combined_text, iocs=iocs_raw, source_quality=resolved_quality))
    result["techniques"] = ttp_raw
    result["source_quality_used"] = resolved_quality
    result["pipeline_stages"].append("ttp_mapping")

    technique_ids = [t["id"] for t in ttp_raw.get("techniques", [])]

    # ── Stage 5: Hunt hypotheses ──────────────────────────────────────────────
    if technique_ids:
        from threat_research_mcp.tools.generate_hunt_hypothesis import (
            generate_hunt_hypotheses_for_techniques,
        )

        src_filter = [s.strip() for s in log_sources.split(",") if s.strip()] or None
        hunt_raw = json.loads(generate_hunt_hypotheses_for_techniques(technique_ids, src_filter))
        result["hunt_hypotheses"] = hunt_raw
        result["pipeline_stages"].append("hunt_hypotheses")
    else:
        result["hunt_hypotheses"] = {
            "hypotheses": [],
            "note": "No ATT&CK techniques detected — try adding technique names or tool names to text.",
        }

    # ── Stage 6: Sigma detection bundle ──────────────────────────────────────
    if technique_ids:
        from threat_research_mcp.tools.generate_sigma import generate_sigma_bundle

        sigma_raw = json.loads(generate_sigma_bundle(technique_ids))
        result["detections"] = {
            "sigma": sigma_raw,
            "note": (
                "Use kql_for_technique / spl_for_technique / eql_for_technique "
                "for SIEM-specific detection rules. Use yara_for_technique for "
                "file-based scanning rules."
            ),
        }
        result["pipeline_stages"].append("sigma_detections")
    else:
        result["detections"] = {"sigma": {"rules": []}}

    # ── Summary ───────────────────────────────────────────────────────────────
    ioc_total = sum(len(iocs_raw.get(k, [])) for k in ("ips", "domains", "urls", "hashes"))
    hypotheses_count = len(result.get("hunt_hypotheses", {}).get("hypotheses", []))
    sigma_count = len(result.get("detections", {}).get("sigma", {}).get("rules", []))

    result["summary"] = {
        "text_chars_analyzed": len(combined_text),
        "iocs_extracted": ioc_total,
        "techniques_detected": len(technique_ids),
        "technique_ids": technique_ids,
        "hunt_hypotheses_generated": hypotheses_count,
        "sigma_rules_generated": sigma_count,
        "enrichment_performed": enrich and bool(all_iocs),
        "log_source_filter": log_sources or "all",
        "source_quality": resolved_quality,
        "stages_completed": result["pipeline_stages"],
        "next_steps": _next_steps(technique_ids, ioc_total, enrich, sigma_count),
    }

    return json.dumps(result, indent=2)


def _next_steps(
    technique_ids: list[str],
    ioc_total: int,
    enrich_done: bool,
    sigma_count: int,
) -> list[str]:
    steps = []
    if ioc_total > 0 and not enrich_done:
        steps.append(
            "Run enrich_iocs_tool with extracted IOCs to get reputation data "
            "(or re-run run_pipeline with enrich=True)."
        )
    if technique_ids:
        steps.append(
            f"Run kql_for_technique / spl_for_technique / eql_for_technique "
            f"for SIEM-native detection rules for: {', '.join(technique_ids[:5])}."
        )
        steps.append("Run yara_for_technique for file-based YARA scanning rules.")
    if sigma_count > 0:
        steps.append(
            "Deploy Sigma rules to your SIEM using sigmac or pySigma. "
            "Pair with Security-Detections-MCP (list_by_mitre) to check existing coverage."
        )
    if not steps:
        steps.append(
            "No techniques detected. Try providing more specific threat intel text "
            "with technique names, tool names, or attack keywords."
        )
    return steps
