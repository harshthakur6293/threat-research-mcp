"""Map agent/tool dict outputs into the canonical AnalysisProduct schema."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from threat_research_mcp.schemas.analysis_product import AnalysisProduct, IntelProvenance
from threat_research_mcp.schemas.detection_delivery import (
    DetectionDeliveryBundle,
    DetectionRuleArtifact,
    LogSourceGuidance,
)
from threat_research_mcp.schemas.hunt_delivery import (
    HuntDeliveryPack,
    HuntOpportunity,
    HuntQueryArtifact,
)
from threat_research_mcp.schemas.ioc_objects import (
    IocDomain,
    IocEmail,
    IocHash,
    IocIpv4,
    IocUrl,
    IocObject,
)
from threat_research_mcp.schemas.ttp_alignment import TechniqueAlignment


def _hash_algorithm(hex_digest: str) -> str:
    n = len(hex_digest)
    if n == 32:
        return "md5"
    if n == 40:
        return "sha1"
    if n == 64:
        return "sha256"
    return "other"


def ioc_dict_to_objects(iocs: Dict[str, Any], *, snippet: str = "") -> List[IocObject]:
    """Convert extract_iocs_from_text() shape into discriminated IOC models."""
    out: List[IocObject] = []
    for ip in iocs.get("ips") or []:
        if isinstance(ip, str) and ip.strip():
            out.append(IocIpv4(value=ip.strip(), source_snippet=snippet[:500]))
    for d in iocs.get("domains") or []:
        if isinstance(d, str) and d.strip():
            out.append(IocDomain(value=d.strip(), source_snippet=snippet[:500]))
    for u in iocs.get("urls") or []:
        if isinstance(u, str) and u.strip():
            out.append(IocUrl(value=u.strip(), source_snippet=snippet[:500]))
    for e in iocs.get("emails") or []:
        if isinstance(e, str) and e.strip():
            out.append(IocEmail(value=e.strip(), source_snippet=snippet[:500]))
    for h in iocs.get("hashes") or []:
        if isinstance(h, str) and h.strip():
            alg = _hash_algorithm(h.strip())
            out.append(
                IocHash(
                    value=h.strip().lower(),
                    algorithm=alg if alg in ("md5", "sha1", "sha256", "sha512") else "other",
                    source_snippet=snippet[:500],
                )
            )
    return out


def _parse_attack_json(attack_field: Any) -> List[TechniqueAlignment]:
    if attack_field is None:
        return []
    if isinstance(attack_field, str):
        try:
            data = json.loads(attack_field)
        except json.JSONDecodeError:
            return []
    elif isinstance(attack_field, dict):
        data = attack_field
    else:
        return []
    techniques = data.get("techniques") or []
    alignments: List[TechniqueAlignment] = []
    for t in techniques:
        if not isinstance(t, dict):
            continue
        tid = t.get("id") or ""
        if not tid:
            continue
        alignments.append(
            TechniqueAlignment(
                technique_id=str(tid),
                technique_name=t.get("name"),
                evidence=str(t.get("evidence", "")),
                confidence="medium",
                data_source_hints=[],
            )
        )
    return alignments


def _hunt_pack_from_hunting(hunting: Dict[str, Any], input_text: str) -> HuntDeliveryPack:
    if not hunting:
        return HuntDeliveryPack()
    hyp_raw = hunting.get("hypothesis")
    opportunities: List[HuntOpportunity] = []
    if isinstance(hyp_raw, str) and hyp_raw.strip():
        try:
            h = json.loads(hyp_raw)
        except json.JSONDecodeError:
            h = {}
        if isinstance(h, dict) and (h.get("title") or h.get("hypothesis")):
            tel = h.get("required_telemetry") or []
            if not isinstance(tel, list):
                tel = []
            tel_strs = [str(x) for x in tel]
            queries: List[HuntQueryArtifact] = []
            if hunting.get("timeline"):
                queries.append(
                    HuntQueryArtifact(
                        language="pseudo",
                        title="Timeline reconstruction",
                        body=str(hunting.get("timeline"))[:8000],
                        log_source_hints=[],
                    )
                )
            if hunting.get("log_explanation"):
                queries.append(
                    HuntQueryArtifact(
                        language="pseudo",
                        title="Log explanation",
                        body=str(hunting.get("log_explanation"))[:8000],
                        log_source_hints=[],
                    )
                )
            opportunities.append(
                HuntOpportunity(
                    title=str(h.get("title") or "Hunt"),
                    hypothesis=str(h.get("hypothesis") or ""),
                    related_technique_ids=[],
                    required_telemetry=tel_strs,
                    hunt_steps=[],
                    queries=queries,
                    analyst_notes=[str(h.get("evidence", ""))[:2000]] if h.get("evidence") else [],
                )
            )
    summary = ""
    if hunting.get("log_explanation"):
        summary = str(hunting.get("log_explanation"))[:400]
    return HuntDeliveryPack(opportunities=opportunities, summary=summary)


def _detection_bundle_from_detection(
    detection: Dict[str, Any], input_text: str
) -> DetectionDeliveryBundle:
    rules: List[DetectionRuleArtifact] = []
    if not detection:
        return DetectionDeliveryBundle()

    tech_ids: List[str] = []
    raw_tids = detection.get("technique_ids")
    if isinstance(raw_tids, list):
        tech_ids = [str(x) for x in raw_tids if str(x).strip()]
    ds_list: List[str] = []
    raw_ds = detection.get("data_source_recommendations")
    if isinstance(raw_ds, list):
        ds_list = [str(x) for x in raw_ds if str(x).strip()]

    sigma_body = detection.get("sigma")
    if isinstance(sigma_body, str) and sigma_body.strip():
        rules.append(
            DetectionRuleArtifact(
                rule_format="sigma",
                title="Generated Sigma draft",
                body=sigma_body,
                description="Heuristic draft; validate with validate_sigma / pySigma before deployment.",
                technique_ids=tech_ids,
                logsource_category="process_creation",
                data_source_recommendations=list(ds_list),
            )
        )

    kql_body = detection.get("kql")
    if isinstance(kql_body, str) and kql_body.strip():
        rules.append(
            DetectionRuleArtifact(
                rule_format="kql",
                title="Draft KQL (Microsoft Sentinel-style)",
                body=kql_body,
                description="Tune table/column names to your workspace.",
                technique_ids=tech_ids,
                platform_hints=["windows", "microsoft_sentinel"],
                data_source_recommendations=list(ds_list),
            )
        )

    spl_body = detection.get("spl")
    if isinstance(spl_body, str) and spl_body.strip():
        rules.append(
            DetectionRuleArtifact(
                rule_format="spl",
                title="Draft SPL (Sysmon / Windows Security)",
                body=spl_body,
                description="Tune index and sourcetype to your deployment.",
                technique_ids=tech_ids,
                platform_hints=["windows", "splunk"],
                data_source_recommendations=list(ds_list),
            )
        )
    ideas_raw = detection.get("ideas")
    if isinstance(ideas_raw, str) and ideas_raw.strip():
        try:
            ide = json.loads(ideas_raw)
        except json.JSONDecodeError:
            ide = {}
        if isinstance(ide, dict):
            idea_list = ide.get("ideas") or []
            if isinstance(idea_list, list):
                for i, idea in enumerate(idea_list[:20]):
                    if not isinstance(idea, str):
                        continue
                    rules.append(
                        DetectionRuleArtifact(
                            rule_format="other",
                            title=f"Detection idea {i + 1}",
                            body=idea,
                            description="Narrative opportunity; translate to SIEM query.",
                            technique_ids=[],
                        )
                    )
    notes: List[str] = []
    if isinstance(detection.get("ideas"), str):
        notes.append("Review ideas JSON for coverage vs environment.")

    # Add log source guidance if techniques are present
    log_guidance: Optional[LogSourceGuidance] = None
    if tech_ids:
        try:
            from threat_research_mcp.detection.log_source_mapper import (
                get_log_sources_for_techniques,
            )
            from threat_research_mcp.detection.query_generator import (
                generate_deployment_checklist,
                generate_hunt_queries,
            )

            # Get log sources for detected techniques
            log_sources = get_log_sources_for_techniques(tech_ids, environment="hybrid")

            # Generate hunt queries for common SIEM platforms
            queries = generate_hunt_queries(tech_ids, ["splunk", "sentinel", "elastic"])

            # Generate deployment checklist
            checklist = generate_deployment_checklist(log_sources)

            log_guidance = LogSourceGuidance(
                techniques=tech_ids,
                environment="hybrid",
                priority_summary=log_sources.get("priority_summary", {}),
                log_sources=log_sources.get("log_sources", {}),
                hunt_queries=queries.get("queries", {}),
                deployment_checklist=checklist,
                blind_spots=log_sources.get("blind_spots", []),
            )

            if log_guidance.log_sources:
                notes.append(
                    f"Log source guidance generated for {len(tech_ids)} technique(s). "
                    "Review deployment_checklist for priority actions."
                )
        except Exception:
            # Silently skip if log source mapper is not available
            pass

    return DetectionDeliveryBundle(rules=rules, log_source_guidance=log_guidance, notes=notes)


def build_analysis_product(
    *,
    workflow: str,
    input_text: str,
    research: Dict[str, Any],
    hunting: Dict[str, Any],
    detection: Dict[str, Any],
    review: Dict[str, Any],
    request_id: Optional[str] = None,
    provenance: Optional[List[IntelProvenance]] = None,
) -> AnalysisProduct:
    """Assemble AnalysisProduct from orchestrator agent dicts (legacy shape)."""
    prov = list(provenance or [])
    if not prov:
        prov.append(
            IntelProvenance(
                source_name="workflow",
                source_type=workflow,
                ingested_at=None,
            )
        )

    iocs_raw = research.get("iocs") or {}
    if not isinstance(iocs_raw, dict):
        iocs_raw = {}

    narrative = str(research.get("summary") or "")
    extracted = ioc_dict_to_objects(iocs_raw, snippet=input_text[:2000])
    alignments = _parse_attack_json(research.get("attack"))

    hunt_pack = _hunt_pack_from_hunting(hunting, input_text)
    det_bundle = _detection_bundle_from_detection(detection, input_text)

    review_notes = list(review.get("notes") or [])
    if not isinstance(review_notes, list):
        review_notes = [str(review_notes)]
    review_notes = [str(n) for n in review_notes]

    status = str(review.get("status") or "") or None

    common = dict(
        provenance=prov,
        narrative_summary=narrative,
        extracted_iocs=extracted,
        technique_alignments=alignments,
        hunt_pack=hunt_pack,
        detection_bundle=det_bundle,
        review_status=status,
        review_notes=review_notes,
    )
    if request_id:
        return AnalysisProduct(product_id=request_id, **common)
    return AnalysisProduct(**common)
