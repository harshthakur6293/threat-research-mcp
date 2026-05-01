"""ATT&CK technique mapper — keyword-to-technique index with evidence-based confidence scoring.

Keyword matching is case-insensitive. Each entry maps one or more text tokens
to a single ATT&CK technique. The tool returns every technique whose keywords
appear in the supplied text, de-duplicated, with supporting evidence and a
confidence score derived from keyword specificity and evidence diversity.

Single source of truth: playbook/keywords.yaml. To add or fix keywords, edit
that file — this module loads from it at startup and uses no hardcoded index.

Confidence model:
  - keyword_specificity: how diagnostic the keyword is (ultra-high → low)
  - evidence_diversity: how many independent keywords matched
  - ioc_corroboration: bonus when extracted IOCs align with the technique
  - source_quality: multiplier based on the intelligence source type

Techniques below confidence_threshold (from confidence_weights.yaml, default 0.35)
are returned in a suppressed list rather than the main techniques list.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Tuple

from threat_research_mcp.utils.paths import playbook_file

try:
    import yaml as _yaml

    _YAML_OK = True
except ImportError:
    _YAML_OK = False


def _compile(keyword: str) -> re.Pattern:
    """Compile keyword to regex with word-boundaries where applicable."""
    kw = keyword.strip()
    pat = re.escape(kw)
    if re.match(r"\w", kw[0]):
        pat = r"\b" + pat
    if re.search(r"\w$", kw):
        pat = pat + r"\b"
    return re.compile(pat, re.IGNORECASE)


def _load_keyword_index() -> Dict[str, Tuple[str, str, str]]:
    """Load keyword→(tactic, technique_id, name) from playbook/keywords.yaml.

    Falls back to a minimal hardcoded set if the file cannot be read, so the
    tool degrades gracefully without crashing on a fresh install before the
    playbook directory is available.
    """
    candidates = [p for p in [playbook_file("keywords.yaml")] if p is not None]
    if _YAML_OK:
        for p in candidates:
            if p.exists():
                try:
                    with open(p, encoding="utf-8") as fh:
                        data = _yaml.safe_load(fh) or {}
                    index: Dict[str, Tuple[str, str, str]] = {}
                    for entry in data.get("entries", []):
                        kw = str(entry.get("keyword", "")).lower()
                        tactic = str(entry.get("tactic", ""))
                        tid = str(entry.get("technique_id", ""))
                        name = str(entry.get("technique_name", ""))
                        if kw and tid:
                            index[kw] = (tactic, tid, name)
                    if index:
                        return index
                except (OSError, _yaml.YAMLError):
                    continue

    # Minimal fallback — keeps the tool functional when YAML unavailable
    return {
        "powershell": ("execution", "T1059.001", "PowerShell"),
        "mimikatz": ("credential-access", "T1003", "OS Credential Dumping"),
        "cobalt strike": ("command-and-control", "T1071.001", "Web Protocols"),
        "ransomware": ("impact", "T1486", "Data Encrypted for Impact"),
        "phishing": ("initial-access", "T1566", "Phishing"),
        "lsass": ("credential-access", "T1003.001", "LSASS Memory"),
        "web shell": ("persistence", "T1505.003", "Web Shell"),
    }


# (tactic, technique_id, technique_name) keyed by lowercase keyword/phrase
_INDEX: Dict[str, Tuple[str, str, str]] = _load_keyword_index()

# Pre-compile patterns with word-boundary anchors where applicable.
_PATTERNS: Dict[str, re.Pattern] = {kw: _compile(kw) for kw in _INDEX}


# ── Confidence scoring helpers ────────────────────────────────────────────────


def _load_confidence_weights() -> Dict[str, Any]:
    candidates = [p for p in [playbook_file("confidence_weights.yaml")] if p is not None]
    if _YAML_OK:
        for p in candidates:
            if p.exists():
                try:
                    with open(p, encoding="utf-8") as fh:
                        return _yaml.safe_load(fh) or {}
                except (OSError, _yaml.YAMLError):
                    continue
    return {}


_WEIGHTS: Dict[str, Any] = _load_confidence_weights()


def _keyword_specificity(keyword: str) -> float:
    """Return specificity score [0.0, 1.0] for a keyword.

    The YAML uses dot-notation ("cobalt.strike") while the index uses spaces
    ("cobalt strike"). We normalise both to dots before comparing.
    """
    kw_dotted = keyword.strip().lower().replace(" ", ".")
    spec = _WEIGHTS.get("keyword_specificity", {})
    for tier, score in [
        ("ultra_high", 0.95),
        ("high", 0.80),
        ("medium", 0.60),
        ("low", 0.30),
    ]:
        tier_keys = [k.lower().replace(" ", ".") for k in spec.get(tier, [])]
        if kw_dotted in tier_keys:
            return score
    return 0.50  # default — unknown keyword


def _evidence_diversity_score(count: int) -> float:
    ed = _WEIGHTS.get("evidence_diversity_scores", {})
    if count >= 5:
        return float(ed.get("5+", 0.95))
    return float(ed.get(str(count), 0.30 + count * 0.15))


def _source_quality_score(source_quality: str) -> float:
    sq = _WEIGHTS.get("source_quality", {})
    return float(sq.get(source_quality, sq.get("unknown", 0.55)))


def _ioc_corroboration_bonus(tactic: str, iocs: Dict[str, List]) -> float:
    ic = _WEIGHTS.get("ioc_corroboration", {})
    has_network = bool(iocs.get("ips") or iocs.get("domains"))
    has_hash = bool(iocs.get("hashes"))
    if tactic in ("command-and-control", "exfiltration") and has_network:
        return float(ic.get("network_ioc_for_c2_technique", 0.30))
    if tactic in ("execution", "defense-evasion", "persistence") and has_hash:
        return float(ic.get("file_hash_for_execution", 0.25))
    if has_hash:
        return float(ic.get("file_hash_for_any_technique", 0.15))
    return float(ic.get("no_ioc_corroboration", 0.0))


def _compute_confidence(
    evidence: List[str],
    tactic: str,
    iocs: Dict[str, List],
    source_quality: str,
) -> float:
    """Compute evidence-based confidence score [0.0, 1.0]."""
    dim_weights = _WEIGHTS.get(
        "dimensions",
        {
            "keyword_specificity": 0.35,
            "evidence_diversity": 0.25,
            "ioc_corroboration": 0.20,
            "source_quality": 0.20,
        },
    )

    avg_specificity = (
        sum(_keyword_specificity(kw) for kw in evidence) / len(evidence) if evidence else 0.30
    )
    diversity = _evidence_diversity_score(len(evidence))
    corroboration = _ioc_corroboration_bonus(tactic, iocs)
    quality = _source_quality_score(source_quality)

    score = (
        avg_specificity * float(dim_weights.get("keyword_specificity", 0.35))
        + diversity * float(dim_weights.get("evidence_diversity", 0.25))
        + corroboration * float(dim_weights.get("ioc_corroboration", 0.20))
        + quality * float(dim_weights.get("source_quality", 0.20))
    )
    return round(min(1.0, max(0.0, score)), 3)


def _confidence_label(score: float) -> str:
    high = float(_WEIGHTS.get("high_threshold", 0.75))
    warn = float(_WEIGHTS.get("warn_threshold", 0.55))
    suppress = float(_WEIGHTS.get("suppress_threshold", 0.35))
    if score >= high:
        return "HIGH"
    if score >= warn:
        return "MEDIUM"
    if score >= suppress:
        return "LOW"
    return "SUPPRESSED"


# ── Public API ────────────────────────────────────────────────────────────────


def map_attack(
    text: str,
    iocs: Dict[str, List] | None = None,
    source_quality: str = "unknown",
    confidence_threshold: float | None = None,
) -> str:
    """Map free-form threat text to ATT&CK techniques with evidence-based confidence.

    Args:
        text: Raw threat intel text to analyse.
        iocs: Optional IOC dict from extract_iocs_from_text() — used for
              IOC corroboration bonus when scoring technique confidence.
        source_quality: Source type key from confidence_weights.yaml
                        (e.g. 'vendor_blog', 'cisa_advisory', 'unknown').
        confidence_threshold: Override the suppress threshold from
                              confidence_weights.yaml.
                              Techniques below this score appear in suppressed[].

    Returns: JSON with techniques (above threshold), suppressed (below threshold),
             and confidence metadata.
    """
    if iocs is None:
        iocs = {}

    # Flatten rich IOC dicts to plain lists for corroboration check
    flat_iocs: Dict[str, List] = {}
    for key in ("ips", "domains", "hashes", "emails"):
        items = iocs.get(key, [])
        flat_iocs[key] = [i["value"] if isinstance(i, dict) else i for i in items]

    # Determine threshold
    if confidence_threshold is None:
        suppress_thresh = float(_WEIGHTS.get("suppress_threshold", 0.35))
    else:
        suppress_thresh = confidence_threshold

    seen: Dict[str, dict] = {}

    for keyword, (tactic, tid, name) in _INDEX.items():
        if _PATTERNS[keyword].search(text):
            if tid not in seen:
                seen[tid] = {
                    "id": tid,
                    "name": name,
                    "tactic": tactic,
                    "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
                    "evidence": [],
                }
            seen[tid]["evidence"].append(keyword.strip())

    techniques: List[dict] = []
    suppressed: List[dict] = []

    for entry in sorted(seen.values(), key=lambda t: t["tactic"]):
        conf = _compute_confidence(entry["evidence"], entry["tactic"], flat_iocs, source_quality)
        label = _confidence_label(conf)
        enriched = {**entry, "confidence": conf, "confidence_label": label}
        if conf >= suppress_thresh:
            techniques.append(enriched)
        else:
            suppressed.append(enriched)

    return json.dumps(
        {
            "techniques": techniques,
            "count": len(techniques),
            "suppressed": suppressed,
            "suppressed_count": len(suppressed),
            "confidence_threshold": suppress_thresh,
            "source_quality": source_quality,
            "note": (
                f"{len(suppressed)} technique(s) suppressed (confidence < {suppress_thresh}). "
                "Lower confidence_threshold or check suppressed[] to see them."
                if suppressed
                else ""
            ),
        },
        indent=2,
    )
