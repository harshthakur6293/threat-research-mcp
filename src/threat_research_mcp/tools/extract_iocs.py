"""Context-aware IOC extractor with confidence scoring.

Extracts indicators of compromise from free-form threat intelligence text and
assigns each IOC a confidence score based on surrounding sentence context.

Confidence model:
  1. Regex finds candidate IOCs in text
  2. For each candidate, the surrounding sentence is examined for context patterns
  3. Malicious patterns increase confidence; victim/researcher/example patterns reduce it
  4. Always-filtered patterns (RFC 1918 IPs, macOS bundle IDs, known-benign domains)
     are removed regardless of confidence
  5. IOCs below include_threshold are returned in a filtered_fps list for transparency

Context patterns are loaded from playbook/ioc_context_patterns.yaml.
Falls back to built-in defaults if the file is not found.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

try:
    import yaml

    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False


# ── Regex patterns ────────────────────────────────────────────────────────────

_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)
_HASH = re.compile(r"\b(?:[a-fA-F\d]{32}|[a-fA-F\d]{40}|[a-fA-F\d]{64})\b")
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_DOMAIN = re.compile(
    r"\b(?=[a-zA-Z0-9.-]{4,253}\b)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}\b"
)
_URL = re.compile(r'\bhttps?://[^\s<>"{}|\\^`\[\]]+', re.IGNORECASE)

# macOS bundle identifier: 3+ label reverse-DNS (com.apple.foo, org.chromium.bar)
_MACOS_BUNDLE = re.compile(
    r"\b(?:com|org|io|net|edu|gov)\.[a-zA-Z0-9\-]+(?:\.[a-zA-Z0-9\-]+){1,}\b"
)

# File extensions that look like TLDs
_FILE_EXTENSIONS: frozenset[str] = frozenset(
    {
        "sh",
        "py",
        "pyc",
        "pyd",
        "pyw",
        "rb",
        "go",
        "rs",
        "c",
        "cpp",
        "h",
        "js",
        "ts",
        "jsx",
        "tsx",
        "php",
        "pl",
        "lua",
        "r",
        "jl",
        "swift",
        "exe",
        "dll",
        "so",
        "dylib",
        "bin",
        "elf",
        "sys",
        "drv",
        "bat",
        "cmd",
        "ps1",
        "psm1",
        "vbs",
        "wsf",
        "json",
        "yaml",
        "yml",
        "toml",
        "xml",
        "ini",
        "cfg",
        "conf",
        "env",
        "txt",
        "log",
        "csv",
        "tsv",
        "md",
        "rst",
        "tar",
        "gz",
        "bz2",
        "xz",
        "zip",
        "rar",
        "7z",
        "zst",
        "deb",
        "rpm",
        "pkg",
        "apk",
        "dmg",
        "msi",
        "whl",
        "egg",
        "war",
        "jar",
        "class",
        "img",
        "iso",
        "vmdk",
        "ova",
        "pth",
        "lock",
        "sum",
        "mod",
        "scpt",
        "app",
        "plist",
        "kext",
        "framework",
        "bundle",
        "local",
    }
)

# RFC 1918 / loopback / special ranges — never malicious C2
_PRIVATE_IP = re.compile(
    r"^(?:"
    r"10\.\d+\.\d+\.\d+|"
    r"172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|"
    r"192\.168\.\d+\.\d+|"
    r"127\.\d+\.\d+\.\d+|"
    r"169\.254\.\d+\.\d+|"
    r"0\.0\.0\.0|"
    r"255\.255\.255\.255"
    r")$"
)

# Known-benign domain suffixes/exact matches — CDN, Microsoft, Google, etc.
_BENIGN_DOMAINS: frozenset[str] = frozenset(
    {
        "windows.com",
        "microsoft.com",
        "windowsupdate.com",
        "office.com",
        "live.com",
        "azure.com",
        "azureedge.net",
        "microsoftonline.com",
        "amazonaws.com",
        "cloudfront.net",
        "akamaihd.net",
        "akamai.net",
        "fastly.net",
        "cloudflare.com",
        "cloudflare.net",
        "google.com",
        "googleapis.com",
        "gstatic.com",
        "googlesyndication.com",
        "apple.com",
        "icloud.com",
        "mzstatic.com",
        "github.com",
        "githubusercontent.com",
        "githubassets.com",
        "pypi.org",
        "npmjs.com",
        "pkg.go.dev",
        "rubygems.org",
        "example.com",
        "example.org",
        "example.net",
        "test.com",
        "localhost",
        "invalid",
        "w3.org",
        "schema.org",
    }
)


# ── Context pattern loader ────────────────────────────────────────────────────


def _load_context_patterns() -> dict[str, Any]:
    """Load ioc_context_patterns.yaml from playbook/. Returns built-in defaults on failure."""
    candidates = [
        Path(__file__).parent.parent.parent.parent / "playbook" / "ioc_context_patterns.yaml",
        Path(os.getcwd()) / "playbook" / "ioc_context_patterns.yaml",
    ]
    for path in candidates:
        if path.exists() and _YAML_AVAILABLE:
            try:
                with open(path, encoding="utf-8") as fh:
                    return yaml.safe_load(fh) or {}
            except (OSError, yaml.YAMLError):
                continue

    # Built-in minimal defaults
    return {
        "malicious": [
            {"pattern": "c2", "weight": 1.0},
            {"pattern": "beacon", "weight": 0.9},
            {"pattern": "callback", "weight": 0.9},
            {"pattern": "payload", "weight": 0.9},
            {"pattern": "malware", "weight": 0.9},
            {"pattern": "malicious", "weight": 0.85},
            {"pattern": "attacker", "weight": 0.85},
            {"pattern": "exfil", "weight": 0.95},
            {"pattern": "dropper", "weight": 0.95},
            {"pattern": "backdoor", "weight": 0.95},
            {"pattern": "hosted.*at", "weight": 0.8},
            {"pattern": "contacted", "weight": 0.7},
        ],
        "victim": [
            {"pattern": "victim", "weight": -1.0},
            {"pattern": "gateway", "weight": -0.8},
            {"pattern": "internal.*IP", "weight": -0.9},
            {"pattern": "our.*network", "weight": -1.0},
        ],
        "researcher": [
            {"pattern": "sandbox", "weight": -1.0},
            {"pattern": "sinkhole", "weight": -0.9},
        ],
        "example": [
            {"pattern": "example\\.com", "weight": -1.0},
            {"pattern": "for example", "weight": -0.9},
            {"pattern": "placeholder", "weight": -1.0},
        ],
        "default_confidence": 0.5,
        "include_threshold": 0.35,
    }


_CONTEXT_PATTERNS: dict[str, Any] = _load_context_patterns()

# Pre-compile context regexes
_COMPILED_CONTEXT: list[tuple[float, re.Pattern]] = []
for _category in ("malicious", "infrastructure", "victim", "researcher", "example"):
    for _entry in _CONTEXT_PATTERNS.get(_category, []):
        _pat = _entry.get("pattern", "")
        _w = float(_entry.get("weight", 0.0))
        try:
            _COMPILED_CONTEXT.append((_w, re.compile(_pat, re.IGNORECASE)))
        except re.error:
            pass


# ── Sentence extraction ───────────────────────────────────────────────────────


def _sentences(text: str) -> list[str]:
    """Split text into sentences (approximate — good enough for context windows)."""
    return re.split(r"(?<=[.!?])\s+|\n{1,}", text)


def _context_window(text: str, ioc: str, window: int = 120) -> str:
    """Return up to `window` chars surrounding the IOC occurrence."""
    idx = text.find(ioc)
    if idx == -1:
        return text[:window]
    start = max(0, idx - window // 2)
    end = min(len(text), idx + len(ioc) + window // 2)
    return text[start:end]


# ── Confidence scoring ────────────────────────────────────────────────────────


def _score_context(context: str) -> float:
    """Score the context surrounding an IOC. Returns float in [-1.0, 1.0]."""
    score = 0.0
    for weight, pattern in _COMPILED_CONTEXT:
        if pattern.search(context):
            score += weight
    return max(-1.0, min(1.0, score))


def _confidence(context_score: float) -> float:
    """Convert raw context score to a [0.0, 1.0] confidence value."""
    default = float(_CONTEXT_PATTERNS.get("default_confidence", 0.5))
    if context_score >= 0:
        return min(1.0, default + context_score * (1.0 - default))
    else:
        return max(0.0, default + context_score * default)


def _include_threshold() -> float:
    return float(_CONTEXT_PATTERNS.get("include_threshold", 0.35))


# ── Always-filter checks ──────────────────────────────────────────────────────


def _is_private_ip(ip: str) -> bool:
    return bool(_PRIVATE_IP.match(ip))


def _is_macos_bundle(domain: str) -> bool:
    parts = domain.split(".")
    if len(parts) < 3:
        return False
    prefix = parts[0].lower()
    return prefix in {"com", "org", "io", "net", "edu", "gov", "co"}


def _is_benign_domain(domain: str) -> bool:
    dl = domain.lower()
    if dl in _BENIGN_DOMAINS:
        return True
    for benign in _BENIGN_DOMAINS:
        if dl.endswith("." + benign):
            return True
    return False


def _is_file_extension_domain(domain: str) -> bool:
    tld = domain.rsplit(".", 1)[-1].lower()
    return tld in _FILE_EXTENSIONS


def _is_version_string(candidate: str, text: str) -> bool:
    """Return True if the IP-like string is a software version (e.g. '1.2.3.4')."""
    ctx = _context_window(text, candidate, 30)
    return bool(re.search(r"\bv(?:ersion)?\s*" + re.escape(candidate), ctx, re.IGNORECASE))


# ── Dedup helper ──────────────────────────────────────────────────────────────


def _unique_scored(items: list[dict]) -> list[dict]:
    seen: set[str] = set()
    out: list[dict] = []
    for item in items:
        val = item["value"]
        if val and val not in seen:
            seen.add(val)
            out.append(item)
    return out


# ── Main extractor ────────────────────────────────────────────────────────────


def extract_iocs_from_text(text: str, source_quality: str = "unknown") -> dict:
    """Extract IOCs from text with context-aware confidence scoring.

    Returns a dict with keys: ips, domains, urls, hashes, emails, filtered_fps, notes.
    Each IOC is {"value": str, "confidence": float, "label": str}.
    filtered_fps is a list of IOCs that were extracted but suppressed.
    """
    if not text or not text.strip():
        return {
            "ips": [],
            "domains": [],
            "urls": [],
            "hashes": [],
            "emails": [],
            "filtered_fps": [],
            "notes": "empty input",
        }

    threshold = _include_threshold()
    ips: list[dict] = []
    domains: list[dict] = []
    urls: list[dict] = []
    hashes: list[dict] = []
    emails: list[dict] = []
    filtered_fps: list[dict] = []

    # ── IPs ──────────────────────────────────────────────────────────────────
    for match in _IPV4.finditer(text):
        val = match.group()
        if _is_private_ip(val):
            filtered_fps.append({"value": val, "type": "ip", "reason": "RFC1918/loopback"})
            continue
        if _is_version_string(val, text):
            filtered_fps.append({"value": val, "type": "ip", "reason": "version string"})
            continue
        ctx = _context_window(text, val)
        cs = _score_context(ctx)
        conf = _confidence(cs)
        label = "MALICIOUS" if cs > 0.3 else ("VICTIM" if cs < -0.3 else "UNKNOWN")
        record = {"value": val, "confidence": round(conf, 3), "label": label}
        if conf >= threshold:
            ips.append(record)
        else:
            filtered_fps.append({**record, "type": "ip", "reason": f"low confidence ({conf:.2f})"})

    # ── URLs (extract before domains to avoid URL fragments being re-matched) ─
    for match in _URL.finditer(text):
        val = match.group().rstrip(".,;)'\"")
        ctx = _context_window(text, val)
        cs = _score_context(ctx)
        conf = _confidence(cs)
        urls.append({"value": val, "confidence": round(conf, 3), "label": "URL"})

    url_strings = {u["value"] for u in urls}

    # ── Domains ───────────────────────────────────────────────────────────────
    ip_set = {i["value"] for i in ips}
    for match in _DOMAIN.finditer(text):
        val = match.group()
        # Skip if it's an IP, part of a URL, file extension, bundle ID, or benign
        if val in ip_set:
            continue
        if any(val in u for u in url_strings):
            continue
        if _is_file_extension_domain(val):
            filtered_fps.append({"value": val, "type": "domain", "reason": "file extension TLD"})
            continue
        if _is_macos_bundle(val):
            filtered_fps.append({"value": val, "type": "domain", "reason": "macOS bundle ID"})
            continue
        if _is_benign_domain(val):
            filtered_fps.append({"value": val, "type": "domain", "reason": "known benign"})
            continue
        ctx = _context_window(text, val)
        cs = _score_context(ctx)
        conf = _confidence(cs)
        label = "MALICIOUS" if cs > 0.3 else ("VICTIM" if cs < -0.3 else "UNKNOWN")
        record = {"value": val, "confidence": round(conf, 3), "label": label}
        if conf >= threshold:
            domains.append(record)
        else:
            filtered_fps.append(
                {**record, "type": "domain", "reason": f"low confidence ({conf:.2f})"}
            )

    # ── Hashes ────────────────────────────────────────────────────────────────
    for match in _HASH.finditer(text):
        val = match.group()
        ctx = _context_window(text, val)
        cs = _score_context(ctx)
        conf = _confidence(cs)
        hashes.append({"value": val, "confidence": round(conf, 3), "label": "HASH"})

    # ── Emails ────────────────────────────────────────────────────────────────
    for match in _EMAIL.finditer(text):
        val = match.group()
        ctx = _context_window(text, val)
        cs = _score_context(ctx)
        conf = _confidence(cs)
        emails.append({"value": val, "confidence": round(conf, 3), "label": "EMAIL"})

    return {
        "ips": _unique_scored(ips),
        "domains": _unique_scored(domains),
        "urls": _unique_scored(urls),
        "hashes": _unique_scored(hashes),
        "emails": _unique_scored(emails),
        "filtered_fps": filtered_fps,
        "notes": (
            f"Context-aware extraction. Threshold: {threshold}. "
            f"Filtered {len(filtered_fps)} candidates (RFC1918, bundles, benign, low-confidence). "
            "Verify all IOCs before blocking."
        ),
    }


def extract_iocs_json(text: str, source_quality: str = "unknown") -> str:
    """JSON wrapper for extract_iocs_from_text."""
    return json.dumps(extract_iocs_from_text(text, source_quality), indent=2)
