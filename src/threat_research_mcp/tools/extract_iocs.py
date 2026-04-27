from __future__ import annotations

import json
import re

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

# Extensions that look like domains (word.ext) but are actually filenames.
_FILE_EXTENSIONS: set[str] = {
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
    # macOS-specific
    "scpt",
    "app",
    "plist",
    "dylib",
    "kext",
    "framework",
    "bundle",
    "pkg",
    "dmg",
    "local",
}


def _unique(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        val = item.strip()
        if val and val not in seen:
            seen.add(val)
            out.append(val)
    return out


def extract_iocs_from_text(text: str) -> dict:
    if not text or not text.strip():
        return {
            "ips": [],
            "domains": [],
            "urls": [],
            "hashes": [],
            "emails": [],
            "notes": "empty input",
        }

    ips = _unique(_IPV4.findall(text))
    urls = _unique(_URL.findall(text))
    hashes = _unique(_HASH.findall(text))
    emails = _unique(_EMAIL.findall(text))
    domain_hits = _unique(_DOMAIN.findall(text))
    domains = [
        d
        for d in domain_hits
        if d not in ips
        and not any(d in u for u in urls)
        and d.rsplit(".", 1)[-1].lower() not in _FILE_EXTENSIONS
    ]

    return {
        "ips": ips,
        "domains": _unique(domains),
        "urls": urls,
        "hashes": hashes,
        "emails": emails,
        "notes": "heuristic extraction; verify before action",
    }


def extract_iocs_json(text: str) -> str:
    return json.dumps(extract_iocs_from_text(text), indent=2)
