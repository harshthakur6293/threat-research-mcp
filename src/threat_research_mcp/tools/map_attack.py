"""ATT&CK technique mapper — keyword-to-technique index with evidence-based confidence scoring.

Keyword matching is case-insensitive. Each entry maps one or more text tokens
to a single ATT&CK technique. The tool returns every technique whose keywords
appear in the supplied text, de-duplicated, with supporting evidence and a
confidence score derived from keyword specificity and evidence diversity.

Confidence model:
  - keyword_specificity: how diagnostic the keyword is (ultra-high → low)
  - evidence_diversity: how many independent keywords matched
  - ioc_corroboration: bonus when extracted IOCs align with the technique
  - source_quality: multiplier based on the intelligence source type

Techniques below confidence_threshold (from operator.yaml, default 0.45) are
returned in a suppressed list rather than the main techniques list.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Tuple

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


# (tactic, technique_id, technique_name) keyed by lowercase keyword/phrase
_INDEX: Dict[str, Tuple[str, str, str]] = {
    # ── Execution ────────────────────────────────────────────────────────────
    "powershell": ("execution", "T1059.001", "PowerShell"),
    "encodedcommand": ("execution", "T1059.001", "PowerShell"),
    "-enc ": ("execution", "T1059.001", "PowerShell"),
    "invoke-expression": ("execution", "T1059.001", "PowerShell"),
    "iex(": ("execution", "T1059.001", "PowerShell"),
    "cmd.exe": ("execution", "T1059.003", "Windows Command Shell"),
    "wscript": ("execution", "T1059.005", "Visual Basic"),
    "cscript": ("execution", "T1059.005", "Visual Basic"),
    "vbscript": ("execution", "T1059.005", "Visual Basic"),
    "javascript": ("execution", "T1059.007", "JavaScript"),
    "jscript": ("execution", "T1059.007", "JavaScript"),
    "mshta": ("execution", "T1059.007", "JavaScript"),
    "bash -c": ("execution", "T1059.004", "Unix Shell"),
    "sh -c": ("execution", "T1059.004", "Unix Shell"),
    "python -c": ("execution", "T1059.006", "Python"),
    "perl -e": ("execution", "T1059.012", "Perl"),
    "ruby -e": ("execution", "T1059.013", "Ruby"),
    "wmic": ("execution", "T1047", "Windows Management Instrumentation"),
    "winrm": ("execution", "T1021.006", "Windows Remote Management"),
    "scheduled task": ("execution", "T1053.005", "Scheduled Task"),
    "schtasks": ("execution", "T1053.005", "Scheduled Task"),
    "at.exe": ("execution", "T1053.002", "At"),
    "cron": ("execution", "T1053.003", "Cron"),
    "msiexec": ("execution", "T1218.007", "Msiexec"),
    "regsvr32": ("execution", "T1218.010", "Regsvr32"),
    "rundll32": ("execution", "T1218.011", "Rundll32"),
    "certutil": ("execution", "T1140", "Deobfuscate/Decode Files or Information"),
    # ── Persistence ──────────────────────────────────────────────────────────
    "run key": ("persistence", "T1547.001", "Registry Run Keys / Startup Folder"),
    "hkcu\\software\\microsoft\\windows\\currentversion\\run": (
        "persistence",
        "T1547.001",
        "Registry Run Keys / Startup Folder",
    ),
    "startup folder": ("persistence", "T1547.001", "Registry Run Keys / Startup Folder"),
    "boot or logon": ("persistence", "T1547", "Boot or Logon Autostart Execution"),
    "autorun": ("persistence", "T1547.001", "Registry Run Keys / Startup Folder"),
    "service creation": ("persistence", "T1543.003", "Windows Service"),
    "sc create": ("persistence", "T1543.003", "Windows Service"),
    "new-service": ("persistence", "T1543.003", "Windows Service"),
    "web shell": ("persistence", "T1505.003", "Web Shell"),
    "webshell": ("persistence", "T1505.003", "Web Shell"),
    "backdoor": ("persistence", "T1505", "Server Software Component"),
    "crontab": ("persistence", "T1053.003", "Cron"),
    "rc.local": ("persistence", "T1037.004", "RC Scripts"),
    "systemd": ("persistence", "T1543.002", "Systemd Service"),
    # ── Privilege Escalation ─────────────────────────────────────────────────
    "privilege escalation": (
        "privilege-escalation",
        "T1068",
        "Exploitation for Privilege Escalation",
    ),
    "uac bypass": ("privilege-escalation", "T1548.002", "Bypass User Account Control"),
    "token impersonation": ("privilege-escalation", "T1134.001", "Token Impersonation/Theft"),
    "pass the hash": ("privilege-escalation", "T1550.002", "Pass the Hash"),
    "pass-the-hash": ("privilege-escalation", "T1550.002", "Pass the Hash"),
    "pass the ticket": ("privilege-escalation", "T1550.003", "Pass the Ticket"),
    "kerberoasting": ("credential-access", "T1558.003", "Kerberoasting"),
    "as-rep roasting": ("credential-access", "T1558.004", "AS-REP Roasting"),
    "sudo": ("privilege-escalation", "T1548.003", "Sudo and Sudo Caching"),
    "setuid": ("privilege-escalation", "T1548.001", "Setuid and Setgid"),
    # ── Defense Evasion ──────────────────────────────────────────────────────
    "obfuscat": ("defense-evasion", "T1027", "Obfuscated Files or Information"),
    "base64": ("defense-evasion", "T1027", "Obfuscated Files or Information"),
    "packed": ("defense-evasion", "T1027.002", "Software Packing"),
    "process injection": ("defense-evasion", "T1055", "Process Injection"),
    "dll injection": ("defense-evasion", "T1055.001", "Dynamic-link Library Injection"),
    "process hollowing": ("defense-evasion", "T1055.012", "Process Hollowing"),
    "timestomp": ("defense-evasion", "T1070.006", "Timestomp"),
    "disable logging": ("defense-evasion", "T1562.002", "Disable Windows Event Logging"),
    "disable antivirus": ("defense-evasion", "T1562.001", "Disable or Modify Tools"),
    "tamper": ("defense-evasion", "T1562", "Impair Defenses"),
    "reflective dll": ("defense-evasion", "T1620", "Reflective Code Loading"),
    "living off the land": ("defense-evasion", "T1218", "System Binary Proxy Execution"),
    "lolbin": ("defense-evasion", "T1218", "System Binary Proxy Execution"),
    "masquerad": ("defense-evasion", "T1036", "Masquerading"),
    "renamed binary": ("defense-evasion", "T1036.003", "Rename System Utilities"),
    "signed binary": ("defense-evasion", "T1218", "System Binary Proxy Execution"),
    # ── Credential Access ────────────────────────────────────────────────────
    "mimikatz": ("credential-access", "T1003", "OS Credential Dumping"),
    "lsass": ("credential-access", "T1003.001", "LSASS Memory"),
    "credential dump": ("credential-access", "T1003", "OS Credential Dumping"),
    "sekurlsa": ("credential-access", "T1003.001", "LSASS Memory"),
    "procdump": ("credential-access", "T1003.001", "LSASS Memory"),
    "ntds.dit": ("credential-access", "T1003.003", "NTDS"),
    "hashdump": ("credential-access", "T1003", "OS Credential Dumping"),
    "brute force": ("credential-access", "T1110", "Brute Force"),
    "password spray": ("credential-access", "T1110.003", "Password Spraying"),
    "credential stuffing": ("credential-access", "T1110.004", "Credential Stuffing"),
    "keylogger": ("credential-access", "T1056.001", "Keylogging"),
    "keylogging": ("credential-access", "T1056.001", "Keylogging"),
    # ── Discovery ────────────────────────────────────────────────────────────
    "nmap": ("discovery", "T1046", "Network Service Discovery"),
    "port scan": ("discovery", "T1046", "Network Service Discovery"),
    "net view": ("discovery", "T1135", "Network Share Discovery"),
    "net user": ("discovery", "T1087.002", "Domain Account"),
    "whoami": ("discovery", "T1033", "System Owner/User Discovery"),
    "ipconfig": ("discovery", "T1016", "System Network Configuration Discovery"),
    "ifconfig": ("discovery", "T1016", "System Network Configuration Discovery"),
    "systeminfo": ("discovery", "T1082", "System Information Discovery"),
    "tasklist": ("discovery", "T1057", "Process Discovery"),
    "ps aux": ("discovery", "T1057", "Process Discovery"),
    "ldap": ("discovery", "T1018", "Remote System Discovery"),
    "bloodhound": ("discovery", "T1482", "Domain Trust Discovery"),
    "sharphound": ("discovery", "T1482", "Domain Trust Discovery"),
    "domain trust": ("discovery", "T1482", "Domain Trust Discovery"),
    # ── Lateral Movement ─────────────────────────────────────────────────────
    "lateral movement": ("lateral-movement", "T1021", "Remote Services"),
    "psexec": ("lateral-movement", "T1021.002", "SMB/Windows Admin Shares"),
    "smb": ("lateral-movement", "T1021.002", "SMB/Windows Admin Shares"),
    "rdp": ("lateral-movement", "T1021.001", "Remote Desktop Protocol"),
    "remote desktop": ("lateral-movement", "T1021.001", "Remote Desktop Protocol"),
    "wmi execution": ("lateral-movement", "T1021.003", "Distributed Component Object Model"),
    "ssh": ("lateral-movement", "T1021.004", "SSH"),
    "rpcclient": ("lateral-movement", "T1021.003", "Distributed Component Object Model"),
    # ── Collection ───────────────────────────────────────────────────────────
    "data staging": ("collection", "T1074", "Data Staged"),
    "screen capture": ("collection", "T1113", "Screen Capture"),
    "screenshot": ("collection", "T1113", "Screen Capture"),
    "clipboard": ("collection", "T1115", "Clipboard Data"),
    "email collection": ("collection", "T1114", "Email Collection"),
    # ── Command & Control ────────────────────────────────────────────────────
    "c2": ("command-and-control", "T1071", "Application Layer Protocol"),
    "command and control": ("command-and-control", "T1071", "Application Layer Protocol"),
    "beacon": ("command-and-control", "T1071.001", "Web Protocols"),
    "cobalt strike": ("command-and-control", "T1071.001", "Web Protocols"),
    "sliver": ("command-and-control", "T1071.001", "Web Protocols"),
    "metasploit": ("command-and-control", "T1071.001", "Web Protocols"),
    "dns tunneling": ("command-and-control", "T1071.004", "DNS"),
    "dns tunnel": ("command-and-control", "T1071.004", "DNS"),
    "domain fronting": ("command-and-control", "T1090.004", "Domain Fronting"),
    "tor network": ("command-and-control", "T1090.003", "Multi-hop Proxy"),
    "via tor": ("command-and-control", "T1090.003", "Multi-hop Proxy"),
    "proxy": ("command-and-control", "T1090", "Proxy"),
    # ── Exfiltration ─────────────────────────────────────────────────────────
    "exfiltrat": ("exfiltration", "T1041", "Exfiltration Over C2 Channel"),
    "data theft": ("exfiltration", "T1041", "Exfiltration Over C2 Channel"),
    "exfil over dns": ("exfiltration", "T1048.003", "Exfiltration Over Unencrypted Protocol"),
    "ftp upload": ("exfiltration", "T1048", "Exfiltration Over Alternative Protocol"),
    "rclone": ("exfiltration", "T1567.002", "Exfiltration to Cloud Storage"),
    "mega.nz": ("exfiltration", "T1567.002", "Exfiltration to Cloud Storage"),
    # ── Initial Access ───────────────────────────────────────────────────────
    "phishing": ("initial-access", "T1566", "Phishing"),
    "spearphish": ("initial-access", "T1566.001", "Spearphishing Attachment"),
    "malicious attachment": ("initial-access", "T1566.001", "Spearphishing Attachment"),
    "malicious link": ("initial-access", "T1566.002", "Spearphishing Link"),
    "drive-by": ("initial-access", "T1189", "Drive-by Compromise"),
    "watering hole": ("initial-access", "T1189", "Drive-by Compromise"),
    "supply chain": ("initial-access", "T1195", "Supply Chain Compromise"),
    "valid accounts": ("initial-access", "T1078", "Valid Accounts"),
    "stolen credentials": ("initial-access", "T1078", "Valid Accounts"),
    "vpn credential": ("initial-access", "T1133", "External Remote Services"),
    "vpn access": ("initial-access", "T1133", "External Remote Services"),
    "exploit public": ("initial-access", "T1190", "Exploit Public-Facing Application"),
    "sql injection": ("initial-access", "T1190", "Exploit Public-Facing Application"),
    "remote code execution": ("initial-access", "T1190", "Exploit Public-Facing Application"),
    # ── macOS-specific ───────────────────────────────────────────────────────
    "osascript": ("execution", "T1059.002", "AppleScript"),
    "applescript": ("execution", "T1059.002", "AppleScript"),
    "osacompile": ("execution", "T1059.002", "AppleScript"),
    "zsh -c": ("execution", "T1059.004", "Unix Shell"),
    "curl | bash": ("execution", "T1059.004", "Unix Shell"),
    "curl | sh": ("execution", "T1059.004", "Unix Shell"),
    "curl | osascript": ("execution", "T1059.004", "Unix Shell"),
    "launchd": ("persistence", "T1543.001", "Launch Agent"),
    "launch daemon": ("persistence", "T1543.001", "Launch Agent"),
    "launch agent": ("persistence", "T1543.001", "Launch Agent"),
    "launchctl": ("persistence", "T1543.001", "Launch Agent"),
    "loginitem": ("persistence", "T1547.009", "Shortcut Modification"),
    "tcc database": ("defense-evasion", "T1548.006", "TCC Manipulation"),
    "tcc.db": ("defense-evasion", "T1548.006", "TCC Manipulation"),
    "transparency consent": ("defense-evasion", "T1548.006", "TCC Manipulation"),
    "gatekeeper": ("defense-evasion", "T1553.001", "Gatekeeper Bypass"),
    "quarantine attribute": ("defense-evasion", "T1553.001", "Gatekeeper Bypass"),
    "notarization": ("defense-evasion", "T1553.001", "Gatekeeper Bypass"),
    "mach-o": ("defense-evasion", "T1027", "Obfuscated Files or Information"),
    "universal binary": ("defense-evasion", "T1027", "Obfuscated Files or Information"),
    "keychain": ("credential-access", "T1555.001", "Keychain"),
    "security find-generic-password": ("credential-access", "T1555.001", "Keychain"),
    "security find-internet-password": ("credential-access", "T1555.001", "Keychain"),
    "session hijack": ("credential-access", "T1539", "Steal Web Session Cookie"),
    "session cookie": ("credential-access", "T1539", "Steal Web Session Cookie"),
    "telegram bot api": ("exfiltration", "T1567.002", "Exfiltration to Web Service"),
    "telegram bot": ("exfiltration", "T1567.002", "Exfiltration to Web Service"),
    "bot api": ("exfiltration", "T1567.002", "Exfiltration to Web Service"),
    "discord webhook": ("exfiltration", "T1567.002", "Exfiltration to Web Service"),
    "archive collected": ("collection", "T1560.001", "Archive via Utility"),
    "zip archive": ("collection", "T1560.001", "Archive via Utility"),
    "compress and exfil": ("collection", "T1560.001", "Archive via Utility"),
    "nscreateobjec": ("defense-evasion", "T1620", "Reflective Code Loading"),
    "in-memory execution": ("defense-evasion", "T1620", "Reflective Code Loading"),
    "fileless": ("defense-evasion", "T1620", "Reflective Code Loading"),
    "user execution": ("execution", "T1204.002", "Malicious File"),
    "malicious file": ("execution", "T1204.002", "Malicious File"),
    "open the file": ("execution", "T1204.002", "Malicious File"),
    "spearphishing link": ("initial-access", "T1566.002", "Spearphishing Link"),
    "linkedin lure": ("initial-access", "T1566.002", "Spearphishing Link"),
    "fake job": ("initial-access", "T1566.002", "Spearphishing Link"),
    "fake recruiter": ("initial-access", "T1566.002", "Spearphishing Link"),
    "cryptocurrency wallet": ("collection", "T1005", "Data from Local System"),
    "crypto wallet": ("collection", "T1005", "Data from Local System"),
    "ledger live": ("collection", "T1005", "Data from Local System"),
    "exodus wallet": ("collection", "T1005", "Data from Local System"),
    "wallet seed": ("collection", "T1005", "Data from Local System"),
    # ── Supply Chain / CI-CD ─────────────────────────────────────────────────
    "software supply chain": ("initial-access", "T1195.001", "Compromise Software Supply Chain"),
    "dependency confusion": ("initial-access", "T1195.001", "Compromise Software Supply Chain"),
    "typosquat": ("initial-access", "T1195.001", "Compromise Software Supply Chain"),
    "malicious package": ("initial-access", "T1195.001", "Compromise Software Supply Chain"),
    "package poisoning": ("initial-access", "T1195.001", "Compromise Software Supply Chain"),
    "artifact poison": ("initial-access", "T1195.001", "Compromise Software Supply Chain"),
    "pypi": ("initial-access", "T1195.001", "Compromise Software Supply Chain"),
    " npm ": ("initial-access", "T1195.001", "Compromise Software Supply Chain"),
    "pip install": ("initial-access", "T1195.001", "Compromise Software Supply Chain"),
    "malicious workflow": ("initial-access", "T1195.002", "Compromise Software Dependencies"),
    "github actions": ("initial-access", "T1195.002", "Compromise Software Dependencies"),
    "ci/cd": ("initial-access", "T1195.002", "Compromise Software Dependencies"),
    "build pipeline": ("initial-access", "T1195.002", "Compromise Software Dependencies"),
    # ── Cloud / Container ────────────────────────────────────────────────────
    "169.254.169.254": ("credential-access", "T1552.005", "Cloud Instance Metadata API"),
    "imds": ("credential-access", "T1552.005", "Cloud Instance Metadata API"),
    "instance metadata": ("credential-access", "T1552.005", "Cloud Instance Metadata API"),
    "metadata service": ("credential-access", "T1552.005", "Cloud Instance Metadata API"),
    "cloud credential": ("credential-access", "T1552.005", "Cloud Instance Metadata API"),
    "iam role": ("privilege-escalation", "T1078.004", "Cloud Accounts"),
    "assumed role": ("privilege-escalation", "T1078.004", "Cloud Accounts"),
    "service principal": ("privilege-escalation", "T1078.004", "Cloud Accounts"),
    "cloud account": ("initial-access", "T1078.004", "Cloud Accounts"),
    "s3 bucket": ("collection", "T1530", "Data from Cloud Storage"),
    "blob storage": ("collection", "T1530", "Data from Cloud Storage"),
    "cloud storage": ("collection", "T1530", "Data from Cloud Storage"),
    "gcs bucket": ("collection", "T1530", "Data from Cloud Storage"),
    "docker exec": ("execution", "T1609", "Container Administration Command"),
    "kubectl exec": ("execution", "T1609", "Container Administration Command"),
    "container exec": ("execution", "T1609", "Container Administration Command"),
    "deploy container": ("defense-evasion", "T1610", "Deploy Container"),
    "daemonset": ("persistence", "T1610", "Deploy Container"),
    "malicious container": ("defense-evasion", "T1610", "Deploy Container"),
    "container discovery": ("discovery", "T1613", "Container and Resource Discovery"),
    "docker ps": ("discovery", "T1613", "Container and Resource Discovery"),
    "kubectl get": ("discovery", "T1613", "Container and Resource Discovery"),
    "kubernetes": ("discovery", "T1613", "Container and Resource Discovery"),
    # ── Impact ───────────────────────────────────────────────────────────────
    "ransomware": ("impact", "T1486", "Data Encrypted for Impact"),
    "encrypted files": ("impact", "T1486", "Data Encrypted for Impact"),
    "ransom note": ("impact", "T1486", "Data Encrypted for Impact"),
    "wiper": ("impact", "T1485", "Data Destruction"),
    "data destruction": ("impact", "T1485", "Data Destruction"),
    "defacement": ("impact", "T1491", "Defacement"),
    "denial of service": ("impact", "T1499", "Endpoint Denial of Service"),
    "ddos": ("impact", "T1499", "Endpoint Denial of Service"),
}

# Pre-compile patterns with word-boundary anchors where applicable.
_PATTERNS: Dict[str, re.Pattern] = {kw: _compile(kw) for kw in _INDEX}


# ── Confidence scoring helpers ────────────────────────────────────────────────


def _load_confidence_weights() -> Dict[str, Any]:
    candidates = [
        Path(__file__).parent.parent.parent.parent / "playbook" / "confidence_weights.yaml",
        Path(os.getcwd()) / "playbook" / "confidence_weights.yaml",
    ]
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
    high = float(_WEIGHTS.get("high_threshold", 0.85))
    warn = float(_WEIGHTS.get("warn_threshold", 0.65))
    suppress = float(_WEIGHTS.get("suppress_threshold", 0.45))
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
                              confidence_weights.yaml / operator.yaml.
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
        suppress_thresh = float(_WEIGHTS.get("suppress_threshold", 0.45))
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
