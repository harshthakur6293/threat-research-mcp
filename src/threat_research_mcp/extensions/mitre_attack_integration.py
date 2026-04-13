"""Integration with mitre-attack-mcp for automatic technique mapping.

This module provides utilities to call the mitre-attack-mcp server to automatically
map threat intelligence to ATT&CK techniques, which can then be used for log source
recommendations.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional


def call_mitre_attack_mcp(
    query: str, tool_name: str = "search_techniques", timeout: int = 30
) -> Optional[Dict[str, Any]]:
    """
    Call mitre-attack-mcp tool via MCP stdio protocol.

    Args:
        query: Search query or text to analyze
        tool_name: MCP tool name (search_techniques, get_technique, etc.)
        timeout: Command timeout in seconds

    Returns:
        Parsed JSON response from mitre-attack-mcp, or None on error
    """
    try:
        # This is a placeholder - in production, you would:
        # 1. Use the MCP SDK to call the tool directly
        # 2. Or use subprocess to call via stdio
        # 3. Or use HTTP if mitre-attack-mcp supports it

        # For now, return a mock response structure
        # In production, replace with actual MCP call
        return None
    except Exception:
        return None


def extract_techniques_from_intel(intel_text: str) -> List[str]:
    """
    Automatically extract ATT&CK techniques from threat intelligence text.

    This function analyzes the intel and returns relevant technique IDs.
    In production, this would call mitre-attack-mcp's search or analysis tools.

    Args:
        intel_text: Threat intelligence text to analyze

    Returns:
        List of ATT&CK technique IDs (e.g., ["T1071.001", "T1090"])
    """
    # Keyword-based heuristic mapping for common patterns
    # In production, replace with actual mitre-attack-mcp calls
    techniques: List[str] = []

    intel_lower = intel_text.lower()

    # Command and Control patterns
    if any(kw in intel_lower for kw in ["c2", "command and control", "c&c", "callback", "beacon"]):
        techniques.append("T1071.001")  # Application Layer Protocol: Web Protocols

    if any(kw in intel_lower for kw in ["proxy", "proxying", "proxy server"]):
        techniques.append("T1090")  # Proxy

    if any(
        kw in intel_lower
        for kw in [
            "encrypted c2",
            "encrypted channel",
            "encrypted communication",
            "tls",
            "ssl",
        ]
    ):
        techniques.append("T1573.002")  # Encrypted Channel: Asymmetric Cryptography

    if any(kw in intel_lower for kw in ["domain generation", "dga", "dynamic dns", "fast flux"]):
        techniques.append("T1568.002")  # Dynamic Resolution: Domain Generation Algorithms

    # Web3/Blockchain/Decentralized patterns
    if any(
        kw in intel_lower
        for kw in [
            "blockchain",
            "web3",
            "decentralized",
            "smart contract",
            "canister",
            "ipfs",
            "ethereum",
        ]
    ):
        # Web3 C2 typically uses web protocols
        if "T1071.001" not in techniques:
            techniques.append("T1071.001")
        # Often involves proxy-like behavior
        if "T1090" not in techniques:
            techniques.append("T1090")

    # Persistence patterns
    if any(
        kw in intel_lower
        for kw in [
            "scheduled task",
            "cron",
            "at job",
            "task scheduler",
            "persistence mechanism",
        ]
    ):
        techniques.append("T1053.005")  # Scheduled Task/Job

    if any(kw in intel_lower for kw in ["registry", "run key", "autorun"]):
        techniques.append("T1547.001")  # Boot or Logon Autostart Execution

    if any(kw in intel_lower for kw in ["service", "systemd", "windows service"]):
        techniques.append("T1543.003")  # Create or Modify System Process: Windows Service

    # Execution patterns
    if any(kw in intel_lower for kw in ["powershell", "pwsh", "ps1", "invoke-expression", "iex"]):
        techniques.append("T1059.001")  # PowerShell

    if any(kw in intel_lower for kw in ["bash", "shell script", "sh", "/bin/bash"]):
        techniques.append("T1059.004")  # Command and Scripting Interpreter: Unix Shell

    # Credential Access
    if any(kw in intel_lower for kw in ["lsass", "credential dump", "mimikatz"]):
        techniques.append("T1003.001")  # OS Credential Dumping: LSASS Memory

    if any(kw in intel_lower for kw in ["password spray", "brute force", "credential stuffing"]):
        techniques.append("T1110.003")  # Brute Force: Password Spraying

    # Defense Evasion
    if any(kw in intel_lower for kw in ["clear log", "event log", "wevtutil", "clear-eventlog"]):
        techniques.append("T1070.001")  # Indicator Removal: Clear Windows Event Logs

    if any(
        kw in intel_lower for kw in ["disable defender", "disable antivirus", "tamper protection"]
    ):
        techniques.append("T1562.001")  # Impair Defenses: Disable or Modify Tools

    # Lateral Movement
    if any(kw in intel_lower for kw in ["rdp", "remote desktop", "terminal services"]):
        techniques.append("T1021.001")  # Remote Services: RDP

    if any(kw in intel_lower for kw in ["psexec", "wmi", "windows management"]):
        techniques.append("T1021.006")  # Remote Services: Windows Remote Management

    # Initial Access
    if any(
        kw in intel_lower for kw in ["phishing", "spearphishing", "malicious attachment", "email"]
    ):
        techniques.append("T1566.001")  # Phishing: Spearphishing Attachment

    if any(kw in intel_lower for kw in ["exploit", "vulnerability", "cve", "public-facing"]):
        techniques.append("T1190")  # Exploit Public-Facing Application

    # Exfiltration
    if any(
        kw in intel_lower
        for kw in ["exfiltration", "data theft", "cloud storage", "s3", "blob storage"]
    ):
        techniques.append("T1567.002")  # Exfiltration to Cloud Storage

    # Impact
    if any(
        kw in intel_lower
        for kw in ["ransomware", "encrypted files", "ransom note", "crypto locker"]
    ):
        techniques.append("T1486")  # Data Encrypted for Impact

    # Account Manipulation
    if any(kw in intel_lower for kw in ["create account", "new user", "useradd", "net user"]):
        techniques.append("T1136.001")  # Create Account: Local Account

    if any(
        kw in intel_lower for kw in ["privilege escalation", "admin rights", "elevate privileges"]
    ):
        techniques.append("T1078")  # Valid Accounts

    # Remove duplicates and return
    return list(set(techniques))


def intel_to_log_sources(
    intel_text: str,
    environment: str = "hybrid",
    siem_platforms: str = "splunk,sentinel,elastic",
    auto_detect_techniques: bool = True,
    manual_techniques: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Complete pipeline: Intel → ATT&CK Techniques → Log Sources & Queries.

    Args:
        intel_text: Threat intelligence text to analyze
        environment: Target environment (aws, azure, gcp, on-prem, hybrid)
        siem_platforms: Comma-separated SIEM platforms
        auto_detect_techniques: If True, automatically extract techniques from intel
        manual_techniques: Optional list of manually specified techniques

    Returns:
        Dictionary with:
        - detected_techniques: Auto-detected ATT&CK techniques
        - manual_techniques: User-provided techniques
        - all_techniques: Combined list
        - log_sources: Log source recommendations
        - hunt_queries: SIEM-specific queries
        - deployment_checklist: Prioritized actions
        - intel_summary: Brief summary of the intel
    """
    from threat_research_mcp.detection.log_source_mapper import (
        get_log_sources_for_techniques,
    )
    from threat_research_mcp.detection.query_generator import (
        generate_deployment_checklist,
        generate_hunt_queries,
    )

    # Auto-detect techniques from intel
    detected_techniques: List[str] = []
    if auto_detect_techniques:
        detected_techniques = extract_techniques_from_intel(intel_text)

    # Combine with manual techniques
    all_techniques = list(set(detected_techniques + (manual_techniques or [])))

    if not all_techniques:
        return {
            "error": "No ATT&CK techniques detected or provided",
            "intel_summary": intel_text[:200] + "..." if len(intel_text) > 200 else intel_text,
            "detected_techniques": [],
            "manual_techniques": manual_techniques or [],
            "suggestion": "Try providing manual techniques or use more descriptive threat intel text",
        }

    # Get log sources
    log_sources = get_log_sources_for_techniques(all_techniques, environment)

    # Parse SIEM platforms
    siem_list = [s.strip() for s in siem_platforms.split(",") if s.strip()]

    # Generate hunt queries
    queries = generate_hunt_queries(all_techniques, siem_list)

    # Generate deployment checklist
    checklist = generate_deployment_checklist(log_sources)

    return {
        "intel_summary": intel_text[:200] + "..." if len(intel_text) > 200 else intel_text,
        "detected_techniques": detected_techniques,
        "manual_techniques": manual_techniques or [],
        "all_techniques": all_techniques,
        "environment": environment,
        "log_sources": log_sources["log_sources"],
        "priority_summary": log_sources["priority_summary"],
        "hunt_queries": queries["queries"],
        "deployment_checklist": checklist,
        "blind_spots": log_sources.get("blind_spots", []),
    }


def intel_to_log_sources_json(
    intel_text: str,
    environment: str = "hybrid",
    siem_platforms: str = "splunk,sentinel,elastic",
    manual_techniques: str = "",
) -> str:
    """
    JSON wrapper for intel_to_log_sources.

    Args:
        intel_text: Threat intelligence text
        environment: Target environment
        siem_platforms: Comma-separated SIEM platforms
        manual_techniques: Optional comma-separated technique IDs

    Returns:
        JSON string with complete analysis
    """
    manual_list = (
        [t.strip() for t in manual_techniques.split(",") if t.strip()]
        if manual_techniques
        else None
    )

    result = intel_to_log_sources(
        intel_text=intel_text,
        environment=environment,
        siem_platforms=siem_platforms,
        auto_detect_techniques=True,
        manual_techniques=manual_list,
    )

    return json.dumps(result, indent=2)
