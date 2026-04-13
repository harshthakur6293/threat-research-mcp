"""Demo: Log Source Recommendations for Common Attack Scenarios.

This example demonstrates the v0.3 log source recommendation feature
for three common security scenarios:
1. Phishing incident with PowerShell payload
2. Ransomware attack
3. Cloud account compromise
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Add src to path for local development
_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_ROOT / "src"))

from threat_research_mcp.tools.recommend_log_sources import (  # noqa: E402
    recommend_log_sources_json,
)


def print_section(title: str) -> None:
    """Print a formatted section header."""
    print("\n" + "=" * 80)
    print(f"  {title}")
    print("=" * 80 + "\n")


def demo_phishing_incident() -> None:
    """Demo: Phishing incident with PowerShell payload."""
    print_section("Scenario 1: Phishing Incident with PowerShell Payload")

    print("Detected Techniques:")
    print("  - T1566.001 (Phishing: Spearphishing Attachment)")
    print("  - T1059.001 (PowerShell)")
    print("  - T1105 (Ingress Tool Transfer)")
    print("\nEnvironment: Hybrid (on-prem + cloud)")
    print("SIEM Platforms: Splunk, Microsoft Sentinel\n")

    result_json = recommend_log_sources_json(
        technique_ids="T1566.001,T1059.001,T1105",
        environment="hybrid",
        siem_platforms="splunk,sentinel",
    )

    result = json.loads(result_json)

    # Show priority summary
    print("Priority Summary:")
    print(f"  Critical: {len(result['priority_summary']['critical'])} sources")
    print(f"  High:     {len(result['priority_summary']['high'])} sources")
    print(f"  Medium:   {len(result['priority_summary']['medium'])} sources")

    # Show top 3 deployment actions
    print("\nTop 3 Deployment Actions:")
    for i, item in enumerate(result["deployment_checklist"][:3], 1):
        print(f"\n  {i}. [{item['priority'].upper()}] {item['platform']} - {item['source']}")
        print(f"     Action: {item['action']}")
        if "configuration_steps" in item:
            print(f"     Config: {item['configuration_steps'][:80]}...")

    # Show sample query
    print("\nSample Splunk Query for PowerShell Detection:")
    powershell_query = result["hunt_queries"]["T1059.001"]["splunk"]["query"]
    print(f"\n{powershell_query[:300]}...\n")


def demo_ransomware_attack() -> None:
    """Demo: Ransomware attack."""
    print_section("Scenario 2: Ransomware Attack")

    print("Detected Techniques:")
    print("  - T1486 (Data Encrypted for Impact)")
    print("  - T1070.001 (Clear Windows Event Logs)")
    print("  - T1562.001 (Impair Defenses)")
    print("\nEnvironment: On-Premises")
    print("SIEM Platforms: Splunk, Elastic\n")

    result_json = recommend_log_sources_json(
        technique_ids="T1486,T1070.001,T1562.001",
        environment="on-prem",
        siem_platforms="splunk,elastic",
    )

    result = json.loads(result_json)

    # Show critical sources
    print("Critical Log Sources:")
    for source in result["priority_summary"]["critical"][:5]:
        print(f"  - {source['platform']}: {source['source']}")
        print(f"    Techniques: {', '.join(source['techniques'])}")

    # Show sample Elastic query
    print("\nSample Elastic Query for Ransomware Detection:")
    ransomware_query = result["hunt_queries"]["T1486"]["elastic"]["query"]
    print(f"\n{ransomware_query[:300]}...\n")


def demo_cloud_compromise() -> None:
    """Demo: Cloud account compromise."""
    print_section("Scenario 3: AWS Account Compromise")

    print("Detected Techniques:")
    print("  - T1078 (Valid Accounts)")
    print("  - T1098 (Account Manipulation)")
    print("  - T1136.001 (Create Account)")
    print("\nEnvironment: AWS")
    print("SIEM Platforms: Athena, Sentinel\n")

    result_json = recommend_log_sources_json(
        technique_ids="T1078,T1098,T1136.001",
        environment="aws",
        siem_platforms="athena,sentinel",
    )

    result = json.loads(result_json)

    # Show AWS-specific sources
    print("AWS Log Sources:")
    if "aws" in result["log_sources"]:
        for source_name, source_info in result["log_sources"]["aws"].items():
            print(f"\n  {source_name}:")
            details = source_info["details"]
            if isinstance(details, dict):
                print(f"    Priority: {details.get('priority', 'N/A')}")
                print(f"    Description: {details.get('description', 'N/A')}")
                if "services" in details:
                    print(f"    Services: {', '.join(details['services'])}")
                if "events" in details:
                    print(f"    Events: {', '.join(details['events'][:3])}...")

    # Show sample Athena query
    print("\nSample Athena Query for Account Activity:")
    account_query = result["hunt_queries"]["T1078"]["athena"]["query"]
    print(f"\n{account_query[:300]}...\n")


def main() -> None:
    """Run all demo scenarios."""
    print("\n" + "=" * 80)
    print("  Log Source Recommendations Demo (v0.3 Preview)")
    print("  threat-research-mcp")
    print("=" * 80)

    try:
        demo_phishing_incident()
        demo_ransomware_attack()
        demo_cloud_compromise()

        print_section("Summary")
        print("This demo showed how the log source recommendation feature provides:")
        print("  1. Specific log sources (Windows Event IDs, CloudTrail events, etc.)")
        print("  2. Ready-to-run SIEM queries (Splunk, Sentinel, Elastic, Athena)")
        print("  3. Prioritized deployment checklists")
        print("  4. Environment-specific filtering (AWS, Azure, GCP, on-prem, hybrid)")
        print("\nFor full documentation, see: docs/log-source-recommendations.md\n")

    except Exception as e:
        print(f"\nError running demo: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
