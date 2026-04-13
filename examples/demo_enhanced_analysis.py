"""Demo: Enhanced analysis with optional MCP integrations.

This example shows how threat-research-mcp orchestrates multiple MCPs
when they are available, and gracefully degrades when they're not.
"""

import json
import sys
from pathlib import Path

# Add src to path for local development
_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_ROOT / "src"))

from threat_research_mcp.tools.enhanced_analysis import (  # noqa: E402
    enhanced_intel_analysis,
    get_integration_status,
)


def main():
    """Run enhanced analysis demo."""
    print("=" * 80)
    print("Enhanced Threat Intelligence Analysis Demo")
    print("=" * 80)
    print()

    # Step 1: Check integration status
    print("Step 1: Checking Optional MCP Integrations")
    print("-" * 80)
    status = json.loads(get_integration_status())
    print(json.dumps(status, indent=2))
    print()

    available_count = status["summary"]["available_count"]
    if available_count == 0:
        print("[!] No optional MCPs detected. Running in standalone mode.")
        print("[i] To enable integrations, see: docs/OPTIONAL-INTEGRATIONS.md")
    else:
        print(f"[+] {available_count} optional MCP(s) available!")

    print()

    # Step 2: Run enhanced analysis
    print("Step 2: Enhanced Analysis of ICP Canister C2")
    print("-" * 80)

    intel_text = """
    APT29 (Cozy Bear) has been observed using a novel C2 framework called
    "ICP Canister" that leverages Internet Computer Protocol (ICP) blockchain
    for command and control communications.

    The malware uses PowerShell to establish initial access via spearphishing
    emails with malicious attachments. Once executed, it beacons to canister
    smart contracts deployed on the ICP blockchain at regular intervals.

    IOCs:
    - IP: 185.220.101.45 (C2 server)
    - Domain: icp-node.example.com
    - Hash: a1b2c3d4e5f6...

    The malware uses WMI for lateral movement and creates scheduled tasks
    for persistence. Network traffic shows HTTPS connections to ICP nodes
    with encrypted payloads.
    """

    result = json.loads(
        enhanced_intel_analysis(
            intel_text=intel_text,
            environment="hybrid",
            siem_platforms="splunk,sentinel,elastic",
            enrich_iocs=True,
            check_coverage=True,
            generate_behavioral_hunts=True,
        )
    )

    # Display core analysis
    print("\n[Core Analysis - Always Available]")
    print(f"Detected Techniques: {result['core_analysis'].get('detected_techniques', [])}")
    print(f"Log Sources: {len(result['core_analysis'].get('log_sources', []))} sources")
    print(f"Hunt Queries: {len(result['core_analysis'].get('hunt_queries', {}))} SIEM platforms")

    # Display enhanced features
    print("\n[Enhanced Features - Optional MCPs]")
    for feature_name, feature_data in result.get("enhanced_features", {}).items():
        if feature_data.get("enabled"):
            print(f"\n{feature_name.replace('_', ' ').title()}: ENABLED")
            if "enriched_iocs" in feature_data:
                print(f"  - Enriched {feature_data['total_enriched']} IOCs")
            elif "coverage_data" in feature_data:
                print(f"  - {feature_data['summary']}")
            elif "hunts" in feature_data:
                print(f"  - {feature_data['summary']}")
        else:
            print(f"\n{feature_name.replace('_', ' ').title()}: NOT AVAILABLE")
            print(f"  - {feature_data.get('message', 'Not configured')}")

    print()
    print("=" * 80)
    print("Demo Complete!")
    print()
    print("Next Steps:")
    print("1. Install optional MCPs to unlock enhanced features")
    print("2. See docs/OPTIONAL-INTEGRATIONS.md for setup instructions")
    print("3. Run this demo again to see the difference!")
    print("=" * 80)


if __name__ == "__main__":
    main()
