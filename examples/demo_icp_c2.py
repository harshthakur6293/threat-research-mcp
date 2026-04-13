"""Demo: ICP-Based Decentralized C2 Analysis with Automatic Technique Detection."""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_ROOT / "src"))

from threat_research_mcp.extensions.mitre_attack_integration import (  # noqa: E402
    intel_to_log_sources,
)


def main() -> None:
    """Analyze ICP Canister C2 threat with automatic technique detection."""
    print("\n" + "=" * 80)
    print("  ICP-Based Decentralized C2 Analysis")
    print("  Automatic ATT&CK Technique Detection -> Log Sources -> SIEM Queries")
    print("=" * 80 + "\n")

    # Your threat intel
    intel = """
    ICP Canister ID: tdtqy-oyaaa-aaaae-af2dq-cai
    
    Decentralized C2 using Internet Computer Protocol for censorship-resistant 
    command and control. Threat actor leveraging Web3/blockchain infrastructure 
    to host malware C2. Avoids domain takedowns by using Canister ID instead of 
    traditional domains. Persistence through decentralized infrastructure.
    
    Detection requires blocking traffic to specific Canister ID or underlying ICP nodes.
    
    TTPs:
    - Censorship-resistant C2 via blockchain
    - Encrypted communication channels
    - Proxy-like behavior through decentralized nodes
    """

    print("Threat Intelligence:")
    print("-" * 80)
    print(intel.strip())
    print("-" * 80 + "\n")

    # Automatic analysis
    print("Running automatic analysis...\n")

    result = intel_to_log_sources(
        intel_text=intel,
        environment="hybrid",
        siem_platforms="splunk,sentinel,elastic,chronicle",
        auto_detect_techniques=True,
    )

    # Display results
    print("=" * 80)
    print("  ANALYSIS RESULTS")
    print("=" * 80 + "\n")

    print(f"[+] Auto-Detected Techniques: {len(result['detected_techniques'])}")
    for tid in result["detected_techniques"]:
        print(f"  - {tid}")

    print(f"\n[+] Total Techniques: {len(result['all_techniques'])}")
    print(f"[+] Environment: {result['environment']}")

    print("\n" + "=" * 80)
    print("  PRIORITY SUMMARY")
    print("=" * 80 + "\n")

    print(f"High Priority:     {len(result['priority_summary']['high'])} sources")
    print(f"Medium Priority:   {len(result['priority_summary']['medium'])} sources")

    print("\n" + "=" * 80)
    print("  TOP 5 DEPLOYMENT ACTIONS")
    print("=" * 80 + "\n")

    for i, item in enumerate(result["deployment_checklist"][:5], 1):
        print(f"{i}. [{item['priority'].upper()}] {item['platform']} - {item['source']}")
        print(f"   Action: {item['action']}")
        if "event_ids" in item:
            print(f"   Event IDs: {item['event_ids']}")
        print()

    print("=" * 80)
    print("  NETWORK DETECTION (Web Protocols - T1071.001)")
    print("=" * 80 + "\n")

    if "T1071.001" in result["hunt_queries"]:
        queries = result["hunt_queries"]["T1071.001"]

        if "splunk" in queries and queries["splunk"].get("ready_to_run"):
            print("Splunk Query:")
            print("-" * 80)
            print(queries["splunk"]["query"][:500] + "...")
            print()

        if "chronicle" in queries and queries["chronicle"].get("ready_to_run"):
            print("\nChronicle Query (YARA-L):")
            print("-" * 80)
            print(queries["chronicle"]["query"])
            print()

        if not any(q.get("ready_to_run") for q in queries.values() if isinstance(q, dict)):
            print("Note: Query templates not yet available for all SIEM platforms")
            print(
                "Available platforms:",
                [
                    k
                    for k in queries.keys()
                    if isinstance(queries[k], dict) and queries[k].get("ready_to_run")
                ],
            )
            print()

    print("\n" + "=" * 80)
    print("  PROXY DETECTION (T1090)")
    print("=" * 80 + "\n")

    if "T1090" in result["hunt_queries"]:
        # T1090 might not have queries yet, show log sources instead
        if "network" in result["log_sources"]:
            print("Network Log Sources:")
            for source_name, source_info in result["log_sources"]["network"].items():
                details = source_info.get("details", {})
                if isinstance(details, dict):
                    print(f"\n{source_name}:")
                    print(f"  Priority: {details.get('priority', 'N/A')}")
                    print(f"  Description: {details.get('description', 'N/A')}")

    print("\n" + "=" * 80)
    print("  CUSTOM DETECTION RECOMMENDATIONS")
    print("=" * 80 + "\n")

    print("For ICP Canister C2 specifically:")
    print()
    print("1. Network Detection:")
    print("   - Monitor DNS queries to *.ic0.app, *.raw.ic0.app")
    print("   - Block/alert on Canister ID: tdtqy-oyaaa-aaaae-af2dq-cai")
    print("   - Monitor HTTPS traffic to ICP boundary nodes")
    print()
    print("2. Endpoint Detection:")
    print("   - Process command lines containing 'ic0.app' or Canister IDs")
    print("   - Unusual processes making HTTPS connections to blockchain domains")
    print()
    print("3. Firewall Rules:")
    print("   - Create deny rules for known malicious Canister IDs")
    print("   - Monitor/restrict access to ICP boundary nodes if not business-required")
    print()
    print("4. Proxy/Web Gateway:")
    print("   - URL filtering for *.ic0.app with Canister ID patterns")
    print("   - SSL inspection for ICP traffic (if policy allows)")
    print()

    print("=" * 80)
    print("  SUMMARY")
    print("=" * 80 + "\n")

    print("This automated analysis:")
    print(f"  [+] Detected {len(result['detected_techniques'])} ATT&CK techniques from intel")
    print(f"  [+] Identified {len(result['deployment_checklist'])} log sources to deploy")
    print(f"  [+] Generated queries for {len(result['hunt_queries'])} techniques")
    print(
        f"  [+] Provided {len([x for x in result['deployment_checklist'] if x['priority'] == 'high'])} high-priority actions"
    )
    print()
    print("Next steps:")
    print("  1. Review and deploy high-priority log sources")
    print("  2. Customize SIEM queries for your environment")
    print("  3. Add ICP-specific detection rules (Canister ID, ic0.app domains)")
    print("  4. Test queries against sample data")
    print()


if __name__ == "__main__":
    main()
