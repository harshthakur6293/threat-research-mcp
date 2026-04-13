"""Demo: Test threat-research-mcp against realistic threat actor scenarios.

This script demonstrates comprehensive testing of the MCP tools against
threat intelligence from various APT groups and UNC groups.
"""

import json
import sys
from pathlib import Path
from typing import Dict, List

# Add src to path for local development
_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_ROOT / "src"))
sys.path.insert(0, str(_ROOT / "tests"))

from threat_research_mcp.tools.extract_iocs import extract_iocs_json  # noqa: E402
from threat_research_mcp.extensions.mitre_attack_integration import (  # noqa: E402
    extract_techniques_from_intel,
    intel_to_log_sources,
)
from threat_actor_profiles import (  # noqa: E402
    get_threat_actor_profile,
    list_threat_actors,
)


def analyze_threat_actor(actor_name: str) -> Dict:
    """Analyze threat intelligence for a specific threat actor."""
    print(f"\n{'=' * 80}")
    print(f"Analyzing: {actor_name}")
    print(f"{'=' * 80}")

    profile = get_threat_actor_profile(actor_name)
    intel = profile["sample_intel"]

    # Display actor info
    print(f"\nAliases: {', '.join(profile['aliases'])}")
    print(f"Attribution: {profile['attribution']}")
    print(f"Motivation: {profile['motivation']}")
    print(f"Sophistication: {profile['sophistication']}")
    print(f"Known Tools: {', '.join(profile['tools'][:5])}...")

    # Step 1: Extract IOCs
    print("\n[Step 1: IOC Extraction]")
    print("-" * 80)
    iocs_result = json.loads(extract_iocs_json(intel))
    print("Extracted IOCs:")
    print(
        f"  - Domains: {len(iocs_result['domains'])} ({', '.join(iocs_result['domains'][:3])}...)"
    )
    print(f"  - IPs: {len(iocs_result['ips'])} ({', '.join(iocs_result['ips'][:3])}...)")
    print(f"  - Hashes: {len(iocs_result['hashes'])}")

    # Validate against known IOCs
    known_domains = profile["iocs"].get("domains", [])
    known_ips = profile["iocs"].get("ips", [])

    extracted_domains = set(iocs_result["domains"])
    extracted_ips = set(iocs_result["ips"])

    domain_matches = [d for d in known_domains if d in extracted_domains]
    ip_matches = [ip for ip in known_ips if ip in extracted_ips]

    print("\nValidation:")
    print(f"  - Matched {len(domain_matches)}/{len(known_domains)} known domains")
    print(f"  - Matched {len(ip_matches)}/{len(known_ips)} known IPs")

    # Step 2: Detect ATT&CK Techniques
    print("\n[Step 2: ATT&CK Technique Detection]")
    print("-" * 80)
    detected_techniques = extract_techniques_from_intel(intel)
    print(f"Auto-detected {len(detected_techniques)} techniques:")
    print(f"  {', '.join(detected_techniques[:10])}...")

    # Validate against known TTPs
    all_known_techniques = []
    for tactic, techniques in profile["ttps"].items():
        all_known_techniques.extend(techniques)

    matched_techniques = [t for t in detected_techniques if t in all_known_techniques]
    print("\nValidation:")
    print(f"  - Matched {len(matched_techniques)}/{len(all_known_techniques)} known techniques")
    print(f"  - Coverage: {len(matched_techniques) / len(all_known_techniques) * 100:.1f}%")

    # Step 3: Generate Log Sources and Queries
    print("\n[Step 3: Log Source Recommendations]")
    print("-" * 80)
    log_guidance = intel_to_log_sources(
        intel_text=intel,
        environment="hybrid",
        siem_platforms="splunk,sentinel,elastic",
        manual_techniques="",
    )

    # intel_to_log_sources returns a JSON string
    if isinstance(log_guidance, str):
        log_data = json.loads(log_guidance)
    else:
        log_data = log_guidance
    print(f"Generated recommendations for {len(detected_techniques)} techniques")

    # Count log sources (nested dict structure)
    log_sources_count = 0
    if "log_sources" in log_data and isinstance(log_data["log_sources"], dict):
        for platform, sources in log_data["log_sources"].items():
            if isinstance(sources, dict):
                log_sources_count += len(sources)

    print(f"  - Log sources: {log_sources_count} unique sources")
    print(f"  - SIEM queries: {len(log_data.get('hunt_queries', {}))} platforms")

    # Display sample log sources
    if "log_sources" in log_data and isinstance(log_data["log_sources"], dict):
        print("\nSample log sources:")
        count = 0
        for platform, sources in log_data["log_sources"].items():
            if isinstance(sources, dict):
                for source_name in list(sources.keys())[:2]:
                    print(f"  - {platform}: {source_name}")
                    count += 1
                    if count >= 3:
                        break
            if count >= 3:
                break

    # Display sample queries
    if log_data.get("hunt_queries"):
        for platform, queries in list(log_data["hunt_queries"].items())[:1]:
            print(f"\nSample {platform.upper()} query:")
            if isinstance(queries, dict) and queries.get("ready_to_run"):
                print(f"  {queries['ready_to_run'][:150]}...")

    # Step 4: Generate Detection Summary
    print("\n[Step 4: Detection Summary]")
    print("-" * 80)

    # Tactic coverage
    tactics_covered = set()
    for technique in detected_techniques:
        for tactic, techniques in profile["ttps"].items():
            if technique in techniques:
                tactics_covered.add(tactic)

    print(f"Tactic Coverage: {len(tactics_covered)}/{len(profile['ttps'])} tactics")
    print(f"  Covered: {', '.join(list(tactics_covered)[:5])}...")

    # Return analysis results
    return {
        "actor_name": actor_name,
        "iocs_extracted": len(iocs_result["domains"])
        + len(iocs_result["ips"])
        + len(iocs_result["hashes"]),
        "iocs_matched": len(domain_matches) + len(ip_matches),
        "techniques_detected": len(detected_techniques),
        "techniques_matched": len(matched_techniques),
        "technique_coverage": len(matched_techniques) / len(all_known_techniques) * 100
        if all_known_techniques
        else 0,
        "tactics_covered": len(tactics_covered),
        "log_sources_generated": len(log_data.get("log_sources", [])),
        "siem_queries_generated": len(log_data.get("hunt_queries", {})),
    }


def generate_comparison_report(results: List[Dict]) -> None:
    """Generate comparison report across all threat actors."""
    print(f"\n{'=' * 80}")
    print("THREAT ACTOR COMPARISON REPORT")
    print(f"{'=' * 80}\n")

    # Summary table
    print(
        f"{'Actor':<20} {'IOCs':>8} {'Techniques':>12} {'Coverage':>10} {'Tactics':>8} {'Queries':>8}"
    )
    print("-" * 80)

    for result in results:
        print(
            f"{result['actor_name']:<20} "
            f"{result['iocs_matched']:>3}/{result['iocs_extracted']:<3} "
            f"{result['techniques_matched']:>3}/{result['techniques_detected']:<7} "
            f"{result['technique_coverage']:>6.1f}%   "
            f"{result['tactics_covered']:>8} "
            f"{result['siem_queries_generated']:>8}"
        )

    # Calculate averages
    avg_coverage = sum(r["technique_coverage"] for r in results) / len(results)
    avg_iocs = sum(r["iocs_matched"] for r in results) / len(results)
    avg_techniques = sum(r["techniques_matched"] for r in results) / len(results)

    print("-" * 80)
    print(f"{'AVERAGE':<20} {avg_iocs:>7.1f} {avg_techniques:>11.1f} {avg_coverage:>9.1f}%")

    # Key findings
    print(f"\n{'=' * 80}")
    print("KEY FINDINGS")
    print(f"{'=' * 80}\n")

    best_coverage = max(results, key=lambda r: r["technique_coverage"])
    most_techniques = max(results, key=lambda r: r["techniques_detected"])
    most_iocs = max(results, key=lambda r: r["iocs_extracted"])

    print(
        f"[+] Best Technique Coverage: {best_coverage['actor_name']} ({best_coverage['technique_coverage']:.1f}%)"
    )
    print(
        f"[+] Most Techniques Detected: {most_techniques['actor_name']} ({most_techniques['techniques_detected']} techniques)"
    )
    print(
        f"[+] Most IOCs Extracted: {most_iocs['actor_name']} ({most_iocs['iocs_extracted']} IOCs)"
    )

    print(f"\n[i] Average technique detection coverage: {avg_coverage:.1f}%")
    print(f"[i] Total threat actors analyzed: {len(results)}")
    print("[i] All actors successfully processed with log source recommendations")


def main():
    """Run comprehensive threat actor testing."""
    print("=" * 80)
    print("THREAT ACTOR SCENARIO TESTING")
    print("Testing threat-research-mcp against realistic APT/UNC group intelligence")
    print("=" * 80)

    actors = list_threat_actors()
    print(f"\nTesting against {len(actors)} threat actors:")
    for i, actor in enumerate(actors, 1):
        print(f"  {i}. {actor}")

    print("\nStarting analysis...")

    results = []
    for actor in actors:
        try:
            result = analyze_threat_actor(actor)
            results.append(result)
        except Exception as e:
            print(f"\n[!] Error analyzing {actor}: {e}")
            continue

    # Generate comparison report
    if results:
        generate_comparison_report(results)

    print(f"\n{'=' * 80}")
    print("TESTING COMPLETE")
    print(f"{'=' * 80}\n")

    print("Next Steps:")
    print("1. Run pytest tests: pytest tests/test_threat_actor_scenarios.py -v")
    print("2. Review generated log sources and queries for each actor")
    print("3. Validate detections against your SIEM environment")
    print("4. Add custom threat actor profiles to tests/threat_actor_profiles.py")


if __name__ == "__main__":
    main()
