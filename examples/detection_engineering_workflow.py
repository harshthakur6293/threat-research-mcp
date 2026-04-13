"""Example: Using threat actor profiles in detection engineering workflows.

This example demonstrates how to integrate threat actor profiles into your
detection engineering process to build targeted detections for specific actors.
"""

import sys
from pathlib import Path

# Add src to path for local development
_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_ROOT / "src"))
sys.path.insert(0, str(_ROOT / "tests"))

from threat_research_mcp.detection.query_generator import (  # noqa: E402
    generate_hunt_queries,
)
from threat_actor_profiles import (  # noqa: E402
    get_threat_actor_profile,
)


def workflow_1_actor_specific_detections():
    """Workflow 1: Build detections for a specific threat actor."""
    print("=" * 80)
    print("WORKFLOW 1: Actor-Specific Detection Engineering")
    print("=" * 80)
    print("\nScenario: Your organization is targeted by APT29 (Cozy Bear)")
    print("Goal: Build comprehensive detections for APT29 TTPs\n")

    # Step 1: Load threat actor profile
    print("[Step 1] Load APT29 Profile")
    print("-" * 80)
    profile = get_threat_actor_profile("APT29")
    print(f"Actor: {profile['aliases'][0]}")
    print(f"Attribution: {profile['attribution']}")
    print(f"Known Tools: {', '.join(profile['tools'][:5])}")

    # Step 2: Extract all techniques from profile
    print("\n[Step 2] Extract ATT&CK Techniques")
    print("-" * 80)
    all_techniques = []
    for tactic, techniques in profile["ttps"].items():
        all_techniques.extend(techniques)

    print(f"Total techniques: {len(all_techniques)}")
    print(f"Tactics covered: {len(profile['ttps'])}")
    print(f"Sample techniques: {', '.join(all_techniques[:5])}")

    # Step 3: Prioritize high-value techniques
    print("\n[Step 3] Prioritize High-Value Techniques")
    print("-" * 80)
    # Focus on initial access, execution, and persistence
    priority_techniques = (
        profile["ttps"].get("initial_access", [])
        + profile["ttps"].get("execution", [])
        + profile["ttps"].get("persistence", [])
    )
    print(f"Priority techniques: {len(priority_techniques)}")
    print(f"Techniques: {', '.join(priority_techniques[:10])}")

    # Step 4: Generate log sources for priority techniques
    print("\n[Step 4] Generate Log Source Requirements")
    print("-" * 80)
    from threat_research_mcp.detection.log_source_mapper import get_log_sources_for_techniques

    log_guidance = get_log_sources_for_techniques(
        priority_techniques[:15],  # Limit to first 15 for demo
        environment="hybrid",
    )

    # Count log sources
    log_sources_count = 0
    if "log_sources" in log_guidance:
        for platform, sources in log_guidance["log_sources"].items():
            if isinstance(sources, dict):
                log_sources_count += len(sources)

    print(f"Log sources required: {log_sources_count}")
    print("\nSample log sources:")
    count = 0
    for platform, sources in log_guidance["log_sources"].items():
        if isinstance(sources, dict):
            for source_name in list(sources.keys())[:2]:
                print(f"  - {platform.upper()}: {source_name}")
                count += 1
                if count >= 5:
                    break
        if count >= 5:
            break

    # Step 5: Generate SIEM queries
    print("\n[Step 5] Generate SIEM Detection Queries")
    print("-" * 80)
    hunt_queries = generate_hunt_queries(
        priority_techniques[:5],  # First 5 for demo
        siem_platforms=["splunk", "sentinel"],
    )

    for platform, queries in hunt_queries.items():
        if isinstance(queries, dict) and queries.get("ready_to_run"):
            print(f"\n{platform.upper()} Query:")
            print(f"{queries['ready_to_run'][:300]}...")
            break

    # Step 6: Create detection deployment plan
    print("\n[Step 6] Detection Deployment Plan")
    print("-" * 80)
    print(f"1. Deploy log collection for {log_sources_count} sources")
    print(f"2. Implement {len(priority_techniques)} detection rules")
    print("3. Test against APT29 sample intelligence")
    print("4. Tune detections to reduce false positives")
    print("5. Document coverage in ATT&CK Navigator")

    print("\n[Result] APT29 Detection Package Ready")
    print(f"  - {len(priority_techniques)} techniques covered")
    print(f"  - {log_sources_count} log sources configured")
    print(f"  - {len(hunt_queries)} SIEM platforms supported")


def workflow_2_multi_actor_coverage():
    """Workflow 2: Build detections covering multiple threat actors."""
    print("\n\n" + "=" * 80)
    print("WORKFLOW 2: Multi-Actor Detection Coverage")
    print("=" * 80)
    print("\nScenario: Build detections covering Russian APT groups")
    print("Goal: Maximize coverage across APT28, APT29, and UNC2452\n")

    # Step 1: Load multiple actor profiles
    print("[Step 1] Load Russian Actor Profiles")
    print("-" * 80)
    russian_actors = ["APT28", "APT29", "UNC2452"]
    profiles = {actor: get_threat_actor_profile(actor) for actor in russian_actors}

    for actor, profile in profiles.items():
        print(f"  - {actor}: {profile['aliases'][0]}")

    # Step 2: Find common techniques
    print("\n[Step 2] Identify Common Techniques")
    print("-" * 80)

    # Collect all techniques from each actor
    actor_techniques = {}
    for actor, profile in profiles.items():
        techniques = []
        for tactic, techs in profile["ttps"].items():
            techniques.extend(techs)
        actor_techniques[actor] = set(techniques)

    # Find common techniques (used by 2+ actors)
    common_techniques = set()
    for actor1, techs1 in actor_techniques.items():
        for actor2, techs2 in actor_techniques.items():
            if actor1 < actor2:  # Avoid duplicates
                common = techs1 & techs2
                common_techniques.update(common)

    print(f"Common techniques: {len(common_techniques)}")
    print(f"Sample: {', '.join(list(common_techniques)[:10])}")

    # Step 3: Prioritize by actor count
    print("\n[Step 3] Prioritize by Coverage")
    print("-" * 80)

    technique_coverage = {}
    for tech in common_techniques:
        actors_using = [actor for actor, techs in actor_techniques.items() if tech in techs]
        technique_coverage[tech] = actors_using

    # Sort by number of actors using the technique
    sorted_techniques = sorted(technique_coverage.items(), key=lambda x: len(x[1]), reverse=True)

    print("Top techniques by actor coverage:")
    for tech, actors in sorted_techniques[:10]:
        print(f"  - {tech}: Used by {', '.join(actors)}")

    # Step 4: Generate unified detection strategy
    print("\n[Step 4] Unified Detection Strategy")
    print("-" * 80)

    high_priority = [tech for tech, actors in sorted_techniques if len(actors) >= 2][:15]

    from threat_research_mcp.detection.log_source_mapper import get_log_sources_for_techniques

    log_guidance = get_log_sources_for_techniques(high_priority, environment="hybrid")

    log_sources_count = sum(
        len(sources)
        for sources in log_guidance["log_sources"].values()
        if isinstance(sources, dict)
    )

    print("Strategy:")
    print(f"  - Focus on {len(high_priority)} high-priority techniques")
    print(f"  - Deploy {log_sources_count} log sources")
    print(f"  - Covers {len(russian_actors)} Russian APT groups")
    print(
        f"  - Efficiency: {len(high_priority)} detections cover {len(common_techniques)} total techniques"
    )


def workflow_3_ioc_based_detections():
    """Workflow 3: Build IOC-based detections from actor profiles."""
    print("\n\n" + "=" * 80)
    print("WORKFLOW 3: IOC-Based Detection Engineering")
    print("=" * 80)
    print("\nScenario: Deploy IOC-based detections for Lazarus Group")
    print("Goal: Block known infrastructure and malware hashes\n")

    # Step 1: Extract IOCs from profile
    print("[Step 1] Extract IOCs from Profile")
    print("-" * 80)
    profile = get_threat_actor_profile("Lazarus Group")

    iocs = profile["iocs"]
    print(f"Domains: {len(iocs.get('domains', []))}")
    for domain in iocs.get("domains", [])[:3]:
        print(f"  - {domain}")

    print(f"\nIPs: {len(iocs.get('ips', []))}")
    for ip in iocs.get("ips", [])[:3]:
        print(f"  - {ip}")

    print(f"\nHashes: {len(iocs.get('hashes', []))}")
    for hash_val in iocs.get("hashes", [])[:1]:
        print(f"  - {hash_val[:32]}...")

    # Step 2: Generate firewall rules
    print("\n[Step 2] Generate Firewall Rules")
    print("-" * 80)
    print("# Lazarus Group - Block known C2 infrastructure")
    for ip in iocs.get("ips", []):
        print(f"deny ip any any {ip} any")

    # Step 3: Generate DNS blocklist
    print("\n[Step 3] Generate DNS Blocklist")
    print("-" * 80)
    print("# Lazarus Group - DNS sinkhole configuration")
    for domain in iocs.get("domains", []):
        print(f'zone "{domain}" {{ type master; file "/etc/bind/db.sinkhole"; }};')

    # Step 4: Generate EDR hash blocks
    print("\n[Step 4] Generate EDR Hash Blocks")
    print("-" * 80)
    print("# Lazarus Group - Block known malware hashes")
    print("# Format: SHA256,Description")
    for hash_val in iocs.get("hashes", []):
        print(f"{hash_val},Lazarus Group malware")

    # Step 5: Generate SIEM correlation rule
    print("\n[Step 5] Generate SIEM Correlation Rule")
    print("-" * 80)
    print("# Splunk correlation search for Lazarus Group IOCs")
    print(
        """
index=* (
    dest_ip IN ("185.220.101.45", "23.227.196.215", "91.109.17.6")
    OR query IN ("nzssdm.com", "codevexillium.org", "bizonepartners.com")
    OR file_hash IN ("b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2")
)
| stats count by src_ip, dest_ip, query, file_hash, user
| where count > 0
| eval threat_actor="Lazarus Group"
| eval severity="critical"
    """.strip()
    )


def workflow_4_threat_hunting():
    """Workflow 4: Use profiles for proactive threat hunting."""
    print("\n\n" + "=" * 80)
    print("WORKFLOW 4: Proactive Threat Hunting")
    print("=" * 80)
    print("\nScenario: Hunt for APT41 activity in your environment")
    print("Goal: Identify potential APT41 compromise indicators\n")

    # Step 1: Load APT41 profile
    print("[Step 1] Load APT41 Hunt Profile")
    print("-" * 80)
    profile = get_threat_actor_profile("APT41")
    print(f"Actor: {profile['aliases'][0]}")
    print(f"Motivation: {profile['motivation']}")
    print(f"Known Tools: {', '.join(profile['tools'][:5])}")

    # Step 2: Build hunt hypotheses
    print("\n[Step 2] Build Hunt Hypotheses")
    print("-" * 80)

    hypotheses = [
        {
            "hypothesis": "APT41 exploited public-facing web applications",
            "techniques": profile["ttps"]["initial_access"],
            "data_sources": ["Web server logs", "WAF logs", "IDS/IPS alerts"],
            "hunt_query": "Look for exploitation attempts against known CVEs (Citrix, Exchange, etc.)",
        },
        {
            "hypothesis": "APT41 deployed web shells for persistence",
            "techniques": profile["ttps"]["persistence"],
            "data_sources": ["File system monitoring", "Web server logs"],
            "hunt_query": "Search for suspicious .aspx, .jsp, .php files in web directories",
        },
        {
            "hypothesis": "APT41 used Cobalt Strike for C2",
            "techniques": profile["ttps"]["command_and_control"],
            "data_sources": ["Network traffic", "Proxy logs", "DNS logs"],
            "hunt_query": "Identify beaconing behavior and known Cobalt Strike indicators",
        },
    ]

    for i, hyp in enumerate(hypotheses, 1):
        print(f"\nHypothesis {i}: {hyp['hypothesis']}")
        print(f"  Techniques: {', '.join(hyp['techniques'][:3])}")
        print(f"  Data Sources: {', '.join(hyp['data_sources'])}")
        print(f"  Hunt: {hyp['hunt_query']}")

    # Step 3: Generate hunt queries
    print("\n[Step 3] Generate Hunt Queries")
    print("-" * 80)

    # Focus on initial access techniques
    initial_access = profile["ttps"]["initial_access"][:3]

    hunt_queries = generate_hunt_queries(initial_access, siem_platforms=["splunk"])

    if "splunk" in hunt_queries:
        print("\nSplunk Hunt Query:")
        print(hunt_queries["splunk"].get("ready_to_run", "")[:400])

    # Step 4: Hunt execution plan
    print("\n[Step 4] Hunt Execution Plan")
    print("-" * 80)
    print("Week 1: Initial Access Hunt")
    print("  - Review web application logs for exploitation attempts")
    print("  - Check for CVE-2019-19781 (Citrix) exploitation indicators")
    print("  - Analyze authentication logs for suspicious patterns")
    print("\nWeek 2: Persistence Hunt")
    print("  - Scan web directories for web shells")
    print("  - Review scheduled tasks and services")
    print("  - Check for DLL side-loading indicators")
    print("\nWeek 3: C2 Hunt")
    print("  - Analyze network traffic for beaconing")
    print("  - Review DNS queries for suspicious domains")
    print("  - Check proxy logs for known APT41 infrastructure")


def main():
    """Run all detection engineering workflows."""
    print("\n" + "=" * 80)
    print("THREAT ACTOR PROFILES IN DETECTION ENGINEERING")
    print("Practical Examples and Workflows")
    print("=" * 80)

    # Run all workflows
    workflow_1_actor_specific_detections()
    workflow_2_multi_actor_coverage()
    workflow_3_ioc_based_detections()
    workflow_4_threat_hunting()

    # Summary
    print("\n\n" + "=" * 80)
    print("SUMMARY: Detection Engineering with Threat Actor Profiles")
    print("=" * 80)
    print("\nKey Takeaways:")
    print("1. Use profiles to build targeted detections for specific actors")
    print("2. Find common techniques across multiple actors for efficiency")
    print("3. Deploy IOC-based detections (firewall, DNS, EDR) from profile data")
    print("4. Build hunt hypotheses based on actor TTPs and tools")
    print("\nNext Steps:")
    print("1. Choose a threat actor relevant to your organization")
    print("2. Extract techniques and IOCs from the profile")
    print("3. Generate log sources and SIEM queries")
    print("4. Deploy detections and validate against sample intelligence")
    print("5. Document coverage in ATT&CK Navigator")


if __name__ == "__main__":
    main()
