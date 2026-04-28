"""Threat actor profiles for testing.

This module contains realistic threat actor profiles based on public reporting
for APT groups and UNC (Uncategorized) groups tracked by threat intelligence firms.
"""

from typing import Dict, List, Any

# Threat Actor Profiles
THREAT_ACTOR_PROFILES: Dict[str, Dict[str, Any]] = {
    "APT29": {
        "aliases": ["Cozy Bear", "The Dukes", "YTTRIUM", "UNC2452"],
        "attribution": "Russian Foreign Intelligence Service (SVR)",
        "first_seen": "2008",
        "targets": ["Government", "Think Tanks", "Healthcare", "Energy"],
        "geography": ["United States", "Europe", "Global"],
        "motivation": "Espionage",
        "sophistication": "Advanced",
        "ttps": {
            "initial_access": ["T1566.001", "T1566.002", "T1199"],  # Spearphishing, Supply Chain
            "execution": [
                "T1059.001",
                "T1059.003",
                "T1203",
            ],  # PowerShell, Windows Command Shell, Exploitation
            "persistence": [
                "T1547.001",
                "T1053.005",
                "T1136.002",
            ],  # Registry Run Keys, Scheduled Task, Domain Account
            "privilege_escalation": ["T1068", "T1134.001"],  # Exploitation, Token Impersonation
            "defense_evasion": [
                "T1027",
                "T1070.004",
                "T1140",
            ],  # Obfuscation, File Deletion, Deobfuscate
            "credential_access": ["T1003.001", "T1558.003"],  # LSASS Memory, Kerberoasting
            "discovery": [
                "T1087.002",
                "T1069.002",
                "T1482",
            ],  # Domain Account Discovery, Domain Groups, Domain Trust
            "lateral_movement": ["T1021.001", "T1021.002", "T1550.002"],  # RDP, SMB, Pass the Hash
            "collection": ["T1114.002", "T1005"],  # Remote Email Collection, Data from Local System
            "command_and_control": [
                "T1071.001",
                "T1573.002",
                "T1090.002",
            ],  # Web Protocols, Asymmetric Crypto, External Proxy
            "exfiltration": ["T1041", "T1567.002"],  # C2 Channel, Exfiltration to Cloud Storage
        },
        "tools": ["SUNBURST", "TEARDROP", "Cobalt Strike", "Mimikatz", "BloodHound"],
        "iocs": {
            "domains": ["avsvmcloud.com", "digitalcollege.org", "freescanonline.com"],
            "ips": ["13.59.205.66", "54.193.127.66", "18.217.225.111"],
            "hashes": ["32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77"],
        },
        "sample_intel": """
        APT29 (Cozy Bear) conducted a sophisticated supply chain attack targeting SolarWinds Orion platform.
        The threat actor compromised the build environment and inserted the SUNBURST backdoor into legitimate
        software updates. Once deployed, SUNBURST established C2 communications via DNS and HTTPS to
        avsvmcloud.com. The malware remained dormant for weeks before activating, using DGA algorithms
        to evade detection. APT29 leveraged compromised credentials to move laterally via RDP and WMI,
        deployed Cobalt Strike beacons, and exfiltrated sensitive data to cloud storage. The campaign
        demonstrated advanced tradecraft including token impersonation, Kerberoasting, and living-off-the-land
        techniques using PowerShell and legitimate Windows utilities.

        IOCs:
        - Domain: avsvmcloud.com
        - IP: 13.59.205.66
        - Hash: 32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77
        """,
    },
    "APT28": {
        "aliases": ["Fancy Bear", "Sofacy", "Pawn Storm", "Sednit", "STRONTIUM"],
        "attribution": "Russian Military Intelligence (GRU)",
        "first_seen": "2007",
        "targets": ["Government", "Military", "Media", "Critical Infrastructure"],
        "geography": ["United States", "Europe", "Ukraine", "Georgia"],
        "motivation": "Espionage, Disruption",
        "sophistication": "Advanced",
        "ttps": {
            "initial_access": [
                "T1566.001",
                "T1190",
                "T1133",
            ],  # Spearphishing, Exploit Public-Facing
            "execution": ["T1059.001", "T1059.005", "T1203"],  # PowerShell, VBScript, Exploitation
            "persistence": [
                "T1547.001",
                "T1053.005",
                "T1078",
            ],  # Registry, Scheduled Task, Valid Accounts
            "privilege_escalation": ["T1068", "T1055"],  # Exploitation, Process Injection
            "defense_evasion": [
                "T1027",
                "T1070.004",
                "T1112",
            ],  # Obfuscation, File Deletion, Modify Registry
            "credential_access": ["T1003.001", "T1056.001"],  # LSASS, Keylogging
            "discovery": [
                "T1083",
                "T1057",
                "T1082",
            ],  # File Discovery, Process Discovery, System Info
            "lateral_movement": ["T1021.001", "T1021.002"],  # RDP, SMB
            "collection": ["T1113", "T1005"],  # Screen Capture, Data from Local System
            "command_and_control": ["T1071.001", "T1105"],  # Web Protocols, Ingress Tool Transfer
            "exfiltration": ["T1041", "T1048.003"],  # C2 Channel, Exfil Over Alternative Protocol
        },
        "tools": ["X-Agent", "Sofacy", "Zebrocy", "Cannon", "Mimikatz"],
        "iocs": {
            "domains": ["netmediaresources.com", "cdn-edge-akamai.com", "mail-newyork.com"],
            "ips": ["185.86.148.222", "185.25.51.198", "89.34.111.11"],
            "hashes": ["e81a8f8ad804c4d83869d7806a303ff04f31cce376c5df8aada2e9db2c1eeb98"],
        },
        "sample_intel": """
        APT28 (Fancy Bear) launched a spearphishing campaign targeting government officials with
        weaponized Office documents exploiting CVE-2017-0262. The malicious documents delivered
        X-Agent malware which established persistence via registry run keys. The threat actor used
        PowerShell scripts to download additional payloads from netmediaresources.com. APT28 deployed
        keyloggers to capture credentials and used Mimikatz to dump LSASS memory. Lateral movement
        occurred via RDP using compromised credentials. The group exfiltrated documents and emails
        to C2 infrastructure at 185.86.148.222.

        IOCs:
        - Domain: netmediaresources.com
        - IP: 185.86.148.222
        - Hash: e81a8f8ad804c4d83869d7806a303ff04f31cce376c5df8aada2e9db2c1eeb98
        """,
    },
    "APT41": {
        "aliases": ["Winnti", "Barium", "Wicked Panda", "Double Dragon"],
        "attribution": "Chinese State-Sponsored + Financially Motivated",
        "first_seen": "2012",
        "targets": ["Healthcare", "Telecom", "Gaming", "Technology", "Government"],
        "geography": ["United States", "Asia", "Europe", "Global"],
        "motivation": "Espionage, Financial Gain",
        "sophistication": "Advanced",
        "ttps": {
            "initial_access": [
                "T1190",
                "T1195.002",
                "T1566.001",
            ],  # Exploit Public-Facing, Supply Chain, Spearphishing
            "execution": [
                "T1059.001",
                "T1059.003",
                "T1106",
            ],  # PowerShell, Windows Command Shell, Native API
            "persistence": [
                "T1543.003",
                "T1574.002",
                "T1053.005",
            ],  # Windows Service, DLL Side-Loading, Scheduled Task
            "privilege_escalation": ["T1068", "T1055"],  # Exploitation, Process Injection
            "defense_evasion": [
                "T1027",
                "T1070.004",
                "T1562.001",
            ],  # Obfuscation, File Deletion, Disable Tools
            "credential_access": ["T1003.001", "T1555.003"],  # LSASS, Credentials from Web Browsers
            "discovery": [
                "T1083",
                "T1057",
                "T1018",
            ],  # File Discovery, Process Discovery, Remote System Discovery
            "lateral_movement": [
                "T1021.001",
                "T1021.002",
                "T1570",
            ],  # RDP, SMB, Lateral Tool Transfer
            "collection": ["T1005", "T1114.001"],  # Data from Local System, Email Collection
            "command_and_control": [
                "T1071.001",
                "T1573.001",
                "T1090.001",
            ],  # Web Protocols, Symmetric Crypto, Internal Proxy
            "exfiltration": ["T1041", "T1020"],  # C2 Channel, Automated Exfiltration
        },
        "tools": ["Cobalt Strike", "Winnti", "MESSAGETAP", "HIGHNOON", "Mimikatz"],
        "iocs": {
            "domains": ["update.iaacenter.com", "login.live-login.com", "ssl.arkouthrie.com"],
            "ips": ["103.85.24.158", "45.77.179.176", "149.28.84.98"],
            "hashes": ["797f4a6d6ab3f0c8f5c4b5e6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6"],
        },
        "sample_intel": """
        APT41 exploited a zero-day vulnerability in Citrix NetScaler (CVE-2019-19781) to gain initial
        access to healthcare organizations. The group deployed Cobalt Strike beacons and established
        persistence via DLL side-loading techniques. APT41 used PowerShell scripts to enumerate the
        network and identify high-value targets. The threat actor deployed MESSAGETAP malware to intercept
        SMS messages and call detail records from telecom infrastructure. Lateral movement occurred via
        RDP and SMB using stolen credentials. APT41 exfiltrated patient records and intellectual property
        to C2 servers at update.iaacenter.com (103.85.24.158). The campaign demonstrated dual-use of
        espionage and ransomware deployment for financial gain.

        IOCs:
        - Domain: update.iaacenter.com
        - IP: 103.85.24.158
        - Hash: 797f4a6d6ab3f0c8f5c4b5e6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6
        """,
    },
    "UNC2452": {
        "aliases": ["NOBELIUM", "SolarStorm", "APT29 (overlapping)"],
        "attribution": "Russian Foreign Intelligence Service (SVR) - Suspected",
        "first_seen": "2020",
        "targets": ["Government", "Technology", "Consulting", "Telecom"],
        "geography": ["United States", "Europe", "Middle East"],
        "motivation": "Espionage",
        "sophistication": "Advanced",
        "ttps": {
            "initial_access": [
                "T1195.002",
                "T1199",
            ],  # Supply Chain Compromise, Trusted Relationship
            "execution": ["T1059.001", "T1106"],  # PowerShell, Native API
            "persistence": ["T1543.003", "T1136.002"],  # Windows Service, Create Domain Account
            "privilege_escalation": [
                "T1134.001",
                "T1078.002",
            ],  # Token Impersonation, Domain Accounts
            "defense_evasion": [
                "T1027",
                "T1070.004",
                "T1562.001",
            ],  # Obfuscation, File Deletion, Disable Security Tools
            "credential_access": ["T1003.001", "T1558.003"],  # LSASS, Kerberoasting
            "discovery": [
                "T1087.002",
                "T1069.002",
                "T1482",
            ],  # Domain Account Discovery, Domain Groups, Domain Trust
            "lateral_movement": ["T1021.001", "T1550.002"],  # RDP, Pass the Hash
            "collection": ["T1114.002", "T1213.002"],  # Remote Email Collection, Sharepoint
            "command_and_control": [
                "T1071.001",
                "T1573.002",
                "T1568.002",
            ],  # Web Protocols, Asymmetric Crypto, DGA
            "exfiltration": ["T1041", "T1567.002"],  # C2 Channel, Cloud Storage
        },
        "tools": ["SUNBURST", "TEARDROP", "RAINDROP", "Cobalt Strike", "AdFind"],
        "iocs": {
            "domains": ["avsvmcloud.com", "digitalcollege.org", "thedoccloud.com"],
            "ips": ["13.59.205.66", "54.193.127.66", "20.140.0.1"],
            "hashes": ["32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77"],
        },
        "sample_intel": """
        UNC2452 (NOBELIUM) executed the SolarWinds supply chain attack, compromising the Orion software
        build process to distribute SUNBURST backdoor to 18,000+ organizations. The malware used DNS
        tunneling and HTTPS to communicate with C2 infrastructure at avsvmcloud.com. After initial
        compromise, the group deployed TEARDROP memory-only dropper to load Cobalt Strike. UNC2452
        created rogue domain admin accounts and used token impersonation to move laterally. The threat
        actor accessed cloud environments via stolen SAML tokens, bypassing MFA. Exfiltration occurred
        to attacker-controlled cloud storage. The campaign demonstrated extreme operational security,
        with dormancy periods and careful victim selection.

        IOCs:
        - Domain: avsvmcloud.com
        - IP: 13.59.205.66
        - Hash: 32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77
        """,
    },
    "UNC3890": {
        "aliases": ["TEMP.Hex", "Venom Spider"],
        "attribution": "Unknown - Suspected Chinese Nexus",
        "first_seen": "2021",
        "targets": ["Government", "Defense Industrial Base", "Technology"],
        "geography": ["United States", "Europe", "Asia"],
        "motivation": "Espionage",
        "sophistication": "Advanced",
        "ttps": {
            "initial_access": [
                "T1190",
                "T1133",
            ],  # Exploit Public-Facing Application, External Remote Services
            "execution": ["T1059.001", "T1059.006", "T1203"],  # PowerShell, Python, Exploitation
            "persistence": ["T1505.003", "T1053.005"],  # Web Shell, Scheduled Task
            "privilege_escalation": ["T1068", "T1078"],  # Exploitation, Valid Accounts
            "defense_evasion": [
                "T1027",
                "T1070.004",
                "T1036",
            ],  # Obfuscation, File Deletion, Masquerading
            "credential_access": ["T1003.001", "T1552.001"],  # LSASS, Credentials in Files
            "discovery": [
                "T1083",
                "T1046",
                "T1018",
            ],  # File Discovery, Network Service Scanning, Remote System Discovery
            "lateral_movement": ["T1021.004", "T1570"],  # SSH, Lateral Tool Transfer
            "collection": ["T1005", "T1560.001"],  # Data from Local System, Archive via Utility
            "command_and_control": ["T1071.001", "T1573.001"],  # Web Protocols, Symmetric Crypto
            "exfiltration": ["T1041", "T1048.003"],  # C2 Channel, Exfil Over Alternative Protocol
        },
        "tools": ["China Chopper", "Cobalt Strike", "Mimikatz", "NBTscan", "Custom Python Tools"],
        "iocs": {
            "domains": ["update-service.org", "cdn-images.net", "api-gateway.info"],
            "ips": ["45.142.212.61", "185.220.101.45", "103.253.145.28"],
            "hashes": ["a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"],
        },
        "sample_intel": """
        UNC3890 exploited ProxyShell vulnerabilities (CVE-2021-34473, CVE-2021-34523, CVE-2021-31207)
        in Microsoft Exchange servers to deploy web shells. The group used China Chopper for initial
        access and deployed custom Python-based backdoors for persistence. UNC3890 leveraged PowerShell
        scripts to enumerate Active Directory and identify sensitive data repositories. The threat actor
        used Mimikatz to harvest credentials and moved laterally via SSH to Linux systems. Network
        scanning with NBTscan identified additional targets. Data was archived using 7-Zip and exfiltrated
        to C2 infrastructure at update-service.org (45.142.212.61). The campaign targeted defense contractors
        and government agencies with a focus on intellectual property theft.

        IOCs:
        - Domain: update-service.org
        - IP: 45.142.212.61
        - Hash: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2
        """,
    },
    "Lazarus Group": {
        "aliases": ["APT38", "HIDDEN COBRA", "Guardians of Peace", "Zinc"],
        "attribution": "North Korean State-Sponsored",
        "first_seen": "2009",
        "targets": ["Financial", "Cryptocurrency", "Media", "Defense", "Government"],
        "geography": ["South Korea", "United States", "Global"],
        "motivation": "Financial Gain, Espionage, Disruption",
        "sophistication": "Advanced",
        "ttps": {
            "initial_access": [
                "T1566.001",
                "T1195.002",
                "T1189",
            ],  # Spearphishing, Supply Chain, Drive-by Compromise
            "execution": [
                "T1059.001",
                "T1059.003",
                "T1203",
            ],  # PowerShell, Windows Command Shell, Exploitation
            "persistence": ["T1547.001", "T1543.003"],  # Registry Run Keys, Windows Service
            "privilege_escalation": ["T1068", "T1055"],  # Exploitation, Process Injection
            "defense_evasion": [
                "T1027",
                "T1070.004",
                "T1112",
            ],  # Obfuscation, File Deletion, Modify Registry
            "credential_access": ["T1003.001", "T1555.003"],  # LSASS, Credentials from Web Browsers
            "discovery": [
                "T1083",
                "T1057",
                "T1082",
            ],  # File Discovery, Process Discovery, System Info
            "lateral_movement": ["T1021.001", "T1021.002"],  # RDP, SMB
            "collection": ["T1005", "T1114.001"],  # Data from Local System, Email Collection
            "command_and_control": ["T1071.001", "T1105"],  # Web Protocols, Ingress Tool Transfer
            "exfiltration": ["T1041", "T1048.003"],  # C2 Channel, Exfil Over Alternative Protocol
            "impact": [
                "T1485",
                "T1490",
                "T1486",
            ],  # Data Destruction, Inhibit System Recovery, Ransomware
        },
        "tools": ["HOPLIGHT", "ELECTRICFISH", "BADCALL", "Mimikatz", "Custom Wipers"],
        "iocs": {
            "domains": ["nzssdm.com", "codevexillium.org", "bizonepartners.com"],
            "ips": ["185.220.101.45", "23.227.196.215", "91.109.17.6"],
            "hashes": ["b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2"],
        },
        "sample_intel": """
        Lazarus Group conducted a sophisticated attack against cryptocurrency exchanges using spearphishing
        emails with trojanized cryptocurrency trading applications. The malicious software exploited a
        zero-day vulnerability to deploy HOPLIGHT backdoor. The malware established C2 communications to
        nzssdm.com and used PowerShell scripts to enumerate the network. Lazarus deployed ELECTRICFISH
        tunneling tool to bypass network segmentation and access isolated systems. The group used Mimikatz
        to harvest credentials and moved laterally to financial transaction systems. Lazarus manipulated
        SWIFT transactions and exfiltrated $81 million in cryptocurrency. The campaign also deployed wiper
        malware to destroy forensic evidence and disrupt recovery efforts.

        IOCs:
        - Domain: nzssdm.com
        - IP: 185.220.101.45
        - Hash: b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2
        """,
    },
}


def get_threat_actor_profile(actor_name: str) -> Dict[str, Any]:
    """Get threat actor profile by name."""
    return THREAT_ACTOR_PROFILES.get(actor_name, {})


def list_threat_actors() -> List[str]:
    """List all available threat actor profiles."""
    return list(THREAT_ACTOR_PROFILES.keys())


def get_all_profiles() -> Dict[str, Dict[str, Any]]:
    """Get all threat actor profiles."""
    return THREAT_ACTOR_PROFILES
