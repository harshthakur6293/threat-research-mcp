"""
SPL (Search Processing Language) detection rule generator.

SPL is used by Splunk for searching and analyzing data.

Reference: https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/
"""

from typing import Dict, List, Any
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class SPLRule:
    """
    SPL detection rule structure.

    Attributes:
        name: Rule name
        description: Rule description
        search: SPL search query
        earliest_time: Earliest time for search
        latest_time: Latest time for search
        cron_schedule: Cron schedule for alert
        severity: Severity level
        mitre_attack: MITRE ATT&CK techniques
        drilldown_search: Optional drilldown search
        recommended_actions: Recommended response actions
    """

    name: str
    description: str
    search: str
    earliest_time: str
    latest_time: str
    cron_schedule: str
    severity: str
    mitre_attack: List[str]
    drilldown_search: str = ""
    recommended_actions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "description": self.description,
            "search": self.search,
            "earliest_time": self.earliest_time,
            "latest_time": self.latest_time,
            "cron_schedule": self.cron_schedule,
            "severity": self.severity,
            "mitre_attack": self.mitre_attack,
            "drilldown_search": self.drilldown_search,
            "recommended_actions": self.recommended_actions,
        }


class SPLGenerator:
    """
    SPL detection rule generator for Splunk.

    Generates SPL queries from threat intelligence and hunt plans.
    """

    def __init__(self):
        """Initialize SPL generator."""
        self.name = "SPL"

    def generate_from_technique(self, technique_id: str, technique_name: str) -> SPLRule:
        """
        Generate SPL rule from ATT&CK technique.

        Args:
            technique_id: ATT&CK technique ID
            technique_name: Technique name

        Returns:
            Generated SPL rule
        """
        if technique_id == "T1059.001":  # PowerShell
            return self._generate_powershell_rule()
        elif technique_id == "T1003.001":  # LSASS Memory
            return self._generate_lsass_rule()
        elif technique_id == "T1071.001":  # Web Protocols
            return self._generate_web_protocols_rule()
        else:
            return self._generate_generic_rule(technique_id, technique_name)

    def _generate_powershell_rule(self) -> SPLRule:
        """Generate SPL rule for PowerShell download cradles."""
        search = """index=windows EventCode=4688 Image="*powershell.exe" 
(CommandLine="*DownloadString*" OR CommandLine="*DownloadFile*" OR CommandLine="*Net.WebClient*" OR CommandLine="*Invoke-WebRequest*" OR CommandLine="*Invoke-RestMethod*" OR CommandLine="*Start-BitsTransfer*")
NOT CommandLine="*Windows\\\\System32*"
| stats count by ComputerName, User, CommandLine, ParentProcessName
| where count > 0"""

        drilldown = """index=windows EventCode=4688 ComputerName="$ComputerName$" User="$User$"
| table _time, EventCode, Image, CommandLine, ParentProcessName, ParentCommandLine
| sort -_time"""

        return SPLRule(
            name="Suspicious PowerShell Download Cradle",
            description="Detects PowerShell download cradles used to fetch and execute malicious payloads",
            search=search,
            earliest_time="-5m",
            latest_time="now",
            cron_schedule="*/5 * * * *",
            severity="high",
            mitre_attack=["T1059.001", "T1071.001"],
            drilldown_search=drilldown,
            recommended_actions=[
                "Investigate the user account and source IP",
                "Check for additional suspicious activity from the same host",
                "Analyze the downloaded content if available",
                "Review parent process for signs of compromise",
            ],
        )

    def _generate_lsass_rule(self) -> SPLRule:
        """Generate SPL rule for LSASS memory access."""
        search = """index=windows EventCode=10 TargetImage="*\\\\lsass.exe" 
(GrantedAccess="0x1010" OR GrantedAccess="0x1410" OR GrantedAccess="0x1438")
NOT (SourceImage="*\\\\svchost.exe" OR SourceImage="*\\\\wininit.exe" OR SourceImage="*\\\\csrss.exe")
| stats count by ComputerName, User, SourceImage, SourceProcessId, GrantedAccess
| where count > 0"""

        drilldown = """index=windows ComputerName="$ComputerName$" SourceImage="$SourceImage$"
| table _time, EventCode, SourceImage, TargetImage, GrantedAccess, CallTrace
| sort -_time"""

        return SPLRule(
            name="LSASS Memory Access for Credential Dumping",
            description="Detects processes accessing LSASS memory for credential dumping",
            search=search,
            earliest_time="-5m",
            latest_time="now",
            cron_schedule="*/5 * * * *",
            severity="critical",
            mitre_attack=["T1003.001"],
            drilldown_search=drilldown,
            recommended_actions=[
                "Immediately isolate the affected host",
                "Force password reset for affected users",
                "Check for lateral movement from the compromised host",
                "Analyze the source process for malware",
                "Review recent authentication events",
            ],
        )

    def _generate_web_protocols_rule(self) -> SPLRule:
        """Generate SPL rule for suspicious web protocols."""
        search = """index=network sourcetype=firewall 
(src_process="*powershell.exe" OR src_process="*cmd.exe" OR src_process="*wscript.exe" OR src_process="*cscript.exe" OR src_process="*mshta.exe" OR src_process="*regsvr32.exe" OR src_process="*rundll32.exe")
(dest_port=80 OR dest_port=443 OR dest_port=8080 OR dest_port=8443)
NOT (dest_ip=10.* OR dest_ip=192.168.* OR dest_ip=172.16.* OR dest_ip=172.17.* OR dest_ip=172.18.* OR dest_ip=172.19.* OR dest_ip=172.20.* OR dest_ip=172.21.* OR dest_ip=172.22.* OR dest_ip=172.23.* OR dest_ip=172.24.* OR dest_ip=172.25.* OR dest_ip=172.26.* OR dest_ip=172.27.* OR dest_ip=172.28.* OR dest_ip=172.29.* OR dest_ip=172.30.* OR dest_ip=172.31.*)
| stats count by src_ip, src_process, dest_ip, dest_port, url
| where count > 0"""

        drilldown = """index=network src_ip="$src_ip$" dest_ip="$dest_ip$"
| table _time, src_ip, src_process, dest_ip, dest_port, url, bytes_out
| sort -_time"""

        return SPLRule(
            name="Suspicious Outbound Connection from Uncommon Process",
            description="Detects suspicious outbound connections from processes that typically don't make network connections",
            search=search,
            earliest_time="-5m",
            latest_time="now",
            cron_schedule="*/5 * * * *",
            severity="medium",
            mitre_attack=["T1071.001"],
            drilldown_search=drilldown,
            recommended_actions=[
                "Investigate the destination IP and URL",
                "Check for data exfiltration patterns",
                "Review process execution history",
                "Analyze network traffic for beaconing",
            ],
        )

    def _generate_generic_rule(self, technique_id: str, technique_name: str) -> SPLRule:
        """Generate generic SPL rule for unknown technique."""
        search = f"""index=windows EventCode=4688 CommandLine="*{technique_name.lower()}*"
| stats count by ComputerName, User, Image, CommandLine
| where count > 0"""

        return SPLRule(
            name=f"Suspicious Activity - {technique_name}",
            description=f"Detects suspicious activity related to {technique_name} ({technique_id})",
            search=search,
            earliest_time="-5m",
            latest_time="now",
            cron_schedule="*/5 * * * *",
            severity="medium",
            mitre_attack=[technique_id],
            recommended_actions=[
                "Manual review required",
                "Investigate the context of the activity",
            ],
        )

    def generate_from_hunt_plan(
        self, hunt_plan: Dict[str, Any], techniques: List[str]
    ) -> List[SPLRule]:
        """
        Generate SPL rules from hunt plan.

        Args:
            hunt_plan: Hunt plan dictionary
            techniques: List of technique IDs

        Returns:
            List of generated SPL rules
        """
        rules = []

        for technique in techniques:
            technique_name = self._get_technique_name(technique)
            rule = self.generate_from_technique(technique, technique_name)
            rules.append(rule)

        return rules

    def _get_technique_name(self, technique_id: str) -> str:
        """Get technique name from ID (simplified)."""
        technique_names = {
            "T1059.001": "PowerShell",
            "T1003.001": "LSASS Memory",
            "T1071.001": "Web Protocols",
            "T1566.001": "Spearphishing Attachment",
        }
        return technique_names.get(technique_id, "Unknown Technique")
