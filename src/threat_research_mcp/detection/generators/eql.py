"""
EQL (Event Query Language) detection rule generator.

EQL is used by Elastic Security for searching and analyzing event data.

Reference: https://www.elastic.co/guide/en/elasticsearch/reference/current/eql.html
"""

from typing import Dict, List, Any
from dataclasses import dataclass, field


@dataclass
class EQLRule:
    """
    EQL detection rule structure.

    Attributes:
        name: Rule name
        description: Rule description
        query: EQL query
        severity: Severity level
        risk_score: Risk score (0-100)
        mitre_attack: MITRE ATT&CK techniques
        rule_type: Rule type (eql, query, threshold, etc.)
        index: Index patterns to search
        interval: How often to run the rule
        from_time: Lookback time
        max_signals: Maximum signals to generate
        tags: Rule tags
        references: External references
    """

    name: str
    description: str
    query: str
    severity: str
    risk_score: int
    mitre_attack: List[str]
    rule_type: str = "eql"
    index: List[str] = field(default_factory=lambda: ["logs-*", "winlogbeat-*"])
    interval: str = "5m"
    from_time: str = "now-6m"
    max_signals: int = 100
    tags: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "description": self.description,
            "query": self.query,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "mitre_attack": self.mitre_attack,
            "rule_type": self.rule_type,
            "index": self.index,
            "interval": self.interval,
            "from": self.from_time,
            "max_signals": self.max_signals,
            "tags": self.tags,
            "references": self.references,
        }


class EQLGenerator:
    """
    EQL detection rule generator for Elastic Security.

    Generates EQL queries from threat intelligence and hunt plans.
    """

    def __init__(self):
        """Initialize EQL generator."""
        self.name = "EQL"

    def generate_from_technique(self, technique_id: str, technique_name: str) -> EQLRule:
        """
        Generate EQL rule from ATT&CK technique.

        Args:
            technique_id: ATT&CK technique ID
            technique_name: Technique name

        Returns:
            Generated EQL rule
        """
        if technique_id == "T1059.001":  # PowerShell
            return self._generate_powershell_rule()
        elif technique_id == "T1003.001":  # LSASS Memory
            return self._generate_lsass_rule()
        elif technique_id == "T1071.001":  # Web Protocols
            return self._generate_web_protocols_rule()
        else:
            return self._generate_generic_rule(technique_id, technique_name)

    def _generate_powershell_rule(self) -> EQLRule:
        """Generate EQL rule for PowerShell download cradles."""
        query = """process where event.type == "start" and
  process.name : ("powershell.exe", "pwsh.exe") and
  process.args : ("*DownloadString*", "*DownloadFile*", "*Net.WebClient*", 
                  "*Invoke-WebRequest*", "*Invoke-RestMethod*", "*Start-BitsTransfer*") and
  not process.args : "*Windows\\\\System32*"
"""

        return EQLRule(
            name="Suspicious PowerShell Download Cradle",
            description="Detects PowerShell download cradles used to fetch and execute malicious payloads",
            query=query,
            severity="high",
            risk_score=73,
            mitre_attack=["T1059.001", "T1071.001"],
            tags=[
                "Domain: Endpoint",
                "OS: Windows",
                "Use Case: Threat Detection",
                "Tactic: Execution",
            ],
            references=[
                "https://attack.mitre.org/techniques/T1059/001/",
            ],
        )

    def _generate_lsass_rule(self) -> EQLRule:
        """Generate EQL rule for LSASS memory access."""
        query = """process where event.type == "start" and
  process.pe.original_file_name : ("procdump.exe", "taskmgr.exe", "ProcessHacker.exe") or
  (process.name : ("rundll32.exe", "powershell.exe", "cmd.exe") and
   process.args : ("*lsass*", "*comsvcs.dll*", "*MiniDump*"))
"""

        return EQLRule(
            name="LSASS Memory Access for Credential Dumping",
            description="Detects processes accessing LSASS memory for credential dumping",
            query=query,
            severity="critical",
            risk_score=99,
            mitre_attack=["T1003.001"],
            tags=[
                "Domain: Endpoint",
                "OS: Windows",
                "Use Case: Threat Detection",
                "Tactic: Credential Access",
            ],
            references=[
                "https://attack.mitre.org/techniques/T1003/001/",
            ],
        )

    def _generate_web_protocols_rule(self) -> EQLRule:
        """Generate EQL rule for suspicious web protocols."""
        query = """network where event.type == "connection" and
  process.name : ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", 
                  "mshta.exe", "regsvr32.exe", "rundll32.exe") and
  destination.port in (80, 443, 8080, 8443) and
  not cidrmatch(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
"""

        return EQLRule(
            name="Suspicious Outbound Connection from Uncommon Process",
            description="Detects suspicious outbound connections from processes that typically don't make network connections",
            query=query,
            severity="medium",
            risk_score=47,
            mitre_attack=["T1071.001"],
            tags=[
                "Domain: Endpoint",
                "OS: Windows",
                "Use Case: Threat Detection",
                "Tactic: Command and Control",
            ],
            references=[
                "https://attack.mitre.org/techniques/T1071/001/",
            ],
        )

    def _generate_generic_rule(self, technique_id: str, technique_name: str) -> EQLRule:
        """Generate generic EQL rule for unknown technique."""
        query = f"""process where event.type == "start" and
  process.command_line : "*{technique_name.lower()}*"
"""

        return EQLRule(
            name=f"Suspicious Activity - {technique_name}",
            description=f"Detects suspicious activity related to {technique_name} ({technique_id})",
            query=query,
            severity="medium",
            risk_score=50,
            mitre_attack=[technique_id],
            tags=["Domain: Endpoint", "OS: Windows", "Use Case: Threat Detection"],
            references=[
                f"https://attack.mitre.org/techniques/{technique_id}/",
            ],
        )

    def generate_from_hunt_plan(
        self, hunt_plan: Dict[str, Any], techniques: List[str]
    ) -> List[EQLRule]:
        """
        Generate EQL rules from hunt plan.

        Args:
            hunt_plan: Hunt plan dictionary
            techniques: List of technique IDs

        Returns:
            List of generated EQL rules
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
