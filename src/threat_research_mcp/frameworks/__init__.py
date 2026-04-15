"""
Threat hunting frameworks.

This package implements structured threat hunting frameworks:
- PEAK: Prepare, Execute, Act with Knowledge
- TaHiTI: Targeted Hunting integrating Threat Intelligence
- SQRRL: Hypothesis Maturity Model (HMM0-HMM4)
- Pyramid of Pain: Behavioral focus (hunt for TTPs, not IOCs)
- HEARTH: Community hunt repository integration
"""

from threat_research_mcp.frameworks.peak import PEAKFramework
from threat_research_mcp.frameworks.tahiti import TaHiTIFramework
from threat_research_mcp.frameworks.sqrrl import SQRRLFramework
from threat_research_mcp.frameworks.pyramid_of_pain import PyramidOfPain
from threat_research_mcp.frameworks.hearth import HEARTHIntegration

__all__ = [
    "PEAKFramework",
    "TaHiTIFramework",
    "SQRRLFramework",
    "PyramidOfPain",
    "HEARTHIntegration",
]
