"""
Enrichment framework for multi-source threat intelligence.

This package provides a modular framework for enriching IOCs with data
from multiple threat intelligence sources, organized into tiers:

- Tier 1: Essential sources (always available, no API key required)
- Tier 2: Advanced sources (BYOK - Bring Your Own Key)
- Tier 3: Specialized sources (C2 trackers, phishing feeds, malware sandboxes)
- Tier 4: LOLBins (Living Off the Land Binaries)
"""

from threat_research_mcp.enrichment.base import (
    EnrichmentSource,
    EnrichmentResult,
    IOCType,
)
from threat_research_mcp.enrichment.manager import EnrichmentManager

__all__ = [
    "EnrichmentSource",
    "EnrichmentResult",
    "IOCType",
    "EnrichmentManager",
]
