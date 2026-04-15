"""ThreatFox enrichment source."""

from typing import List
import logging

from threat_research_mcp.enrichment.base import (
    EnrichmentSource,
    EnrichmentResult,
    IOCType,
)

logger = logging.getLogger(__name__)


class ThreatFoxSource(EnrichmentSource):
    """ThreatFox enrichment source for IOC sharing."""
    
    def __init__(self):
        super().__init__(name="ThreatFox", tier=1, requires_api_key=False)
    
    def supported_ioc_types(self) -> List[IOCType]:
        return [IOCType.IP, IOCType.DOMAIN, IOCType.URL, IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256]
    
    def enrich(self, ioc: str, ioc_type: IOCType) -> EnrichmentResult:
        if not self.can_enrich(ioc_type):
            return self._create_result(ioc=ioc, ioc_type=ioc_type, error=f"ThreatFox does not support {ioc_type.value}")
        
        # Mock data
        is_malicious = "malicious" in ioc.lower() or ioc.startswith("185.220.101")
        
        data = {
            "threat_type": "botnet_cc" if is_malicious else "unknown",
            "malware_family": "cobalt_strike" if is_malicious else None,
            "confidence_level": 90 if is_malicious else 0,
            "tags": ["cobalt-strike", "apt"] if is_malicious else [],
            "reporter": "abuse_ch" if is_malicious else None,
            "first_seen": "2024-02-01T00:00:00Z" if is_malicious else None,
        }
        
        confidence = 0.87 if is_malicious else 0.40
        
        return self._create_result(
            ioc=ioc,
            ioc_type=ioc_type,
            data=data,
            confidence=confidence,
            metadata={"mock": True, "source": "ThreatFox"}
        )
