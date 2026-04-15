"""AbuseIPDB enrichment source."""

from typing import List, Optional
import logging

from threat_research_mcp.enrichment.base import (
    EnrichmentSource,
    EnrichmentResult,
    IOCType,
)

logger = logging.getLogger(__name__)


class AbuseIPDBSource(EnrichmentSource):
    """AbuseIPDB enrichment source for IP reputation."""
    
    def __init__(self, api_key: Optional[str] = None):
        super().__init__(name="AbuseIPDB", tier=1, requires_api_key=True)
        if api_key:
            self.set_api_key(api_key)
    
    def supported_ioc_types(self) -> List[IOCType]:
        return [IOCType.IP]  # Only supports IPs
    
    def enrich(self, ioc: str, ioc_type: IOCType) -> EnrichmentResult:
        if not self.can_enrich(ioc_type):
            return self._create_result(ioc=ioc, ioc_type=ioc_type, error="AbuseIPDB only supports IPs")
        
        # Mock data
        is_malicious = "malicious" in ioc.lower() or ioc.startswith("185.220.101")
        
        data = {
            "abuse_confidence_score": 95 if is_malicious else 0,
            "total_reports": 127 if is_malicious else 0,
            "last_reported": "2024-04-14T00:00:00Z" if is_malicious else None,
            "categories": ["malware", "brute-force", "c2"] if is_malicious else [],
            "is_whitelisted": False,
            "country_code": "RU" if is_malicious else "US",
            "usage_type": "Data Center" if is_malicious else "Residential",
        }
        
        confidence = 0.90 if is_malicious else 0.75
        
        return self._create_result(
            ioc=ioc,
            ioc_type=ioc_type,
            data=data,
            confidence=confidence,
            metadata={"mock": True, "source": "AbuseIPDB"}
        )
