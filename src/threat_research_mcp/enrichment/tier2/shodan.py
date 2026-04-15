"""Shodan enrichment source."""

from typing import List, Optional
from threat_research_mcp.enrichment.base import EnrichmentSource, EnrichmentResult, IOCType


class ShodanSource(EnrichmentSource):
    """Shodan enrichment source for IP intelligence."""

    def __init__(self, api_key: Optional[str] = None):
        super().__init__(name="Shodan", tier=2, requires_api_key=True)
        if api_key:
            self.set_api_key(api_key)

    def supported_ioc_types(self) -> List[IOCType]:
        return [IOCType.IP]

    def enrich(self, ioc: str, ioc_type: IOCType) -> EnrichmentResult:
        if not self.can_enrich(ioc_type):
            return self._create_result(ioc=ioc, ioc_type=ioc_type, error="Shodan only supports IPs")

        # Mock data
        data = {
            "ports": [80, 443, 22],
            "services": ["http", "https", "ssh"],
            "organization": "Evil Corp" if "185.220.101" in ioc else "Unknown",
            "country": "RU" if "185.220.101" in ioc else "US",
            "tags": ["malware", "c2"] if "185.220.101" in ioc else [],
        }

        return self._create_result(
            ioc=ioc, ioc_type=ioc_type, data=data, confidence=0.80, metadata={"mock": True}
        )
