"""GreyNoise enrichment source."""

from typing import List, Optional
from threat_research_mcp.enrichment.base import EnrichmentSource, EnrichmentResult, IOCType


class GreyNoiseSource(EnrichmentSource):
    """GreyNoise enrichment source for internet noise detection."""

    def __init__(self, api_key: Optional[str] = None):
        super().__init__(name="GreyNoise", tier=2, requires_api_key=True)
        if api_key:
            self.set_api_key(api_key)

    def supported_ioc_types(self) -> List[IOCType]:
        return [IOCType.IP]

    def enrich(self, ioc: str, ioc_type: IOCType) -> EnrichmentResult:
        if not self.can_enrich(ioc_type):
            return self._create_result(
                ioc=ioc, ioc_type=ioc_type, error="GreyNoise only supports IPs"
            )

        # Mock data
        is_malicious = "185.220.101" in ioc
        data = {
            "classification": "malicious" if is_malicious else "benign",
            "noise": not is_malicious,
            "riot": False,
            "tags": ["scanner", "malware"] if is_malicious else ["benign"],
        }

        return self._create_result(
            ioc=ioc, ioc_type=ioc_type, data=data, confidence=0.85, metadata={"mock": True}
        )
