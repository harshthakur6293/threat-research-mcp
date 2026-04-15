"""AlienVault OTX enrichment source."""

from typing import List, Optional
import logging

from threat_research_mcp.enrichment.base import (
    EnrichmentSource,
    EnrichmentResult,
    IOCType,
)

logger = logging.getLogger(__name__)


class AlienVaultOTXSource(EnrichmentSource):
    """AlienVault Open Threat Exchange enrichment source."""

    def __init__(self, api_key: Optional[str] = None):
        super().__init__(name="AlienVault OTX", tier=1, requires_api_key=False)
        if api_key:
            self.set_api_key(api_key)

    def supported_ioc_types(self) -> List[IOCType]:
        return [
            IOCType.IP,
            IOCType.DOMAIN,
            IOCType.URL,
            IOCType.HASH_MD5,
            IOCType.HASH_SHA1,
            IOCType.HASH_SHA256,
        ]

    def enrich(self, ioc: str, ioc_type: IOCType) -> EnrichmentResult:
        if not self.can_enrich(ioc_type):
            return self._create_result(
                ioc=ioc, ioc_type=ioc_type, error=f"OTX does not support {ioc_type.value}"
            )

        # Mock data
        is_malicious = "malicious" in ioc.lower() or ioc.startswith("185.220.101")

        data = {
            "reputation": "malicious" if is_malicious else "unknown",
            "pulse_count": 12 if is_malicious else 0,
            "pulses": [
                {"name": "APT29 SolarWinds Campaign", "created": "2024-01-15"},
                {"name": "Cozy Bear Infrastructure", "created": "2024-02-20"},
            ]
            if is_malicious
            else [],
            "tags": ["apt29", "solarwinds"] if is_malicious else [],
            "threat_score": 85 if is_malicious else 0,
        }

        confidence = 0.88 if is_malicious else 0.50

        return self._create_result(
            ioc=ioc,
            ioc_type=ioc_type,
            data=data,
            confidence=confidence,
            metadata={"mock": True, "source": "AlienVault OTX"},
        )
