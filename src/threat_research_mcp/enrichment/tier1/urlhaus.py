"""URLhaus enrichment source."""

from typing import List
import logging

from threat_research_mcp.enrichment.base import (
    EnrichmentSource,
    EnrichmentResult,
    IOCType,
)

logger = logging.getLogger(__name__)


class URLhausSource(EnrichmentSource):
    """URLhaus enrichment source for malicious URLs."""

    def __init__(self):
        super().__init__(name="URLhaus", tier=1, requires_api_key=False)

    def supported_ioc_types(self) -> List[IOCType]:
        return [IOCType.URL, IOCType.DOMAIN]

    def enrich(self, ioc: str, ioc_type: IOCType) -> EnrichmentResult:
        if not self.can_enrich(ioc_type):
            return self._create_result(
                ioc=ioc, ioc_type=ioc_type, error=f"URLhaus does not support {ioc_type.value}"
            )

        # Mock data
        is_malicious = "malicious" in ioc.lower() or "c2" in ioc.lower()

        data = {
            "status": "online" if is_malicious else "unknown",
            "threat_type": "malware_download" if is_malicious else None,
            "malware_family": "emotet" if is_malicious else None,
            "tags": ["emotet", "trojan"] if is_malicious else [],
            "first_seen": "2024-01-10T00:00:00Z" if is_malicious else None,
            "last_seen": "2024-04-14T00:00:00Z" if is_malicious else None,
        }

        confidence = 0.85 if is_malicious else 0.30

        return self._create_result(
            ioc=ioc,
            ioc_type=ioc_type,
            data=data,
            confidence=confidence,
            metadata={"mock": True, "source": "URLhaus"},
        )
