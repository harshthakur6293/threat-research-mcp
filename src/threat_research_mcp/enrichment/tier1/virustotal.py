"""
VirusTotal enrichment source.

This source enriches IOCs using the VirusTotal API.
For testing without an API key, it returns mock data.
"""

from typing import List, Optional
import logging

from threat_research_mcp.enrichment.base import (
    EnrichmentSource,
    EnrichmentResult,
    IOCType,
)

logger = logging.getLogger(__name__)


class VirusTotalSource(EnrichmentSource):
    """
    VirusTotal enrichment source.

    Enriches IPs, domains, URLs, and hashes using VirusTotal API.
    """

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize VirusTotal source.

        Args:
            api_key: Optional VirusTotal API key
        """
        super().__init__(
            name="VirusTotal",
            tier=1,
            requires_api_key=True,  # Requires key for real use
        )
        if api_key:
            self.set_api_key(api_key)

    def supported_ioc_types(self) -> List[IOCType]:
        """VirusTotal supports IPs, domains, URLs, and hashes."""
        return [
            IOCType.IP,
            IOCType.DOMAIN,
            IOCType.URL,
            IOCType.HASH_MD5,
            IOCType.HASH_SHA1,
            IOCType.HASH_SHA256,
        ]

    def enrich(self, ioc: str, ioc_type: IOCType) -> EnrichmentResult:
        """
        Enrich an IOC using VirusTotal.

        Args:
            ioc: The IOC to enrich
            ioc_type: Type of the IOC

        Returns:
            EnrichmentResult with VirusTotal data
        """
        if not self.can_enrich(ioc_type):
            return self._create_result(
                ioc=ioc, ioc_type=ioc_type, error=f"VirusTotal does not support {ioc_type.value}"
            )

        # For now, return mock data
        # In production, this would call the VirusTotal API
        if not self.has_api_key():
            logger.warning("VirusTotal API key not set, returning mock data")
            return self._get_mock_data(ioc, ioc_type)

        # TODO: Implement real API call
        # For now, return mock data even with API key
        return self._get_mock_data(ioc, ioc_type)

    def _get_mock_data(self, ioc: str, ioc_type: IOCType) -> EnrichmentResult:
        """Get mock VirusTotal data for testing."""
        # Simulate different reputations based on IOC
        if "malicious" in ioc.lower() or ioc.startswith("185.220.101"):
            malicious_count = 45
            total_vendors = 70
            reputation = "malicious"
            confidence = 0.92
        elif "suspicious" in ioc.lower():
            malicious_count = 15
            total_vendors = 70
            reputation = "suspicious"
            confidence = 0.65
        else:
            malicious_count = 0
            total_vendors = 70
            reputation = "clean"
            confidence = 0.85

        data = {
            "reputation": reputation,
            "malicious_count": malicious_count,
            "total_vendors": total_vendors,
            "detection_rate": f"{malicious_count}/{total_vendors}",
            "categories": ["malware", "c2"] if reputation == "malicious" else [],
            "tags": ["apt29", "cozy-bear"] if "185.220.101" in ioc else [],
            "first_seen": "2024-01-01T00:00:00Z",
            "last_seen": "2024-04-14T00:00:00Z",
        }

        return self._create_result(
            ioc=ioc,
            ioc_type=ioc_type,
            data=data,
            confidence=confidence,
            metadata={"mock": True, "source": "VirusTotal"},
        )
