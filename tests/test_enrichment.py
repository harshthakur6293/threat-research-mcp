"""
Tests for the enrichment framework.

This module tests the enrichment base classes, sources, manager,
and confidence scorer.
"""

import pytest

from threat_research_mcp.enrichment.base import (
    IOCType,
    EnrichmentResult,
    MockEnrichmentSource,
)
from threat_research_mcp.enrichment.manager import EnrichmentManager
from threat_research_mcp.enrichment.confidence_scorer import ConfidenceScorer
from threat_research_mcp.enrichment.tier1 import (
    VirusTotalSource,
    AlienVaultOTXSource,
    AbuseIPDBSource,
    URLhausSource,
    ThreatFoxSource,
)
from threat_research_mcp.enrichment.tier2 import (
    ShodanSource,
    GreyNoiseSource,
)


class TestIOCType:
    """Tests for IOCType enum."""

    def test_ioc_types_exist(self):
        """Test that all IOC types are defined."""
        assert IOCType.IP.value == "ip"
        assert IOCType.DOMAIN.value == "domain"
        assert IOCType.URL.value == "url"
        assert IOCType.HASH_MD5.value == "hash_md5"
        assert IOCType.HASH_SHA1.value == "hash_sha1"
        assert IOCType.HASH_SHA256.value == "hash_sha256"


class TestEnrichmentResult:
    """Tests for EnrichmentResult dataclass."""

    def test_create_enrichment_result(self):
        """Test creating an enrichment result."""
        result = EnrichmentResult(
            source_name="Test Source",
            ioc="192.168.1.1",
            ioc_type=IOCType.IP,
            data={"reputation": "malicious"},
            confidence=0.85,
        )

        assert result.source_name == "Test Source"
        assert result.ioc == "192.168.1.1"
        assert result.ioc_type == IOCType.IP
        assert result.data["reputation"] == "malicious"
        assert result.confidence == 0.85

    def test_is_success_with_data(self):
        """Test is_success returns True with data."""
        result = EnrichmentResult(
            source_name="Test",
            ioc="test",
            ioc_type=IOCType.IP,
            data={"test": "data"},
        )
        assert result.is_success() is True

    def test_is_success_with_error(self):
        """Test is_success returns False with error."""
        result = EnrichmentResult(
            source_name="Test",
            ioc="test",
            ioc_type=IOCType.IP,
            error="Test error",
        )
        assert result.is_success() is False

    def test_to_dict(self):
        """Test converting result to dictionary."""
        result = EnrichmentResult(
            source_name="Test",
            ioc="test",
            ioc_type=IOCType.IP,
            data={"key": "value"},
            confidence=0.75,
        )

        result_dict = result.to_dict()
        assert result_dict["source_name"] == "Test"
        assert result_dict["ioc"] == "test"
        assert result_dict["ioc_type"] == "ip"
        assert result_dict["data"] == {"key": "value"}
        assert result_dict["confidence"] == 0.75


class TestMockEnrichmentSource:
    """Tests for MockEnrichmentSource."""

    def test_mock_source_supports_all_types(self):
        """Test mock source supports all IOC types."""
        source = MockEnrichmentSource()

        for ioc_type in IOCType:
            assert source.can_enrich(ioc_type)

    def test_mock_source_enrichment(self):
        """Test mock source returns data."""
        source = MockEnrichmentSource()
        result = source.enrich("test", IOCType.IP)

        assert result.is_success()
        assert result.data is not None
        assert "reputation" in result.data
        assert result.confidence == 0.5


class TestEnrichmentManager:
    """Tests for EnrichmentManager."""

    def test_manager_initialization(self):
        """Test manager initializes correctly."""
        manager = EnrichmentManager()
        assert len(manager.sources) == 0
        assert all(tier in manager.sources_by_tier for tier in [1, 2, 3, 4])

    def test_register_source(self):
        """Test registering an enrichment source."""
        manager = EnrichmentManager()
        source = MockEnrichmentSource(name="Test Source", tier=1)

        manager.register_source(source)

        assert "Test Source" in manager.sources
        assert source in manager.sources_by_tier[1]

    def test_set_api_key(self):
        """Test setting API key for a source."""
        manager = EnrichmentManager()
        source = VirusTotalSource()
        manager.register_source(source)

        result = manager.set_api_key("VirusTotal", "test_key")

        assert result is True
        assert source.has_api_key()

    def test_set_api_key_nonexistent_source(self):
        """Test setting API key for nonexistent source."""
        manager = EnrichmentManager()
        result = manager.set_api_key("NonExistent", "test_key")
        assert result is False

    def test_get_available_sources(self):
        """Test getting available sources."""
        manager = EnrichmentManager()
        manager.register_source(MockEnrichmentSource(name="Source 1", tier=1))
        manager.register_source(MockEnrichmentSource(name="Source 2", tier=2))

        all_sources = manager.get_available_sources()
        assert len(all_sources) == 2

        tier1_sources = manager.get_available_sources(tier=1)
        assert len(tier1_sources) == 1

    def test_enrich_ioc(self):
        """Test enriching a single IOC."""
        manager = EnrichmentManager()
        manager.register_source(MockEnrichmentSource())

        results = manager.enrich_ioc("192.168.1.1", IOCType.IP)

        assert len(results) > 0
        assert results[0].ioc == "192.168.1.1"

    def test_get_source_status(self):
        """Test getting source status."""
        manager = EnrichmentManager()
        manager.register_source(MockEnrichmentSource(tier=1))
        manager.register_source(VirusTotalSource())  # Requires API key

        status = manager.get_source_status()

        assert status["total_sources"] == 2
        assert status["available_sources"] == 1  # Only mock is available
        assert "sources_by_tier" in status


class TestConfidenceScorer:
    """Tests for ConfidenceScorer."""

    def test_scorer_initialization(self):
        """Test scorer initializes correctly."""
        scorer = ConfidenceScorer()
        assert scorer.WEIGHTS["source_count"] > 0
        assert scorer.SOURCE_REPUTATION["VirusTotal"] > 0

    def test_calculate_confidence_empty_results(self):
        """Test confidence calculation with no results."""
        scorer = ConfidenceScorer()
        analysis = scorer.calculate_confidence([])

        assert analysis["overall_confidence"] == 0.0
        assert analysis["successful_sources"] == 0

    def test_calculate_confidence_single_source(self):
        """Test confidence calculation with single source."""
        scorer = ConfidenceScorer()

        result = EnrichmentResult(
            source_name="VirusTotal",
            ioc="test",
            ioc_type=IOCType.IP,
            data={"reputation": "malicious"},
            confidence=0.90,
        )

        analysis = scorer.calculate_confidence([result])

        assert analysis["overall_confidence"] > 0
        assert analysis["successful_sources"] == 1
        assert "factors" in analysis

    def test_calculate_confidence_multiple_sources(self):
        """Test confidence calculation with multiple sources."""
        scorer = ConfidenceScorer()

        results = [
            EnrichmentResult(
                source_name="VirusTotal",
                ioc="test",
                ioc_type=IOCType.IP,
                data={"reputation": "malicious"},
                confidence=0.90,
            ),
            EnrichmentResult(
                source_name="AlienVault OTX",
                ioc="test",
                ioc_type=IOCType.IP,
                data={"reputation": "malicious"},
                confidence=0.85,
            ),
        ]

        analysis = scorer.calculate_confidence(results)

        assert analysis["overall_confidence"] > 0.5
        assert analysis["successful_sources"] == 2


class TestTier1Sources:
    """Tests for Tier 1 enrichment sources."""

    def test_virustotal_source(self):
        """Test VirusTotal source."""
        source = VirusTotalSource()

        assert source.name == "VirusTotal"
        assert source.tier == 1
        assert source.requires_api_key is True
        assert IOCType.IP in source.supported_ioc_types()

        result = source.enrich("185.220.101.45", IOCType.IP)
        assert result.is_success()
        assert result.data["reputation"] == "malicious"

    def test_alienvault_otx_source(self):
        """Test AlienVault OTX source."""
        source = AlienVaultOTXSource()

        assert source.name == "AlienVault OTX"
        assert source.tier == 1

        result = source.enrich("185.220.101.45", IOCType.IP)
        assert result.is_success()

    def test_abuseipdb_source(self):
        """Test AbuseIPDB source."""
        source = AbuseIPDBSource()

        assert source.name == "AbuseIPDB"
        assert IOCType.IP in source.supported_ioc_types()
        assert IOCType.DOMAIN not in source.supported_ioc_types()

        result = source.enrich("185.220.101.45", IOCType.IP)
        assert result.is_success()

    def test_urlhaus_source(self):
        """Test URLhaus source."""
        source = URLhausSource()

        assert source.name == "URLhaus"
        assert IOCType.URL in source.supported_ioc_types()

        result = source.enrich("http://malicious-c2.com", IOCType.URL)
        assert result.is_success()

    def test_threatfox_source(self):
        """Test ThreatFox source."""
        source = ThreatFoxSource()

        assert source.name == "ThreatFox"
        assert IOCType.IP in source.supported_ioc_types()

        result = source.enrich("185.220.101.45", IOCType.IP)
        assert result.is_success()


class TestTier2Sources:
    """Tests for Tier 2 enrichment sources."""

    def test_shodan_source(self):
        """Test Shodan source."""
        source = ShodanSource()

        assert source.name == "Shodan"
        assert source.tier == 2
        assert source.requires_api_key is True
        assert IOCType.IP in source.supported_ioc_types()

        result = source.enrich("185.220.101.45", IOCType.IP)
        assert result.is_success()

    def test_greynoise_source(self):
        """Test GreyNoise source."""
        source = GreyNoiseSource()

        assert source.name == "GreyNoise"
        assert source.tier == 2

        result = source.enrich("185.220.101.45", IOCType.IP)
        assert result.is_success()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
