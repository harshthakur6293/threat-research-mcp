"""
Enrichment manager for coordinating multiple enrichment sources.

This module provides the EnrichmentManager class that coordinates
enrichment across multiple sources and aggregates results.
"""

from typing import Dict, List, Optional, Any
import logging

from threat_research_mcp.enrichment.base import (
    EnrichmentSource,
    EnrichmentResult,
    IOCType,
)

logger = logging.getLogger(__name__)


class EnrichmentManager:
    """
    Manager for coordinating multiple enrichment sources.
    
    The manager:
    - Registers enrichment sources
    - Routes IOCs to appropriate sources
    - Aggregates results from multiple sources
    - Handles graceful degradation when sources are unavailable
    """
    
    def __init__(self):
        """Initialize the enrichment manager."""
        self.sources: Dict[str, EnrichmentSource] = {}
        self.sources_by_tier: Dict[int, List[EnrichmentSource]] = {
            1: [],
            2: [],
            3: [],
            4: [],
        }
    
    def register_source(self, source: EnrichmentSource) -> None:
        """
        Register an enrichment source.
        
        Args:
            source: EnrichmentSource to register
        """
        self.sources[source.name] = source
        self.sources_by_tier[source.tier].append(source)
        logger.info(f"Registered enrichment source: {source.name} (Tier {source.tier})")
    
    def set_api_key(self, source_name: str, api_key: str) -> bool:
        """
        Set API key for a source.
        
        Args:
            source_name: Name of the source
            api_key: API key to set
        
        Returns:
            True if source found and key set, False otherwise
        """
        source = self.sources.get(source_name)
        if source:
            source.set_api_key(api_key)
            logger.info(f"API key set for {source_name}")
            return True
        logger.warning(f"Source not found: {source_name}")
        return False
    
    def set_api_keys(self, api_keys: Dict[str, str]) -> None:
        """
        Set multiple API keys at once.
        
        Args:
            api_keys: Dictionary mapping source names to API keys
        """
        for source_name, api_key in api_keys.items():
            self.set_api_key(source_name, api_key)
    
    def get_available_sources(
        self,
        ioc_type: Optional[IOCType] = None,
        tier: Optional[int] = None
    ) -> List[EnrichmentSource]:
        """
        Get available enrichment sources.
        
        Args:
            ioc_type: Optional filter by IOC type support
            ioc_type: Optional filter by IOC type support
            tier: Optional filter by tier
        
        Returns:
            List of available sources
        """
        sources = []
        
        # Filter by tier if specified
        if tier is not None:
            candidate_sources = self.sources_by_tier.get(tier, [])
        else:
            candidate_sources = list(self.sources.values())
        
        # Filter by availability and IOC type
        for source in candidate_sources:
            if not source.is_available():
                continue
            if ioc_type and not source.can_enrich(ioc_type):
                continue
            sources.append(source)
        
        return sources
    
    def enrich_ioc(
        self,
        ioc: str,
        ioc_type: IOCType,
        tiers: Optional[List[int]] = None
    ) -> List[EnrichmentResult]:
        """
        Enrich an IOC using available sources.
        
        Args:
            ioc: The IOC to enrich
            ioc_type: Type of the IOC
            tiers: Optional list of tiers to use (default: all)
        
        Returns:
            List of EnrichmentResults from all sources
        """
        results = []
        
        # Determine which tiers to use
        if tiers is None:
            tiers = [1, 2, 3, 4]
        
        # Get available sources for each tier
        for tier in tiers:
            sources = self.get_available_sources(ioc_type=ioc_type, tier=tier)
            
            for source in sources:
                try:
                    result = source.enrich(ioc, ioc_type)
                    results.append(result)
                    
                    if result.is_success():
                        logger.debug(
                            f"Successfully enriched {ioc} with {source.name} "
                            f"(confidence: {result.confidence:.2f})"
                        )
                    else:
                        logger.warning(
                            f"Failed to enrich {ioc} with {source.name}: {result.error}"
                        )
                
                except Exception as e:
                    logger.error(f"Error enriching {ioc} with {source.name}: {e}")
                    # Create error result
                    results.append(
                        source._create_result(
                            ioc=ioc,
                            ioc_type=ioc_type,
                            error=str(e)
                        )
                    )
        
        return results
    
    def enrich_iocs(
        self,
        iocs: Dict[IOCType, List[str]],
        tiers: Optional[List[int]] = None
    ) -> Dict[str, List[EnrichmentResult]]:
        """
        Enrich multiple IOCs.
        
        Args:
            iocs: Dictionary mapping IOC types to lists of IOCs
            tiers: Optional list of tiers to use
        
        Returns:
            Dictionary mapping IOCs to their enrichment results
        """
        all_results = {}
        
        for ioc_type, ioc_list in iocs.items():
            for ioc in ioc_list:
                results = self.enrich_ioc(ioc, ioc_type, tiers=tiers)
                all_results[ioc] = results
        
        return all_results
    
    def get_source_status(self) -> Dict[str, Any]:
        """
        Get status of all registered sources.
        
        Returns:
            Dictionary with source status information
        """
        status = {
            "total_sources": len(self.sources),
            "available_sources": len([s for s in self.sources.values() if s.is_available()]),
            "sources_by_tier": {},
            "sources": []
        }
        
        for tier in [1, 2, 3, 4]:
            tier_sources = self.sources_by_tier[tier]
            status["sources_by_tier"][f"tier_{tier}"] = {
                "total": len(tier_sources),
                "available": len([s for s in tier_sources if s.is_available()])
            }
        
        for source in self.sources.values():
            status["sources"].append({
                "name": source.name,
                "tier": source.tier,
                "requires_api_key": source.requires_api_key,
                "has_api_key": source.has_api_key(),
                "is_available": source.is_available(),
                "supported_ioc_types": [t.value for t in source.supported_ioc_types()]
            })
        
        return status
