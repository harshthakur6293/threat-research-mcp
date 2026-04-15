"""
Research Agent v2 with multi-source intelligence enrichment.

This agent extracts IOCs from threat intelligence and enriches them
using multiple threat intelligence sources.
"""

from typing import Dict, List, Any, Optional
import logging
import re

from threat_research_mcp.agents.base_agent import BaseAgent
from threat_research_mcp.schemas.workflow_state import ThreatAnalysisState
from threat_research_mcp.enrichment.base import IOCType
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

logger = logging.getLogger(__name__)


class ResearchAgentV2(BaseAgent):
    """
    Research Agent v2 with multi-source intelligence enrichment.
    
    Features:
    - IOC extraction (IPs, domains, URLs, hashes)
    - Multi-source enrichment (Tier 1-4)
    - BYOK (Bring Your Own Keys) support
    - Confidence scoring
    - Graceful degradation
    """
    
    def __init__(self, api_keys: Optional[Dict[str, str]] = None):
        """
        Initialize Research Agent v2.
        
        Args:
            api_keys: Optional dictionary of API keys for enrichment sources
        """
        super().__init__("Research Agent v2")
        
        # Initialize enrichment manager
        self.enrichment_manager = EnrichmentManager()
        self.confidence_scorer = ConfidenceScorer()
        
        # Register Tier 1 sources (Essential)
        self.enrichment_manager.register_source(VirusTotalSource())
        self.enrichment_manager.register_source(AlienVaultOTXSource())
        self.enrichment_manager.register_source(AbuseIPDBSource())
        self.enrichment_manager.register_source(URLhausSource())
        self.enrichment_manager.register_source(ThreatFoxSource())
        
        # Register Tier 2 sources (Advanced - BYOK)
        self.enrichment_manager.register_source(ShodanSource())
        self.enrichment_manager.register_source(GreyNoiseSource())
        
        # Set API keys if provided
        if api_keys:
            self.enrichment_manager.set_api_keys(api_keys)
        
        logger.info("Research Agent v2 initialized with enrichment sources")
    
    def execute(self, state: ThreatAnalysisState) -> ThreatAnalysisState:
        """
        Execute research agent logic.
        
        Args:
            state: Current workflow state
        
        Returns:
            Updated state with research findings
        """
        self._validate_input(state, ["intel_text"])
        
        intel_text = state["intel_text"]
        api_keys = state.get("api_keys", {})
        
        # Set API keys from state
        if api_keys:
            self.enrichment_manager.set_api_keys(api_keys)
        
        logger.info("Starting IOC extraction and enrichment")
        
        # Extract IOCs
        iocs = self._extract_iocs(intel_text)
        
        # Extract ATT&CK techniques
        techniques = self._extract_techniques(intel_text)
        
        # Enrich IOCs
        enrichment_results = self._enrich_iocs(iocs)
        
        # Calculate overall confidence
        all_results = []
        for ioc_results in enrichment_results.values():
            all_results.extend(ioc_results)
        
        confidence_analysis = self.confidence_scorer.calculate_confidence(all_results)
        
        # Create findings
        findings = {
            "iocs": self._format_iocs(iocs, enrichment_results),
            "techniques": techniques,
            "enrichment_summary": {
                "total_iocs": sum(len(v) for v in iocs.values()),
                "enriched_iocs": len(enrichment_results),
                "successful_enrichments": confidence_analysis["successful_sources"],
                "total_enrichments": confidence_analysis["total_sources"],
            },
            "confidence_analysis": confidence_analysis,
        }
        
        # Update state
        state["research_findings"] = self._create_output(
            findings=findings,
            confidence=confidence_analysis["overall_confidence"],
            metadata={
                "source_status": self.enrichment_manager.get_source_status(),
            }
        )
        
        logger.info(
            f"Research complete: {len(iocs)} IOC types, "
            f"{confidence_analysis['successful_sources']} successful enrichments, "
            f"confidence: {confidence_analysis['overall_confidence']:.2f}"
        )
        
        return self._record_execution(state)
    
    def _extract_iocs(self, text: str) -> Dict[IOCType, List[str]]:
        """Extract IOCs from text."""
        iocs = {
            IOCType.IP: [],
            IOCType.DOMAIN: [],
            IOCType.URL: [],
            IOCType.HASH_MD5: [],
            IOCType.HASH_SHA1: [],
            IOCType.HASH_SHA256: [],
        }
        
        # IP addresses
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        iocs[IOCType.IP] = list(set(re.findall(ip_pattern, text)))
        
        # Domains (simple pattern)
        domain_pattern = r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b'
        iocs[IOCType.DOMAIN] = list(set(re.findall(domain_pattern, text.lower())))
        
        # URLs
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        iocs[IOCType.URL] = list(set(re.findall(url_pattern, text)))
        
        # Hashes
        hash_pattern = r'\b[a-fA-F0-9]{32,64}\b'
        hashes = list(set(re.findall(hash_pattern, text)))
        for h in hashes:
            if len(h) == 32:
                iocs[IOCType.HASH_MD5].append(h)
            elif len(h) == 40:
                iocs[IOCType.HASH_SHA1].append(h)
            elif len(h) == 64:
                iocs[IOCType.HASH_SHA256].append(h)
        
        # Remove empty lists
        iocs = {k: v for k, v in iocs.items() if v}
        
        return iocs
    
    def _extract_techniques(self, text: str) -> List[Dict[str, str]]:
        """Extract ATT&CK techniques from text."""
        techniques = []
        
        # Pattern for ATT&CK technique IDs
        technique_pattern = r'T\d{4}(?:\.\d{3})?'
        technique_ids = list(set(re.findall(technique_pattern, text)))
        
        for tid in technique_ids:
            techniques.append({
                "technique_id": tid,
                "name": self._get_technique_name(tid),
            })
        
        return techniques
    
    def _get_technique_name(self, technique_id: str) -> str:
        """Get technique name from ID (simplified)."""
        # In production, this would look up from ATT&CK database
        technique_names = {
            "T1059.001": "PowerShell",
            "T1071.001": "Web Protocols",
            "T1566.001": "Spearphishing Attachment",
        }
        return technique_names.get(technique_id, "Unknown")
    
    def _enrich_iocs(self, iocs: Dict[IOCType, List[str]]) -> Dict[str, List]:
        """Enrich IOCs using enrichment manager."""
        return self.enrichment_manager.enrich_iocs(iocs)
    
    def _format_iocs(
        self,
        iocs: Dict[IOCType, List[str]],
        enrichment_results: Dict[str, List]
    ) -> List[Dict[str, Any]]:
        """Format IOCs with enrichment data."""
        formatted = []
        
        for ioc_type, ioc_list in iocs.items():
            for ioc in ioc_list:
                enrichment = enrichment_results.get(ioc, [])
                
                # Get successful enrichments
                successful = [e for e in enrichment if e.is_success()]
                
                # Calculate confidence for this IOC
                confidence_analysis = self.confidence_scorer.calculate_confidence(enrichment)
                
                formatted.append({
                    "value": ioc,
                    "type": ioc_type.value,
                    "enrichment_count": len(successful),
                    "confidence": confidence_analysis["overall_confidence"],
                    "enrichment_data": [
                        {
                            "source": e.source_name,
                            "data": e.data,
                            "confidence": e.confidence,
                        }
                        for e in successful
                    ],
                })
        
        return formatted
