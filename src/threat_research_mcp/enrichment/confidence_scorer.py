"""
Confidence scoring engine for enrichment results.

This module calculates confidence scores based on multiple factors:
- Source count (how many sources agree)
- Source agreement (how consistent are the results)
- Source reputation (how reliable are the sources)
- Data freshness (how recent is the data)
"""

from typing import List, Dict, Any
from datetime import datetime, timedelta
import logging

from threat_research_mcp.enrichment.base import EnrichmentResult

logger = logging.getLogger(__name__)


class ConfidenceScorer:
    """
    Calculate confidence scores for enrichment results.
    
    The scorer uses multiple factors to calculate an overall confidence:
    - Source count: More sources = higher confidence
    - Source agreement: Consistent results = higher confidence
    - Source reputation: Reliable sources = higher confidence
    - Data freshness: Recent data = higher confidence
    """
    
    # Source reputation scores (0.0-1.0)
    SOURCE_REPUTATION = {
        "VirusTotal": 0.95,
        "AlienVault OTX": 0.90,
        "AbuseIPDB": 0.90,
        "URLhaus": 0.85,
        "ThreatFox": 0.85,
        "Shodan": 0.88,
        "GreyNoise": 0.87,
    }
    
    # Factor weights
    WEIGHTS = {
        "source_count": 0.25,
        "source_agreement": 0.30,
        "source_reputation": 0.25,
        "data_freshness": 0.20,
    }
    
    def calculate_confidence(
        self,
        results: List[EnrichmentResult]
    ) -> Dict[str, Any]:
        """
        Calculate overall confidence from enrichment results.
        
        Args:
            results: List of enrichment results
        
        Returns:
            Dictionary with confidence score and breakdown
        """
        if not results:
            return {
                "overall_confidence": 0.0,
                "factors": {},
                "successful_sources": 0,
                "total_sources": 0,
            }
        
        # Filter successful results
        successful_results = [r for r in results if r.is_success()]
        
        if not successful_results:
            return {
                "overall_confidence": 0.0,
                "factors": {
                    "source_count": 0.0,
                    "source_agreement": 0.0,
                    "source_reputation": 0.0,
                    "data_freshness": 0.0,
                },
                "successful_sources": 0,
                "total_sources": len(results),
            }
        
        # Calculate individual factors
        factors = {
            "source_count": self._calculate_source_count_score(successful_results),
            "source_agreement": self._calculate_agreement_score(successful_results),
            "source_reputation": self._calculate_reputation_score(successful_results),
            "data_freshness": self._calculate_freshness_score(successful_results),
        }
        
        # Calculate weighted overall confidence
        overall_confidence = sum(
            factors[factor] * self.WEIGHTS[factor]
            for factor in factors
        )
        
        return {
            "overall_confidence": round(overall_confidence, 2),
            "factors": {k: round(v, 2) for k, v in factors.items()},
            "successful_sources": len(successful_results),
            "total_sources": len(results),
            "source_details": [
                {
                    "source": r.source_name,
                    "confidence": r.confidence,
                    "reputation": self.SOURCE_REPUTATION.get(r.source_name, 0.5),
                }
                for r in successful_results
            ],
        }
    
    def _calculate_source_count_score(
        self,
        results: List[EnrichmentResult]
    ) -> float:
        """
        Calculate score based on number of sources.
        
        More sources = higher confidence (with diminishing returns)
        """
        count = len(results)
        
        # Diminishing returns curve
        if count == 0:
            return 0.0
        elif count == 1:
            return 0.50
        elif count == 2:
            return 0.70
        elif count == 3:
            return 0.85
        elif count >= 4:
            return 0.95
        
        return 0.50
    
    def _calculate_agreement_score(
        self,
        results: List[EnrichmentResult]
    ) -> float:
        """
        Calculate score based on agreement between sources.
        
        Consistent results = higher confidence
        """
        if len(results) < 2:
            return 0.70  # Can't measure agreement with 1 source
        
        # Check if sources agree on reputation
        reputations = []
        for result in results:
            if result.data and "reputation" in result.data:
                reputations.append(result.data["reputation"])
        
        if not reputations:
            return 0.50
        
        # Calculate agreement percentage
        most_common = max(set(reputations), key=reputations.count)
        agreement_rate = reputations.count(most_common) / len(reputations)
        
        return agreement_rate
    
    def _calculate_reputation_score(
        self,
        results: List[EnrichmentResult]
    ) -> float:
        """
        Calculate score based on source reputation.
        
        Reliable sources = higher confidence
        """
        if not results:
            return 0.0
        
        # Average reputation of all sources
        total_reputation = sum(
            self.SOURCE_REPUTATION.get(r.source_name, 0.5)
            for r in results
        )
        
        return total_reputation / len(results)
    
    def _calculate_freshness_score(
        self,
        results: List[EnrichmentResult]
    ) -> float:
        """
        Calculate score based on data freshness.
        
        Recent data = higher confidence
        """
        if not results:
            return 0.0
        
        now = datetime.utcnow()
        freshness_scores = []
        
        for result in results:
            # Check timestamp
            age = now - result.timestamp
            
            # Freshness decay curve
            if age < timedelta(hours=1):
                freshness_scores.append(1.0)
            elif age < timedelta(days=1):
                freshness_scores.append(0.95)
            elif age < timedelta(days=7):
                freshness_scores.append(0.85)
            elif age < timedelta(days=30):
                freshness_scores.append(0.70)
            else:
                freshness_scores.append(0.50)
        
        return sum(freshness_scores) / len(freshness_scores) if freshness_scores else 0.50
