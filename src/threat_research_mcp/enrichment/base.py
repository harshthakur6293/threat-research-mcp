"""
Base classes for the enrichment framework.

This module defines the abstract base classes and data structures
for threat intelligence enrichment sources.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any
from datetime import datetime


class IOCType(Enum):
    """Types of Indicators of Compromise."""
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    EMAIL = "email"
    FILE_PATH = "file_path"
    REGISTRY_KEY = "registry_key"
    UNKNOWN = "unknown"


@dataclass
class EnrichmentResult:
    """
    Result from an enrichment source.
    
    Attributes:
        source_name: Name of the enrichment source
        ioc: The IOC that was enriched
        ioc_type: Type of the IOC
        data: Enrichment data from the source
        confidence: Confidence score (0.0-1.0)
        timestamp: When the enrichment was performed
        error: Error message if enrichment failed
        metadata: Additional metadata
    """
    source_name: str
    ioc: str
    ioc_type: IOCType
    data: Optional[Dict[str, Any]] = None
    confidence: float = 0.0
    timestamp: datetime = field(default_factory=datetime.utcnow)
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def is_success(self) -> bool:
        """Check if enrichment was successful."""
        return self.error is None and self.data is not None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "source_name": self.source_name,
            "ioc": self.ioc,
            "ioc_type": self.ioc_type.value,
            "data": self.data,
            "confidence": self.confidence,
            "timestamp": self.timestamp.isoformat(),
            "error": self.error,
            "metadata": self.metadata,
        }


class EnrichmentSource(ABC):
    """
    Abstract base class for enrichment sources.
    
    All enrichment sources must inherit from this class and implement
    the required methods.
    """
    
    def __init__(self, name: str, tier: int, requires_api_key: bool = False):
        """
        Initialize the enrichment source.
        
        Args:
            name: Human-readable name of the source
            tier: Tier level (1-4)
            requires_api_key: Whether this source requires an API key
        """
        self.name = name
        self.tier = tier
        self.requires_api_key = requires_api_key
        self._api_key: Optional[str] = None
    
    def set_api_key(self, api_key: str) -> None:
        """Set the API key for this source."""
        self._api_key = api_key
    
    def has_api_key(self) -> bool:
        """Check if API key is set."""
        return self._api_key is not None
    
    def is_available(self) -> bool:
        """
        Check if this source is available for use.
        
        Returns:
            True if source is available (has API key if required)
        """
        if self.requires_api_key:
            return self.has_api_key()
        return True
    
    @abstractmethod
    def supported_ioc_types(self) -> List[IOCType]:
        """
        Get the IOC types supported by this source.
        
        Returns:
            List of supported IOC types
        """
        pass
    
    @abstractmethod
    def enrich(self, ioc: str, ioc_type: IOCType) -> EnrichmentResult:
        """
        Enrich an IOC with data from this source.
        
        Args:
            ioc: The IOC to enrich
            ioc_type: Type of the IOC
        
        Returns:
            EnrichmentResult with data or error
        """
        pass
    
    def can_enrich(self, ioc_type: IOCType) -> bool:
        """
        Check if this source can enrich the given IOC type.
        
        Args:
            ioc_type: Type of IOC to check
        
        Returns:
            True if this source supports the IOC type
        """
        return ioc_type in self.supported_ioc_types()
    
    def _create_result(
        self,
        ioc: str,
        ioc_type: IOCType,
        data: Optional[Dict[str, Any]] = None,
        confidence: float = 0.0,
        error: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> EnrichmentResult:
        """
        Helper method to create an EnrichmentResult.
        
        Args:
            ioc: The IOC
            ioc_type: Type of the IOC
            data: Enrichment data
            confidence: Confidence score
            error: Error message if failed
            metadata: Additional metadata
        
        Returns:
            EnrichmentResult instance
        """
        return EnrichmentResult(
            source_name=self.name,
            ioc=ioc,
            ioc_type=ioc_type,
            data=data,
            confidence=confidence,
            error=error,
            metadata=metadata or {},
        )


class MockEnrichmentSource(EnrichmentSource):
    """
    Mock enrichment source for testing.
    
    This source always returns mock data for any IOC type.
    """
    
    def __init__(self, name: str = "Mock Source", tier: int = 1):
        super().__init__(name=name, tier=tier, requires_api_key=False)
    
    def supported_ioc_types(self) -> List[IOCType]:
        """Support all IOC types."""
        return list(IOCType)
    
    def enrich(self, ioc: str, ioc_type: IOCType) -> EnrichmentResult:
        """Return mock enrichment data."""
        return self._create_result(
            ioc=ioc,
            ioc_type=ioc_type,
            data={
                "reputation": "unknown",
                "first_seen": "2024-01-01",
                "last_seen": "2024-01-31",
                "tags": ["mock", "test"],
            },
            confidence=0.5,
            metadata={"mock": True},
        )
