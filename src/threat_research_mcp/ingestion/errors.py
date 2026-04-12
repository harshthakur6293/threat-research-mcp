"""Ingestion-specific errors."""


class IngestionError(Exception):
    """Raised when a source cannot be fetched or parsed."""
