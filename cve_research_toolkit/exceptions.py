"""Custom exceptions for CVE Research Toolkit."""

from typing import Optional


class CVEResearchError(Exception):
    """Base exception for CVE Research Toolkit."""
    
    def __init__(self, message: str, cve_id: Optional[str] = None, source: Optional[str] = None) -> None:
        self.message = message
        self.cve_id = cve_id
        self.source = source
        super().__init__(self.message)
    
    def __str__(self) -> str:
        parts = [self.message]
        if self.cve_id:
            parts.append(f"CVE: {self.cve_id}")
        if self.source:
            parts.append(f"Source: {self.source}")
        return " | ".join(parts)


class DataSourceError(CVEResearchError):
    """Exception raised when data source operations fail."""
    pass


class NetworkError(DataSourceError):
    """Exception raised for network-related failures."""
    
    def __init__(self, message: str, status_code: Optional[int] = None, **kwargs) -> None:
        self.status_code = status_code
        super().__init__(message, **kwargs)


class RateLimitError(NetworkError):
    """Exception raised when rate limits are exceeded."""
    
    def __init__(self, message: str, retry_after: Optional[int] = None, **kwargs) -> None:
        self.retry_after = retry_after
        super().__init__(message, status_code=429, **kwargs)


class ParseError(DataSourceError):
    """Exception raised when data parsing fails."""
    pass


class ValidationError(CVEResearchError):
    """Exception raised when data validation fails."""
    pass


class ConfigurationError(CVEResearchError):
    """Exception raised for configuration-related issues."""
    pass


class DependencyError(CVEResearchError):
    """Exception raised when required dependencies are missing."""
    
    def __init__(self, dependency: str, message: Optional[str] = None, **kwargs) -> None:
        self.dependency = dependency
        if not message:
            message = f"Required dependency '{dependency}' is not available"
        super().__init__(message, **kwargs)