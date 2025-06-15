"""Base connector interface."""

from abc import ABC, abstractmethod
from typing import Any, Dict


class DataSourceConnector(ABC):
    """Abstract base for data source connectors."""
    
    @abstractmethod
    async def fetch(self, cve_id: str, session: Any) -> Dict[str, Any]:
        """Fetch data for a specific CVE."""
        pass
    
    @abstractmethod
    def parse(self, cve_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse fetched data into standardized format."""
        pass