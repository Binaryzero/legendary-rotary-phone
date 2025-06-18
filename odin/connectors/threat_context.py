"""Threat context connector - placeholder after ARPSyndicate removal."""

import logging
from typing import Any, Dict, Optional

from .base import DataSourceConnector
from ..models.data import SessionCache

logger = logging.getLogger(__name__)


class ThreatContextConnector(DataSourceConnector):
    """Placeholder connector after ARPSyndicate removal.
    
    Previously fetched EPSS and VEDAS data from ARPSyndicate/cve-scores.
    Now returns empty data as EPSS is available from cvss-bt connector.
    Kept for architectural compatibility.
    """
    
    def __init__(self) -> None:
        self.session_cache: Optional[SessionCache] = None
    
    def set_session_cache(self, session_cache: SessionCache) -> None:
        """Set session cache for performance optimization."""
        self.session_cache = session_cache
    
    async def fetch(self, cve_id: str, session: Any) -> Dict[str, Any]:
        """
        Returns empty data as ARPSyndicate has been removed.
        
        EPSS data is now obtained from cvss-bt connector.
        """
        logger.debug(f"ThreatContextConnector returning empty data for {cve_id} (ARPSyndicate removed)")
        return {}
    
    def parse(self, cve_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Returns empty threat data as ARPSyndicate has been removed.
        """
        return {"threat": {}}