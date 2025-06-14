"""Threat context connector for EPSS and KEV data."""

import json
import logging
from typing import Any, Dict

try:
    from aiohttp import ContentTypeError
except ImportError:
    ContentTypeError = Exception

from .base import DataSourceConnector

logger = logging.getLogger(__name__)
GITHUB_RAW_BASE = "https://raw.githubusercontent.com"


class ThreatContextConnector(DataSourceConnector):
    """Connector for threat context data from GitHub sources (Layer 4)."""
    
    def __init__(self) -> None:
        self.headers = {
            'User-Agent': 'CVE-Research-Toolkit/1.0 (Security Research Tool)',
            'Accept': 'application/json'
        }
        self.epss_cache: Dict[str, Any] = {}
        self.cache_loaded = False
    
    async def _load_epss_data(self, session: Any) -> None:
        """Load EPSS data from ARPSyndicate/cve-scores GitHub repo."""
        if self.cache_loaded:
            return
            
        try:
            url = f"{GITHUB_RAW_BASE}/ARPSyndicate/cve-scores/master/cve-scores.json"
            logger.debug(f"Loading EPSS data from: {url}")
            
            async with session.get(url, headers=self.headers) as response:
                if response.status == 200:
                    try:
                        # Try normal JSON parsing first
                        epss_data = await response.json()
                    except ContentTypeError:
                        # Fallback: parse text content as JSON (GitHub raw returns text/plain)
                        text_content = await response.text()
                        if text_content.strip():
                            epss_data = json.loads(text_content)
                        else:
                            logger.warning("Empty EPSS data response")
                            return
                    
                    self.epss_cache = epss_data
                    self.cache_loaded = True
                    logger.debug(f"Loaded EPSS data for {len(epss_data)} CVEs")
                else:
                    logger.warning(f"Failed to load EPSS data: HTTP {response.status}")
        except Exception as e:
            logger.warning(f"Error loading EPSS data: {e}")
    
    async def fetch(self, cve_id: str, session: Any) -> Dict[str, Any]:
        """Fetch threat context from GitHub sources."""
        # Load EPSS data if not already loaded
        await self._load_epss_data(session)
        
        data = {}
        
        # Get EPSS score from cache
        if cve_id in self.epss_cache:
            epss_data = self.epss_cache[cve_id]
            data["epss"] = {
                "score": epss_data.get("epss", 0.0),
                "percentile": epss_data.get("percentile", 0.0)  # Will calculate if available
            }
        
        # TODO: Add CISA KEV data from GitHub source
        data["in_kev"] = False  # Placeholder
        
        return data
    
    def parse(self, cve_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse threat context data."""
        threat = {
            "in_kev": data.get("in_kev", False),
            "epss_score": data.get("epss", {}).get("score"),
            "epss_percentile": data.get("epss", {}).get("percentile"),
            "actively_exploited": data.get("in_kev", False)
        }
        return {"threat": threat}