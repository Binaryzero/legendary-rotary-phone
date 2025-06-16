"""Threat context connector for EPSS and VEDAS data."""

import json
import logging
from typing import Any, Dict, Optional

try:
    from aiohttp import ContentTypeError
except ImportError:
    ContentTypeError = Exception

from .base import DataSourceConnector
from ..models.data import SessionCache

logger = logging.getLogger(__name__)
GITHUB_RAW_BASE = "https://raw.githubusercontent.com"


class ThreatContextConnector(DataSourceConnector):
    """Connector for threat context data from GitHub sources (Layer 4)."""
    
    def __init__(self) -> None:
        self.headers = {
            'User-Agent': 'ODIN/1.0 (Security Research Tool)',
            'Accept': 'application/json'
        }
        self.epss_cache: Dict[str, Any] = {}
        self.cache_loaded = False
        self.session_cache: Optional[SessionCache] = None
    
    def set_session_cache(self, session_cache: SessionCache) -> None:
        """Set session cache for performance optimization."""
        self.session_cache = session_cache
    
    async def _load_epss_data(self, session: Any) -> None:
        """Load EPSS data from ARPSyndicate/cve-scores GitHub repo."""
        # Check session cache first
        if self.session_cache and hasattr(self.session_cache, 'epss_data') and self.session_cache.epss_data:
            self.epss_cache = self.session_cache.epss_data
            self.cache_loaded = True
            logger.debug("Using session-cached EPSS data")
            return
            
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
                    
                    # Store in session cache for other CVEs in this batch
                    if self.session_cache and hasattr(self.session_cache, 'epss_data'):
                        self.session_cache.epss_data = epss_data
                        if hasattr(self.session_cache, 'session_stats'):
                            self.session_cache.session_stats["api_calls"] = self.session_cache.session_stats.get("api_calls", 0) + 1
                    
                    logger.debug(f"Loaded EPSS data for {len(epss_data)} CVEs")
                else:
                    logger.warning(f"Failed to load EPSS data: HTTP {response.status}")
        except Exception as e:
            logger.warning(f"Error loading EPSS data: {e}")
    
    async def fetch(self, cve_id: str, session: Any) -> Dict[str, Any]:
        """
        Asynchronously fetches EPSS and VEDAS threat context data for a given CVE ID.
        
        Retrieves EPSS and VEDAS scores from the session cache, loading data from GitHub sources if necessary. Returns a dictionary containing EPSS and VEDAS threat intelligence metrics for the specified CVE.
        """
        # Load EPSS data if not already loaded
        await self._load_epss_data(session)
        
        data = {}
        
        # Get EPSS and VEDAS scores from cache
        if cve_id in self.epss_cache:
            epss_data = self.epss_cache[cve_id]
            data["epss"] = {
                "score": epss_data.get("epss", 0.0),
                "percentile": epss_data.get("percentile", 0.0)
            }
            # Extract VEDAS data
            data["vedas"] = {
                "score": epss_data.get("vedas_score"),
                "percentile": epss_data.get("vedas_percentile"),
                "score_change": epss_data.get("vedas_score_change"),
                "detail_url": epss_data.get("vedas_detail_url", ""),
                "date": epss_data.get("vedas_date")
            }
        
        # CISA KEV data is now handled by MITREConnector
        # This provides EPSS scores and threat context data
        
        return data
    
    def parse(self, cve_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parses threat context data for a CVE, extracting EPSS and VEDAS threat intelligence metrics.
        
        Returns a dictionary containing threat context fields such as KEV status, EPSS score and percentile, VEDAS score, percentile, score change, detail URL, date, and active exploitation flag.
        """
        vedas_data = data.get("vedas", {})
        threat = {
            "in_kev": data.get("in_kev", False),
            "epss_score": data.get("epss", {}).get("score"),
            "epss_percentile": data.get("epss", {}).get("percentile"),
            "vedas_score": vedas_data.get("score"),
            "vedas_percentile": vedas_data.get("percentile"),
            "vedas_score_change": vedas_data.get("score_change"),
            "vedas_detail_url": vedas_data.get("detail_url", ""),
            "vedas_date": vedas_data.get("date"),
            "actively_exploited": data.get("in_kev", False)
        }
        return {"threat": threat}