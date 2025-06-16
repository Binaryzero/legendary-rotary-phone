"""CVSS-BT connector for enhanced CVSS data."""

import csv
import logging
from io import StringIO
from typing import Any, Dict, Optional

try:
    from aiohttp import ClientError
except ImportError:
    ClientError = Exception

from .base import DataSourceConnector
from ..models.data import SessionCache

logger = logging.getLogger(__name__)
GITHUB_RAW_BASE = "https://raw.githubusercontent.com"


class CVSSBTConnector(DataSourceConnector):
    """Connector for t0sche/cvss-bt CVSS enrichment data (Layer 4)."""
    
    def __init__(self) -> None:
        self.headers = {
            'User-Agent': 'ODIN/1.0 (Security Research Tool)',
            'Accept': 'text/csv, text/plain'
        }
        self.cvss_cache: Dict[str, Any] = {}
        self.cache_loaded = False
        self.session_cache: Optional[SessionCache] = None
    
    def set_session_cache(self, session_cache: SessionCache) -> None:
        """Set session cache for performance optimization."""
        self.session_cache = session_cache
    
    async def _load_cvss_data(self, session: Any) -> None:
        """
        Asynchronously loads CVSS-BT enrichment data from the t0sche/cvss-bt GitHub repository and populates the internal cache with CVSS base, CVSS-BT, and temporal metrics for CVEs.
        
        If available, uses session cache to avoid redundant downloads. Updates the session cache and internal statistics after successful loading.
        """
        # Check session cache first
        if self.session_cache and hasattr(self.session_cache, 'cvss_bt_data') and self.session_cache.cvss_bt_data:
            self.cvss_cache = self.session_cache.cvss_bt_data
            self.cache_loaded = True
            logger.debug("Using session-cached CVSS-BT data")
            return
            
        if self.cache_loaded:
            return
            
        try:
            url = f"{GITHUB_RAW_BASE}/t0sche/cvss-bt/main/cvss-bt.csv"
            logger.debug(f"Loading CVSS-BT data from: {url}")
            
            async with session.get(url, headers=self.headers) as response:
                if response.status == 200:
                    csv_text = await response.text()
                    
                    # Parse CSV data
                    reader = csv.DictReader(StringIO(csv_text))
                    
                    for row in reader:
                        cve_id = row.get('cve', '').strip()
                        if cve_id:
                            # Helper function to safely convert to float
                            def safe_float(value: Any, default: float = 0.0) -> float:
                                try:
                                    if value and value.lower() not in ['n/a', 'null', 'none', '']:
                                        return float(value)
                                except (ValueError, AttributeError):
                                    pass
                                return default
                            
                            self.cvss_cache[cve_id] = {
                                'base_score': safe_float(row.get('base_score')),
                                'base_severity': row.get('base_severity', ''),
                                'base_vector': row.get('base_vector', ''),
                                'cvss_version': row.get('cvss_version', ''),
                                'cvss_bt_score': safe_float(row.get('cvss-bt_score')),
                                'cvss_bt_severity': row.get('cvss-bt_severity', ''),
                                'cvss_bt_vector': row.get('cvss-bt_vector', ''),
                                # Temporal CVSS metrics
                                'temporal_score': safe_float(row.get('temporal_score')),
                                'exploit_code_maturity': row.get('exploit_code_maturity', ''),
                                'remediation_level': row.get('remediation_level', ''),
                                'report_confidence': row.get('report_confidence', ''),
                                'assigner': row.get('assigner', ''),
                                'published_date': row.get('published_date', ''),
                                'epss': safe_float(row.get('epss')),
                                'cisa_kev': row.get('cisa_kev', '').lower() == 'true',
                                'vulncheck_kev': row.get('vulncheck_kev', '').lower() == 'true',
                                'exploitdb': row.get('exploitdb', '').lower() == 'true',
                                'metasploit': row.get('metasploit', '').lower() == 'true',
                                'nuclei': row.get('nuclei', '').lower() == 'true',
                                'poc_github': row.get('poc_github', '').lower() == 'true'
                            }
                    
                    self.cache_loaded = True
                    
                    # Store in session cache for other CVEs in this batch
                    if self.session_cache and hasattr(self.session_cache, 'cvss_bt_data'):
                        self.session_cache.cvss_bt_data = self.cvss_cache.copy()
                        if hasattr(self.session_cache, 'session_stats'):
                            self.session_cache.session_stats["api_calls"] = self.session_cache.session_stats.get("api_calls", 0) + 1
                    
                    logger.debug(f"Loaded CVSS-BT data for {len(self.cvss_cache)} CVEs")
                else:
                    logger.warning(f"Failed to load CVSS-BT data: HTTP {response.status}")
        except Exception as e:
            logger.warning(f"Error loading CVSS-BT data: {e}")
    
    async def fetch(self, cve_id: str, session: Any) -> Dict[str, Any]:
        """Fetch CVSS data from t0sche/cvss-bt."""
        # Load CVSS data if not already loaded
        await self._load_cvss_data(session)
        
        if cve_id in self.cvss_cache:
            return self.cvss_cache[cve_id]
        
        return {}
    
    def parse(self, cve_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parses CVSS-BT enrichment data for a given CVE.
        
        Extracts base and CVSS-BT scores, vectors, severity, assigner, publication date, and threat context including KEV status, EPSS score, temporal CVSS metrics, and exploit availability indicators.
        
        Returns:
            A dictionary containing parsed CVSS-BT and threat context data for the specified CVE.
        """
        if not data:
            return {}
        
        return {
            "cvss_score": data.get("base_score", 0.0),
            "cvss_vector": data.get("base_vector", ""),
            "cvss_version": data.get("cvss_version", ""),
            "cvss_bt_score": data.get("cvss_bt_score", 0.0),
            "cvss_bt_severity": data.get("cvss_bt_severity", ""),
            "cvss_bt_vector": data.get("cvss_bt_vector", ""),
            "assigner": data.get("assigner", ""),
            "published_date": data.get("published_date", ""),
            "threat": {
                "in_kev": data.get("cisa_kev", False),
                "vulncheck_kev": data.get("vulncheck_kev", False),
                "epss_score": data.get("epss", 0.0),
                "temporal_score": data.get("temporal_score"),
                "exploit_code_maturity": data.get("exploit_code_maturity", ""),
                "remediation_level": data.get("remediation_level", ""),
                "report_confidence": data.get("report_confidence", ""),
                "has_metasploit": data.get("metasploit", False),
                "has_exploitdb": data.get("exploitdb", False),
                "has_nuclei": data.get("nuclei", False),
                "has_poc_github": data.get("poc_github", False)
            }
        }