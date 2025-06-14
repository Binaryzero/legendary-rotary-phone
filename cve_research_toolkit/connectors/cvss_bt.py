"""CVSS-BT connector for enhanced CVSS data."""

import csv
import logging
from io import StringIO
from typing import Any, Dict

try:
    from aiohttp import ClientError
except ImportError:
    ClientError = Exception

from .base import DataSourceConnector

logger = logging.getLogger(__name__)
GITHUB_RAW_BASE = "https://raw.githubusercontent.com"


class CVSSBTConnector(DataSourceConnector):
    """Connector for t0sche/cvss-bt CVSS enrichment data (Layer 4)."""
    
    def __init__(self) -> None:
        self.headers = {
            'User-Agent': 'CVE-Research-Toolkit/1.0 (Security Research Tool)',
            'Accept': 'text/csv, text/plain'
        }
        self.cvss_cache: Dict[str, Any] = {}
        self.cache_loaded = False
    
    async def _load_cvss_data(self, session: Any) -> None:
        """Load CVSS data from t0sche/cvss-bt GitHub repo."""
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
                                'epss': safe_float(row.get('epss')),
                                'cisa_kev': row.get('cisa_kev', '').lower() == 'true',
                                'exploitdb': row.get('exploitdb', '').lower() == 'true',
                                'metasploit': row.get('metasploit', '').lower() == 'true'
                            }
                    
                    self.cache_loaded = True
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
        """Parse CVSS-BT data."""
        if not data:
            return {}
        
        return {
            "cvss_score": data.get("base_score", 0.0),
            "cvss_vector": data.get("base_vector", ""),
            "cvss_version": data.get("cvss_version", ""),
            "threat": {
                "in_kev": data.get("cisa_kev", False),
                "epss_score": data.get("epss", 0.0),
                "has_metasploit": data.get("metasploit", False),
                "has_exploitdb": data.get("exploitdb", False)
            }
        }