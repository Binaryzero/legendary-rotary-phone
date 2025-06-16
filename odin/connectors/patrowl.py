"""Patrowl connector for raw vulnerability intelligence."""

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


class PatrowlConnector(DataSourceConnector):
    """Connector for Patrowl/PatrowlHearsData (Layer 5 - Raw Intelligence)."""
    
    def __init__(self) -> None:
        self.headers = {
            'User-Agent': 'ODIN/1.0 (Security Research Tool)',
            'Accept': 'application/json, text/plain'
        }
    
    async def fetch(self, cve_id: str, session: Any) -> Dict[str, Any]:
        """Fetch CVE data from Patrowl/PatrowlHearsData."""
        try:
            parts = cve_id.split("-")
            if len(parts) != 3:
                logger.error(f"Invalid CVE ID format: {cve_id}")
                return {}
            
            year = parts[1]
            url = f"{GITHUB_RAW_BASE}/Patrowl/PatrowlHearsData/main/CVE/data/{year}/{cve_id}.json"
            logger.debug(f"Fetching Patrowl data from: {url}")
            
            async with session.get(url, headers=self.headers) as response:
                if response.status == 200:
                    try:
                        data = await response.json()
                        # Ensure we return a dict
                        if isinstance(data, dict):
                            return data
                        else:
                            logger.debug(f"Patrowl returned non-dict for {cve_id}")
                            return {}
                    except ContentTypeError:
                        # Handle GitHub's text/plain content type
                        text_content = await response.text()
                        if text_content.strip():
                            try:
                                data = json.loads(text_content)
                                if isinstance(data, dict):
                                    return data
                                else:
                                    logger.debug(f"Patrowl returned non-dict JSON for {cve_id}")
                                    return {}
                            except json.JSONDecodeError:
                                logger.debug(f"Invalid JSON from Patrowl for {cve_id}")
                                return {}
                        return {}
                elif response.status == 404:
                    logger.debug(f"CVE {cve_id} not found in Patrowl repository (404)")
                    return {}
                else:
                    logger.warning(f"Failed to fetch {cve_id} from Patrowl: HTTP {response.status}")
                    return {}
        except Exception as e:
            logger.debug(f"Error fetching {cve_id} from Patrowl: {e}")
            return {}
    
    def parse(self, cve_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Patrowl CVE data."""
        if not data:
            return {}
        
        # Handle case where data might be a string or other non-dict type
        if not isinstance(data, dict):
            logger.debug(f"Patrowl returned non-dict data for {cve_id}: {type(data).__name__}")
            return {}
        
        result = {}
        
        # Extract CVE metadata
        cve_data = data.get("cve", {})
        result["cve_metadata"] = {
            "published_date": data.get("publishedDate", ""),
            "last_modified": data.get("lastModifiedDate", ""),
            "source_identifier": cve_data.get("sourceIdentifier", ""),
            "vuln_status": cve_data.get("vulnStatus", "")
        }
        
        # Extract CVSS data with preference for v3.1, v3.0, v2.0
        impact = data.get("impact", {})
        cvss_score = 0.0
        cvss_vector = ""
        cvss_version = ""
        
        # Try CVSS v3 first
        if "baseMetricV3" in impact:
            cvss_v3 = impact["baseMetricV3"].get("cvssV3", {})
            cvss_score = float(cvss_v3.get("baseScore", 0))
            cvss_vector = cvss_v3.get("vectorString", "")
            cvss_version = cvss_v3.get("version", "3.x")
        
        # Fallback to CVSS v2 if no v3
        elif "baseMetricV2" in impact:
            cvss_v2 = impact["baseMetricV2"].get("cvssV2", {})
            cvss_score = float(cvss_v2.get("baseScore", 0))
            cvss_vector = cvss_v2.get("vectorString", "")
            cvss_version = cvss_v2.get("version", "2.0")
        
        if cvss_score > 0:
            result["cvss_score"] = cvss_score
            result["cvss_vector"] = cvss_vector
            result["cvss_version"] = cvss_version
        
        # Extract configurations (affected products)
        configurations = data.get("configurations", [])
        cpe_matches = []
        for config in configurations:
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if cpe_match.get("vulnerable", False):
                        cpe_matches.append(cpe_match.get("criteria", ""))
        
        result["cpe_affected"] = cpe_matches
        
        # Extract detailed impact metrics
        if "baseMetricV3" in impact:
            v3_data = impact["baseMetricV3"]
            result["impact_metrics"] = {
                "exploitability_score": v3_data.get("exploitabilityScore", 0.0),
                "impact_score": v3_data.get("impactScore", 0.0),
                "cvss_version": "3.x"
            }
        elif "baseMetricV2" in impact:
            v2_data = impact["baseMetricV2"]
            result["impact_metrics"] = {
                "exploitability_score": v2_data.get("exploitabilityScore", 0.0),
                "impact_score": v2_data.get("impactScore", 0.0),
                "cvss_version": "2.0",
                "user_interaction_required": v2_data.get("userInteractionRequired", False),
                "obtain_all_privilege": v2_data.get("obtainAllPrivilege", False)
            }
        
        logger.debug(f"Patrowl parsed {cve_id}: CVSS={cvss_score}, CPEs={len(cpe_matches)}")
        return result