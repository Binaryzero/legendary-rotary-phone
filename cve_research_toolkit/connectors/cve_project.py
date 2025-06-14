"""CVE Project connector for foundational CVE data."""

import json
import logging
from typing import Any, Dict

try:
    from aiohttp import ClientError, ContentTypeError
except ImportError:
    ClientError = Exception
    ContentTypeError = Exception

from .base import DataSourceConnector

logger = logging.getLogger(__name__)
GITHUB_RAW_BASE = "https://raw.githubusercontent.com"


class CVEProjectConnector(DataSourceConnector):
    """Connector for CVEProject/cvelistV5 (Layer 1)."""
    
    def __init__(self) -> None:
        """Initialize connector with request headers."""
        self.headers = {
            'User-Agent': 'CVE-Research-Toolkit/1.0 (Security Research Tool)',
            'Accept': 'application/json, text/plain, */*',
            'Accept-Encoding': 'gzip, deflate'
        }
    
    async def fetch(self, cve_id: str, session: Any) -> Dict[str, Any]:
        """Fetch from MITRE CVE repository with robust error handling."""
        try:
            parts = cve_id.split("-")
            if len(parts) != 3:
                logger.error(f"Invalid CVE ID format: {cve_id}")
                return {}
            
            year = parts[1]
            try:
                cve_number = int(parts[2])
                bucket = cve_number // 1000
            except ValueError:
                logger.error(f"Invalid CVE number in {cve_id}")
                return {}
            
            url = f"{GITHUB_RAW_BASE}/CVEProject/cvelistV5/main/cves/{year}/{bucket}xxx/{cve_id}.json"
            logger.debug(f"Fetching CVE data from: {url}")
            
            async with session.get(url, headers=self.headers) as response:
                if response.status == 200:
                    # GitHub raw API returns JSON with text/plain content-type
                    # We need to handle this by parsing text as JSON manually
                    try:
                        # First try the normal JSON parsing (in case GitHub fixes their MIME type)
                        return await response.json()  # type: ignore
                    except ContentTypeError:
                        # Fallback: parse text content as JSON
                        logger.debug(f"Content-Type issue for {cve_id}, parsing text as JSON")
                        text_content = await response.text()
                        if text_content.strip():
                            try:
                                return json.loads(text_content)  # type: ignore
                            except json.JSONDecodeError as json_error:
                                logger.error(f"Failed to parse JSON for {cve_id}: {json_error}")
                                return {}
                        else:
                            logger.warning(f"Empty response for {cve_id}")
                            return {}
                elif response.status == 404:
                    logger.info(f"CVE {cve_id} not found in CVEProject repository (404)")
                    return {}
                else:
                    logger.warning(f"Failed to fetch {cve_id} from CVEProject: HTTP {response.status}")
                    # Try to get error details
                    try:
                        error_text = await response.text()
                        if error_text:
                            logger.debug(f"Error response for {cve_id}: {error_text[:200]}")
                    except:
                        pass
                    return {}
                    
        except ClientError as e:
            logger.error(f"Network error fetching {cve_id} from CVEProject: {e}")
            return {}
        except Exception as e:
            logger.error(f"Unexpected error fetching {cve_id} from CVEProject: {type(e).__name__}: {e}")
            return {}
    
    def parse(self, cve_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse CVE JSON 5.x format."""
        if not data:
            return {}
        
        containers = data.get("containers", {})
        cna = containers.get("cna", {})
        
        # Extract basic info
        description = ""
        if "descriptions" in cna:
            description = cna["descriptions"][0].get("value", "")
        elif "x_legacyV4Record" in cna:
            legacy = cna["x_legacyV4Record"]
            description = legacy.get("description", {}).get("description_data", [{}])[0].get("value", "")
        
        # Extract CVSS - Enhanced to handle multiple CVSS versions and all ADP entries
        cvss_score = 0.0
        cvss_vector = ""
        
        # Check CNA first, then all ADP entries
        all_containers = [cna] + containers.get("adp", [])
        
        for container in all_containers:
            if not container or cvss_score > 0:
                continue
                
            # Check metrics array
            for metric in container.get("metrics", []):
                if cvss_score > 0:
                    break
                    
                # Try all CVSS versions in preference order (v3.1, v3.0, v2.1, v2.0, v2)
                for cvss_key in ["cvssV3_1", "cvssV3_0", "cvssV2_1", "cvssV2_0", "cvssV2"]:
                    if cvss_key in metric:
                        cvss_data = metric[cvss_key]
                        cvss_score = float(cvss_data.get("baseScore", 0))
                        cvss_vector = cvss_data.get("vectorString", "")
                        logger.debug(f"Found {cvss_key} score {cvss_score} for {cve_id} in {container.get('providerMetadata', {}).get('shortName', 'unknown')}")
                        break
                if cvss_score > 0:
                    break
        
        # Extract references
        references = []
        for ref in cna.get("references", []):
            url = ref.get("url", "")
            if url:
                references.append(url)
        
        # Extract dates
        metadata = data.get("cveMetadata", {})
        published = metadata.get("datePublished", "")
        modified = metadata.get("dateUpdated", published)
        
        result = {
            "description": description,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "references": references,
            "published_date": published,
            "last_modified": modified
        }
        
        logger.debug(f"{cve_id} parsed: CVSS={cvss_score}, desc_length={len(description)}, refs={len(references)}")
        return result