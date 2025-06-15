"""CVE Project connector for foundational CVE data."""

import json
import logging
from typing import Any, Dict

try:
    from aiohttp import ClientError, ContentTypeError, ClientResponseError
except ImportError:
    ClientError = Exception
    ContentTypeError = Exception
    ClientResponseError = Exception

from .base import DataSourceConnector
from ..exceptions import NetworkError, ParseError, RateLimitError
from ..utils.retry import async_retry, RetryConfig

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
        """Fetch from MITRE CVE repository with robust error handling and retry logic."""
        # Validate CVE ID format
        parts = cve_id.split("-")
        if len(parts) != 3:
            raise ParseError(f"Invalid CVE ID format: {cve_id}", cve_id=cve_id, source="CVEProject")
        
        year = parts[1]
        try:
            cve_number = int(parts[2])
            bucket = cve_number // 1000
        except ValueError:
            raise ParseError(f"Invalid CVE number in {cve_id}", cve_id=cve_id, source="CVEProject")
        
        url = f"{GITHUB_RAW_BASE}/CVEProject/cvelistV5/main/cves/{year}/{bucket}xxx/{cve_id}.json"
        
        # Configure retry for this specific source
        retry_config = RetryConfig(
            max_attempts=3,
            base_delay=1.0,
            max_delay=30.0
        )
        
        return await async_retry(
            self._fetch_with_session,
            session, url, cve_id,
            config=retry_config
        )
    
    async def _fetch_with_session(self, session: Any, url: str, cve_id: str) -> Dict[str, Any]:
        """Internal fetch method with session handling."""
        logger.debug(f"Fetching CVE data from: {url}")
        
        try:
            async with session.get(url, headers=self.headers) as response:
                # Handle rate limiting
                if response.status == 429:
                    retry_after = int(response.headers.get('Retry-After', 60))
                    raise RateLimitError(
                        f"Rate limited by CVEProject",
                        retry_after=retry_after,
                        cve_id=cve_id,
                        source="CVEProject"
                    )
                
                # Handle client/server errors
                if response.status >= 500:
                    raise NetworkError(
                        f"Server error from CVEProject: HTTP {response.status}",
                        status_code=response.status,
                        cve_id=cve_id,
                        source="CVEProject"
                    )
                
                if response.status == 404:
                    logger.info(f"CVE {cve_id} not found in CVEProject repository (404)")
                    return {}
                
                if response.status >= 400:
                    error_text = ""
                    try:
                        error_text = await response.text()
                    except Exception:
                        pass
                    
                    raise NetworkError(
                        f"Client error from CVEProject: HTTP {response.status} - {error_text[:200]}",
                        status_code=response.status,
                        cve_id=cve_id,
                        source="CVEProject"
                    )
                
                if response.status == 200:
                    return await self._parse_response(response, cve_id)
                
                # Unexpected status
                raise NetworkError(
                    f"Unexpected response status: {response.status}",
                    status_code=response.status,
                    cve_id=cve_id,
                    source="CVEProject"
                )
                
        except ClientError as e:
            raise NetworkError(
                f"Network error fetching {cve_id} from CVEProject: {e}",
                cve_id=cve_id,
                source="CVEProject"
            )
    
    async def _parse_response(self, response: Any, cve_id: str) -> Dict[str, Any]:
        """Parse response with proper error handling."""
        try:
            # First try the normal JSON parsing
            return await response.json()
        except ContentTypeError:
            # GitHub raw API returns JSON with text/plain content-type
            logger.debug(f"Content-Type issue for {cve_id}, parsing text as JSON")
            text_content = await response.text()
            
            if not text_content.strip():
                logger.warning(f"Empty response for {cve_id}")
                return {}
            
            try:
                return json.loads(text_content)
            except json.JSONDecodeError as json_error:
                raise ParseError(
                    f"Failed to parse JSON for {cve_id}: {json_error}",
                    cve_id=cve_id,
                    source="CVEProject"
                )
    
    def parse(self, cve_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse CVE JSON 5.x format with enhanced error handling."""
        if not data:
            return {}
        
        try:
            return self._parse_cve_data(cve_id, data)
        except Exception as e:
            raise ParseError(
                f"Failed to parse CVE data: {e}",
                cve_id=cve_id,
                source="CVEProject"
            )
    
    def _parse_cve_data(self, cve_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Internal parsing logic with detailed error context."""
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