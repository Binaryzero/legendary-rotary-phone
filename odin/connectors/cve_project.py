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
            'User-Agent': 'ODIN/1.0 (Security Research Tool)',
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
        """
        Internal parsing logic with detailed error context.
        
        Parses CVE JSON 5.x data to extract vulnerability details and structured product intelligence.
        Extracts the vulnerability description, CVSS score and vector, CWE identifiers and descriptions, 
        categorized references (including patches, vendor advisories, mitigations, and fix versions), 
        affected products, CPE-style identifiers, publication and modification dates, and detailed 
        product intelligence such as vendors, products, versions, platforms, modules, and repositories.
        """
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
        
        # Extract CWE information
        cwe_ids = []
        cwe_descriptions = []
        
        # Check CNA problemTypes for CWE data
        for problem_type in cna.get("problemTypes", []):
            for desc in problem_type.get("descriptions", []):
                if desc.get("type") == "CWE" and desc.get("cweId"):
                    cwe_id = desc.get("cweId", "")
                    cwe_desc = desc.get("description", "")
                    if cwe_id and cwe_id not in cwe_ids:
                        cwe_ids.append(cwe_id)
                        if cwe_desc:
                            cwe_descriptions.append(f"{cwe_id}: {cwe_desc}")
        
        # Also check ADP entries for additional CWE data
        for adp in containers.get("adp", []):
            for problem_type in adp.get("problemTypes", []):
                for desc in problem_type.get("descriptions", []):
                    if desc.get("type") == "CWE" and desc.get("cweId"):
                        cwe_id = desc.get("cweId", "")
                        cwe_desc = desc.get("description", "")
                        if cwe_id and cwe_id not in cwe_ids:
                            cwe_ids.append(cwe_id)
                            if cwe_desc:
                                cwe_descriptions.append(f"{cwe_id}: {cwe_desc}")
        
        # Extract references and categorize them
        references = []
        fix_versions = []
        mitigations = []
        vendor_advisories = []
        patches = []
        
        for ref in cna.get("references", []):
            url = ref.get("url", "")
            if not url:
                continue
                
            references.append(url)
            
            # Categorize references based on tags and URL patterns
            tags = ref.get("tags", [])
            url_lower = url.lower()
            
            # Identify fix/upgrade references
            if any(tag in ["patch", "vendor-advisory", "fix", "upgrade"] for tag in tags):
                if "patch" in tags or "fix" in tags:
                    patches.append(url)
                elif "upgrade" in tags or "vendor-advisory" in tags:
                    fix_versions.append(url)
                    vendor_advisories.append(url)
            
            # Pattern-based categorization for untagged references
            elif any(pattern in url_lower for pattern in ["security-advisories", "advisory", "bulletin", "alert"]):
                vendor_advisories.append(url)
            elif any(pattern in url_lower for pattern in ["patch", "fix", "update", "upgrade", "release-notes"]):
                if "patch" in url_lower or "fix" in url_lower:
                    patches.append(url)
                else:
                    fix_versions.append(url)
            elif any(pattern in url_lower for pattern in ["mitigation", "workaround", "guidance"]):
                mitigations.append(url)
        
        # Extract affected products (CVE 5.0 format) - Enhanced with structured data
        affected_products = []
        cpe_affected = []
        
        # Product intelligence extraction
        vendors = []
        products = []
        affected_versions = []
        platforms = []
        modules = []
        repositories = []
        
        for product in cna.get("affected", []):
            vendor = product.get("vendor", "")
            product_name = product.get("product", "")
            
            if vendor and product_name:
                # Create human-readable affected product entry
                affected_products.append(f"{vendor} {product_name}")
                
                # Generate CPE-style identifier for compatibility
                # Note: This isn't a full CPE but provides affected product info
                cpe_affected.append(f"cpe:2.3:a:{vendor.lower().replace(' ', '_')}:{product_name.lower().replace(' ', '_')}:*:*:*:*:*:*:*:*")
                
                # Extract structured product intelligence
                if vendor not in vendors:
                    vendors.append(vendor)
                if product_name not in products:
                    products.append(product_name)
                
                # Extract repository information
                repo_url = product.get("repo", "")
                if repo_url and repo_url not in repositories:
                    repositories.append(repo_url)
                
                # Extract platform information
                product_platforms = product.get("platforms", [])
                for platform in product_platforms:
                    if platform not in platforms:
                        platforms.append(platform)
                
                # Extract module information
                product_modules = product.get("modules", [])
                for module in product_modules:
                    if module not in modules:
                        modules.append(module)
                
                # Add version information if available
                versions = product.get("versions", [])
                if versions:
                    version_info = []
                    for version in versions[:5]:  # Limit to first 5 versions to avoid bloat
                        version_str = version.get("version", "")
                        status = version.get("status", "")
                        if version_str:
                            version_info.append(f"{version_str} ({status})" if status else version_str)
                            # Add to structured version list
                            if version_str not in affected_versions:
                                affected_versions.append(version_str)
                    if version_info:
                        affected_products.append(f"  Versions: {', '.join(version_info)}")
        
        # Extract dates
        metadata = data.get("cveMetadata", {})
        published = metadata.get("datePublished", "")
        modified = metadata.get("dateUpdated", published)
        
        result = {
            "description": description,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "cwe_ids": cwe_ids,
            "cwe_descriptions": cwe_descriptions,
            "references": references,
            "fix_versions": fix_versions,
            "mitigations": mitigations,
            "vendor_advisories": vendor_advisories,
            "patches": patches,
            "published_date": published,
            "last_modified": modified,
            "affected_products": affected_products,
            "cpe_affected": cpe_affected,
            # Enhanced product intelligence
            "product_intelligence": {
                "vendors": vendors,
                "products": products,
                "affected_versions": affected_versions,
                "platforms": platforms,
                "modules": modules,
                "repositories": repositories
            }
        }
        
        logger.debug(f"{cve_id} parsed: CVSS={cvss_score}, desc_length={len(description)}, refs={len(references)}")
        return result