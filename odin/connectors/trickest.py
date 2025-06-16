"""Trickest connector for exploit PoC data."""

import logging
import re
from typing import Any, Dict

try:
    from aiohttp import ClientError
except ImportError:
    ClientError = Exception

from .base import DataSourceConnector

logger = logging.getLogger(__name__)
GITHUB_RAW_BASE = "https://raw.githubusercontent.com"


class TrickestConnector(DataSourceConnector):
    """Connector for trickest/cve (Layer 2)."""
    
    def __init__(self) -> None:
        """Initialize connector with request headers."""
        self.headers = {
            'User-Agent': 'ODIN/1.0 (Security Research Tool)',
            'Accept': 'text/markdown, text/plain, */*',
            'Accept-Encoding': 'gzip, deflate'
        }
    
    async def fetch(self, cve_id: str, session: Any) -> Dict[str, Any]:
        """Fetch PoC information from Trickest with robust error handling."""
        try:
            parts = cve_id.split("-")
            if len(parts) < 2:
                logger.error(f"Invalid CVE ID format: {cve_id}")
                return {}
            
            year = parts[1]
            url = f"{GITHUB_RAW_BASE}/trickest/cve/main/{year}/{cve_id}.md"
            logger.debug(f"Fetching Trickest data from: {url}")
            
            async with session.get(url, headers=self.headers) as response:
                if response.status == 200:
                    content = await response.text()
                    if content.strip():
                        return {"content": content}
                    else:
                        logger.debug(f"Empty content for {cve_id} from Trickest")
                        return {}
                elif response.status == 404:
                    logger.debug(f"No PoC data for {cve_id} in Trickest repository (404)")
                    return {}
                else:
                    logger.warning(f"Failed to fetch Trickest data for {cve_id}: HTTP {response.status}")
                    return {}
                    
        except ClientError as e:
            logger.debug(f"Network error fetching Trickest data for {cve_id}: {e}")
            return {}
        except Exception as e:
            logger.debug(f"Error fetching Trickest data for {cve_id}: {type(e).__name__}: {e}")
            return {}
    
    def parse(self, cve_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Trickest markdown format."""
        if not data or "content" not in data:
            return {"exploits": []}
        
        content = data["content"]
        exploits = []
        
        # Parse markdown links (original method)
        link_pattern = r'\[([^\]]+)\]\(([^)]+)\)'
        matches = re.findall(link_pattern, content)
        
        for title, url in matches:
            # Skip CVE reference links
            if any(domain in url.lower() for domain in ['cve.mitre.org', 'nvd.nist.gov']):
                continue
                
            # Determine exploit type
            exploit_type = "poc"
            if "exploit-db.com" in url:
                exploit_type = "exploit-db"
            elif "github.com" in url and "poc" in title.lower():
                exploit_type = "github-poc"
            elif "packetstormsecurity" in url:
                exploit_type = "packetstorm"
            
            exploits.append({
                "url": url,
                "source": "trickest",
                "type": exploit_type,
                "title": title
            })
        
        # Enhanced parsing: Extract plain URLs from content
        # This is the main fix - Trickest data contains mostly plain URLs, not markdown links
        url_pattern = r'https?://[^\s\)]+(?:\.[^\s\)]+)*'
        plain_urls = re.findall(url_pattern, content)
        
        # Filter for exploit-related URLs
        exploit_domains = ['exploit-db.com', 'github.com', 'packetstormsecurity', 'exploitdb.com']
        reference_domains = ['cve.mitre.org', 'nvd.nist.gov', 'cwe.mitre.org']
        
        # Track URLs we've already added to avoid duplicates
        existing_urls = {exploit["url"] for exploit in exploits}
        
        for url in plain_urls:
            # Skip if already added or is a reference URL
            if url in existing_urls or any(domain in url.lower() for domain in reference_domains):
                continue
                
            # Only include exploit-related domains
            if any(domain in url.lower() for domain in exploit_domains):
                # Determine exploit type based on URL
                exploit_type = "poc"
                title = "PoC"
                
                if "exploit-db.com" in url.lower():
                    exploit_type = "exploit-db"
                    title = "Exploit-DB"
                elif "github.com" in url.lower():
                    exploit_type = "github-poc"
                    title = "GitHub PoC"
                elif "packetstormsecurity" in url.lower():
                    exploit_type = "packetstorm"
                    title = "Packet Storm"
                
                exploits.append({
                    "url": url,
                    "source": "trickest",
                    "type": exploit_type,
                    "title": title
                })
                existing_urls.add(url)
        
        logger.debug(f"TrickestConnector found {len(exploits)} exploit URLs for {cve_id}")
        return {"exploits": exploits}