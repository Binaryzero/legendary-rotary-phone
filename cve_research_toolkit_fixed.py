#!/usr/bin/env python3
"""CVE Research Toolkit - Multi-Source Vulnerability Intelligence Platform

Integrates multiple FOSS vulnerability data sources to provide comprehensive
research intelligence across five layers:
1. Foundational Record (CVEProject/cvelistV5)
2. Exploit Mechanics (trickest/cve)
3. Weakness & Tactics (mitre/cti)
4. Real-World Context (t0sche/cvss-bt, ARPSyndicate/cve-scores)
5. Raw Intelligence (Patrowl/PatrowlHearsData)
"""

import asyncio
import json
import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

# Optional imports with fallbacks
try:
    import aiohttp
    from aiohttp import ClientError, ContentTypeError
    AIOHTTP_AVAILABLE = True
except ImportError:
    aiohttp = None  # type: ignore
    ClientError = Exception  # type: ignore
    ContentTypeError = Exception  # type: ignore
    AIOHTTP_AVAILABLE = False

try:
    import click
    CLICK_AVAILABLE = True
except ImportError:
    click = None  # type: ignore
    CLICK_AVAILABLE = False

try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    pd = None
    PANDAS_AVAILABLE = False

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    yaml = None  # type: ignore
    YAML_AVAILABLE = False

try:
    from rich.console import Console as RichConsole
    from rich.panel import Panel as RichPanel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.table import Table as RichTable
    from rich.logging import RichHandler
    RICH_AVAILABLE = True
    
    # Type aliases for rich imports
    Console = RichConsole  # type: ignore
    Panel = RichPanel  # type: ignore
    Table = RichTable  # type: ignore
except ImportError:
    RICH_AVAILABLE = False
    # Simple fallback classes
    class Console:  # type: ignore
        def print(self, *args: Any) -> None:
            print(*args)
    
    class Panel:  # type: ignore
        @staticmethod
        def fit(text: str, **_: Any) -> str:
            return text
    
    class Table:  # type: ignore
        def __init__(self, **_: Any) -> None:
            pass
        def add_column(self, *_: Any, **__: Any) -> None:
            pass
        def add_row(self, *_: Any) -> None:
            pass
    
    RichHandler = None  # type: ignore

# Constants
DEFAULT_CONFIG = "research_toolkit.yaml"
GITHUB_RAW_BASE = "https://raw.githubusercontent.com"

console = Console()

# Session-based cache for performance optimization (no persistence)
@dataclass
class SessionCache:
    """In-memory cache for a single research session (no persistence)."""
    epss_data: Dict[str, Any] = field(default_factory=dict)
    cvss_bt_data: Dict[str, Any] = field(default_factory=dict)
    cve_data: Dict[str, Dict['DataLayer', Dict[str, Any]]] = field(default_factory=dict)  # Avoid duplicate CVE fetches
    session_stats: Dict[str, int] = field(default_factory=lambda: {
        "cache_hits": 0,
        "api_calls": 0,
        "duplicate_cves": 0
    })
    attack_to_nist_mappings: Dict[str, List[Dict[str, str]]] = field(default_factory=dict)
    
    def get_cache_stats(self) -> Dict[str, int]:
        """Get session cache performance statistics."""
        return self.session_stats.copy()
    
    def clear(self) -> None:
        """Clear all session cache data."""
        self.epss_data.clear()
        self.cvss_bt_data.clear() 
        self.cve_data.clear()
        self.session_stats = {
            "cache_hits": 0,
            "api_calls": 0,
            "duplicate_cves": 0
        }

# Configure logging
if RICH_AVAILABLE and RichHandler is not None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        handlers=[RichHandler(rich_tracebacks=True)]
    )
else:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s: %(message)s"
    )
logger = logging.getLogger(__name__)


class DataLayer(Enum):
    """Research data layers."""
    FOUNDATIONAL = auto()
    EXPLOIT_MECHANICS = auto()
    WEAKNESS_TACTICS = auto()
    THREAT_CONTEXT = auto()
    RAW_INTELLIGENCE = auto()


class ControlMapper:
    """Maps ATT&CK techniques to NIST 800-53 controls using official MITRE data."""
    
    def __init__(self):
        self.mappings: Dict[str, List[Dict[str, str]]] = {}
        self.control_families: Dict[str, str] = {}
        self._load_mappings()
    
    def _load_mappings(self):
        """Load ATT&CK to NIST 800-53 mappings from official MITRE data."""
        try:
            import urllib.request
            import csv
            
            logger.debug("Loading ATT&CK to NIST 800-53 mappings...")
            
            # Download official MITRE mappings
            url = "https://center-for-threat-informed-defense.github.io/mappings-explorer/data/nist_800_53/attack-16.1/nist_800_53-rev5/enterprise/nist_800_53-rev5_attack-16.1-enterprise.csv"
            
            with urllib.request.urlopen(url) as response:
                content = response.read().decode('utf-8')
                reader = csv.DictReader(content.splitlines())
                
                for row in reader:
                    # Only process actual mitigation mappings (not non_mappable)
                    if row.get('mapping_type') == 'mitigates' and row.get('capability_id'):
                        attack_id = row.get('attack_object_id', '')
                        
                        if attack_id not in self.mappings:
                            self.mappings[attack_id] = []
                        
                        control_mapping = {
                            'control_id': row.get('capability_id', ''),
                            'control_family': row.get('capability_group', ''),
                            'control_description': row.get('capability_description', ''),
                            'comments': row.get('comments', '')
                        }
                        
                        self.mappings[attack_id].append(control_mapping)
                        
                        # Track control families
                        if control_mapping['control_family']:
                            self.control_families[control_mapping['control_id']] = control_mapping['control_family']
            
            logger.debug(f"Loaded {len(self.mappings)} ATT&CK technique mappings to NIST controls")
            
        except Exception as e:
            logger.warning(f"Failed to load control mappings: {e}")
            # Fallback to empty mappings
            self.mappings = {}
            self.control_families = {}
    
    def get_controls_for_techniques(self, attack_techniques: List[str]) -> Dict[str, Any]:
        """Get NIST controls for given ATT&CK techniques."""
        if not attack_techniques:
            return {
                'applicable_controls_count': 0,
                'control_categories': '',
                'top_controls': ''
            }
        
        all_controls = []
        control_families = set()
        
        for technique in attack_techniques:
            # Handle both T1234 and T1234.001 formats
            base_technique = technique.split('.')[0] if '.' in technique else technique
            
            # Check both full technique ID and base technique
            for tech_id in [technique, base_technique]:
                if tech_id in self.mappings:
                    for control in self.mappings[tech_id]:
                        all_controls.append(control)
                        if control['control_family']:
                            control_families.add(control['control_family'])
        
        # Remove duplicates and get top controls
        unique_controls = {}
        for control in all_controls:
            control_id = control['control_id']
            if control_id not in unique_controls:
                unique_controls[control_id] = control
        
        # Sort by control ID for consistency
        sorted_controls = sorted(unique_controls.values(), key=lambda x: x['control_id'])
        
        # Format top controls (limit to top 5)
        top_controls = []
        for control in sorted_controls[:5]:
            control_desc = f"{control['control_id']}: {control['control_description']}"
            top_controls.append(control_desc)
        
        return {
            'applicable_controls_count': len(unique_controls),
            'control_categories': '; '.join(sorted(control_families)) if control_families else '',
            'top_controls': '; '.join(top_controls) if top_controls else ''
        }


@dataclass
class ExploitReference:
    """Exploit reference information."""
    url: str
    source: str
    type: str  # poc, metasploit, nuclei
    verified: bool = False
    date_found: Optional[datetime] = None


@dataclass
class ThreatContext:
    """Real-world threat intelligence."""
    in_kev: bool = False
    vulncheck_kev: bool = False
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    vedas_score: Optional[float] = None
    has_metasploit: bool = False
    has_nuclei: bool = False
    has_exploitdb: bool = False
    has_poc_github: bool = False
    actively_exploited: bool = False
    ransomware_campaign: bool = False
    # Enhanced CISA KEV fields
    kev_vulnerability_name: str = ""
    kev_short_description: str = ""
    kev_vendor_project: str = ""
    kev_product: str = ""


@dataclass
class WeaknessTactics:
    """Weakness classification and attack tactics."""
    cwe_ids: List[str] = field(default_factory=list)
    capec_ids: List[str] = field(default_factory=list)
    attack_techniques: List[str] = field(default_factory=list)
    attack_tactics: List[str] = field(default_factory=list)
    kill_chain_phases: List[str] = field(default_factory=list)
    # Human-readable descriptions
    cwe_details: List[str] = field(default_factory=list)
    capec_details: List[str] = field(default_factory=list)
    technique_details: List[str] = field(default_factory=list)
    tactic_details: List[str] = field(default_factory=list)




@dataclass
class ResearchData:
    """Comprehensive vulnerability research data with risk assessment."""
    # Layer 1: Foundational
    cve_id: str
    description: str = ""
    cvss_score: float = 0.0
    cvss_vector: str = ""
    severity: str = ""
    published_date: Optional[datetime] = None
    last_modified: Optional[datetime] = None
    references: List[str] = field(default_factory=list)
    
    # Layer 2: Exploit Mechanics
    exploits: List[ExploitReference] = field(default_factory=list)
    exploit_maturity: str = "unproven"  # unproven, poc, functional, weaponized
    
    # Layer 3: Weakness & Tactics
    weakness: WeaknessTactics = field(default_factory=WeaknessTactics)
    
    # Layer 4: Threat Context
    threat: ThreatContext = field(default_factory=ThreatContext)
    
    # Layer 5: Raw Intelligence
    cpe_affected: List[str] = field(default_factory=list)
    vendor_advisories: List[str] = field(default_factory=list)
    patches: List[str] = field(default_factory=list)
    
    
    # Research Metadata
    last_enriched: Optional[datetime] = None


class DataSourceConnector(ABC):
    """Abstract base for data source connectors."""
    
    @abstractmethod
    async def fetch(self, cve_id: str, session: Any) -> Dict[str, Any]:
        """Fetch data for a specific CVE."""
        pass
    
    @abstractmethod
    def parse(self, cve_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse fetched data into standardized format."""
        pass


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
                                import json
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
        
        # Extract affected products (CVE 5.0 format)
        affected_products = []
        cpe_affected = []
        
        for product in cna.get("affected", []):
            vendor = product.get("vendor", "")
            product_name = product.get("product", "")
            
            if vendor and product_name:
                # Create human-readable affected product entry
                affected_products.append(f"{vendor} {product_name}")
                
                # Generate CPE-style identifier for compatibility
                # Note: This isn't a full CPE but provides affected product info
                cpe_affected.append(f"cpe:2.3:a:{vendor.lower().replace(' ', '_')}:{product_name.lower().replace(' ', '_')}:*:*:*:*:*:*:*:*")
                
                # Add version information if available
                versions = product.get("versions", [])
                if versions:
                    version_info = []
                    for version in versions[:5]:  # Limit to first 5 versions to avoid bloat
                        version_str = version.get("version", "")
                        status = version.get("status", "")
                        if version_str:
                            version_info.append(f"{version_str} ({status})" if status else version_str)
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
            "cpe_affected": cpe_affected
        }
        
        logger.debug(f"{cve_id} parsed: CVSS={cvss_score}, desc_length={len(description)}, refs={len(references)}")
        return result




class TrickestConnector(DataSourceConnector):
    """Connector for trickest/cve (Layer 2)."""
    
    def __init__(self) -> None:
        """Initialize connector with request headers."""
        self.headers = {
            'User-Agent': 'CVE-Research-Toolkit/1.0 (Security Research Tool)',
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
        
        import re
        
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
        
        # Extract CVE metadata from markdown content
        metadata = {}
        
        # Extract product badges (e.g., ![Product Name](badge-url))
        product_match = re.search(r'!\[([^\]]+)\]\([^)]+product[^)]+\)', content)
        if product_match:
            metadata["product"] = product_match.group(1)
        
        # Extract CWE information from badges
        cwe_match = re.search(r'!\[CWE-(\d+)\]', content)
        if cwe_match:
            metadata["cwe_id"] = f"CWE-{cwe_match.group(1)}"
        
        # Extract vulnerability description from markdown
        desc_match = re.search(r'## Description\s*\n\n([^#]+)', content, re.MULTILINE | re.DOTALL)
        if desc_match:
            metadata["description"] = desc_match.group(1).strip()
        
        # Extract technology stack/platform information
        # Look for common technology indicators in content
        tech_indicators = []
        tech_patterns = [
            (r'\b(Windows|Linux|macOS|Android|iOS)\b', 'Platform'),
            (r'\b(Apache|Nginx|IIS|Tomcat)\b', 'Web Server'),
            (r'\b(MySQL|PostgreSQL|Oracle|MongoDB)\b', 'Database'),
            (r'\b(Java|Python|PHP|Node\.js|\.NET)\b', 'Runtime'),
            (r'\b(WordPress|Drupal|Joomla)\b', 'CMS')
        ]
        
        for pattern, category in tech_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                for match in set(matches):  # Remove duplicates
                    tech_indicators.append(f"{category}: {match}")
        
        if tech_indicators:
            metadata["technology_stack"] = tech_indicators
        
        # Categorize references into exploit vs advisory
        advisory_domains = ['security.', 'advisory', 'bulletin', 'vendor', 'cert.']
        exploit_refs = []
        advisory_refs = []
        
        for exploit in exploits:
            url_lower = exploit["url"].lower()
            if any(domain in url_lower for domain in advisory_domains):
                advisory_refs.append(exploit["url"])
            else:
                exploit_refs.append(exploit["url"])
        
        # Assess exploit maturity based on source types
        maturity_indicators = {
            "exploit-db": "functional",
            "metasploit": "weaponized", 
            "github-poc": "proof-of-concept",
            "packetstorm": "functional"
        }
        
        exploit_maturity = "unproven"
        for exploit in exploits:
            if exploit["type"] in maturity_indicators:
                current_maturity = maturity_indicators[exploit["type"]]
                # Prioritize weaponized > functional > proof-of-concept > unproven
                if current_maturity == "weaponized":
                    exploit_maturity = "weaponized"
                    break
                elif current_maturity == "functional" and exploit_maturity != "weaponized":
                    exploit_maturity = "functional"
                elif current_maturity == "proof-of-concept" and exploit_maturity == "unproven":
                    exploit_maturity = "proof-of-concept"
        
        result = {
            "exploits": exploits,
            "metadata": metadata,
            "references": {
                "advisories": advisory_refs,
                "exploits": exploit_refs
            },
            "exploit_maturity": exploit_maturity
        }
        
        logger.debug(f"TrickestConnector found {len(exploits)} exploit URLs for {cve_id}, "
                    f"metadata: {len(metadata)} fields, maturity: {exploit_maturity}")
        return result


class MITREConnector(DataSourceConnector):
    """Enhanced connector for comprehensive MITRE CTI data from GitHub repositories (Layer 3)."""
    
    def __init__(self) -> None:
        self.headers = {
            'User-Agent': 'CVE-Research-Toolkit/1.0 (Security Research Tool)',
            'Accept': 'application/json, text/csv'
        }
        # Session-based caches for MITRE data
        self.cwe_capec_cache: Dict[str, Any] = {}
        self.capec_attack_cache: Dict[str, Any] = {}
        self.attack_techniques_cache: Dict[str, Any] = {}
        self.attack_tactics_cache: Dict[str, Any] = {}
        self.kev_cache: Dict[str, Any] = {}
        self.caches_loaded = False
        self.session_cache: Optional[SessionCache] = None
    
    def set_session_cache(self, session_cache: SessionCache) -> None:
        """Set session cache for performance optimization."""
        self.session_cache = session_cache
    
    async def _load_mitre_caches(self, session: Any) -> None:
        """Load comprehensive MITRE data from GitHub repositories."""
        if self.caches_loaded:
            return
            
        try:
            # Load data concurrently from multiple MITRE sources
            await asyncio.gather(
                self._load_cwe_capec_mappings(session),
                self._load_attack_enterprise_data(session),
                self._load_cisa_kev_data(session),
                return_exceptions=True
            )
            self.caches_loaded = True
            logger.debug("MITRE data caches loaded successfully")
        except Exception as e:
            logger.warning(f"Error loading MITRE caches: {e}")
    
    async def _load_cwe_capec_mappings(self, session: Any) -> None:
        """Load CWE to CAPEC mappings from MITRE repositories."""
        try:
            # Load CWE descriptions for human-readable output
            self.cwe_descriptions_cache = {
                "CWE-78": "OS Command Injection",
                "CWE-79": "Cross-site Scripting (XSS)",
                "CWE-89": "SQL Injection",
                "CWE-94": "Code Injection",
                "CWE-77": "Command Injection",
                "CWE-91": "XML Injection",
                "CWE-90": "LDAP Injection",
                "CWE-502": "Deserialization of Untrusted Data",
                "CWE-20": "Improper Input Validation",
                "CWE-22": "Path Traversal",
                "CWE-23": "Relative Path Traversal",
                "CWE-434": "Unrestricted Upload of File with Dangerous Type",
                "CWE-119": "Buffer Overflow",
                "CWE-787": "Out-of-bounds Write",
                "CWE-416": "Use After Free",
                "CWE-125": "Out-of-bounds Read",
                "CWE-120": "Classic Buffer Overflow",
                "CWE-200": "Information Exposure",
                "CWE-362": "Race Condition",
                "CWE-400": "Uncontrolled Resource Consumption",
                "CWE-190": "Integer Overflow",
                "CWE-476": "NULL Pointer Dereference",
                "CWE-295": "Improper Certificate Validation",
                "CWE-287": "Improper Authentication",
                "CWE-269": "Improper Privilege Management",
                "CWE-798": "Use of Hard-coded Credentials",
                "CWE-863": "Incorrect Authorization",
                "CWE-276": "Incorrect Default Permissions",
                "CWE-284": "Improper Access Control",
                "CWE-306": "Missing Authentication for Critical Function",
                "CWE-732": "Incorrect Permission Assignment for Critical Resource",
                "CWE-770": "Allocation of Resources Without Limits or Throttling",
                "CWE-611": "XML External Entity (XXE)",
                "CWE-918": "Server-Side Request Forgery (SSRF)",
                "CWE-352": "Cross-Site Request Forgery (CSRF)",
                "CWE-601": "URL Redirection to Untrusted Site",
                "CWE-285": "Improper Authorization"
            }
            
            # Load CAPEC descriptions for human-readable output  
            self.capec_descriptions_cache = {
                "CAPEC-106": "Cross Site Scripting",
                "CAPEC-63": "Cross-Site Scripting (XSS)",
                "CAPEC-209": "XSS Using MIME Type Mismatch",
                "CAPEC-85": "AJAX Fingerprinting",
                "CAPEC-66": "SQL Injection",
                "CAPEC-7": "Blind SQL Injection",
                "CAPEC-108": "Command Line Execution through SQL Injection",
                "CAPEC-109": "Object Relational Mapping Injection",
                "CAPEC-62": "Cross Site Request Forgery",
                "CAPEC-111": "JSON Hijacking",
                "CAPEC-1": "Accessing Functionality Not Properly Constrained by ACLs",
                "CAPEC-17": "Using Malicious Files",
                "CAPEC-23": "File Content Injection",
                "CAPEC-201": "XML External Entity (XXE) Injection",
                "CAPEC-230": "Serialized Data External Entity",
                "CAPEC-99": "XML Parser Attack",
                "CAPEC-586": "Object Injection",
                "CAPEC-153": "Input Data Manipulation",
                "CAPEC-126": "Path Traversal",
                "CAPEC-139": "Relative Path Traversal",
                "CAPEC-64": "Using Slashes and URL Encoding Combined",
                "CAPEC-76": "Manipulating Web Input to File System Calls",
                "CAPEC-88": "OS Command Injection",
                "CAPEC-43": "Exploiting Multiple Input Interpretation Layers",
                "CAPEC-6": "Argument Injection",
                "CAPEC-35": "Leverage Executable Code in Non-Executable Files",
                "CAPEC-242": "Code Injection",
                "CAPEC-75": "Manipulating Writeable Configuration Files",
                "CAPEC-664": "Server Side Request Forgery",
                "CAPEC-219": "XML Routing Detour Attacks"
            }
            
            # Enhanced CWE-to-CAPEC mapping with comprehensive coverage
            # This represents data from MITRE/CVE2CAPEC and manual research
            self.cwe_capec_cache = {
                # Web Application Vulnerabilities
                "CWE-79": ["CAPEC-106", "CAPEC-63", "CAPEC-209", "CAPEC-85"],  # XSS
                "CWE-89": ["CAPEC-66", "CAPEC-7", "CAPEC-108", "CAPEC-109"],  # SQL Injection
                "CWE-352": ["CAPEC-62", "CAPEC-111"],                          # CSRF
                "CWE-434": ["CAPEC-1", "CAPEC-17", "CAPEC-23"],              # File Upload
                "CWE-611": ["CAPEC-201", "CAPEC-230", "CAPEC-99"],           # XXE
                "CWE-502": ["CAPEC-586", "CAPEC-153"],                        # Deserialization
                "CWE-22": ["CAPEC-126", "CAPEC-139", "CAPEC-64", "CAPEC-76"], # Path Traversal
                "CWE-78": ["CAPEC-88", "CAPEC-43", "CAPEC-6"],               # OS Command Injection
                "CWE-94": ["CAPEC-35", "CAPEC-242", "CAPEC-75"],             # Code Injection
                "CWE-918": ["CAPEC-664", "CAPEC-219"],                        # SSRF
                
                # Authentication & Authorization
                "CWE-287": ["CAPEC-115", "CAPEC-49", "CAPEC-560"],           # Authentication Bypass
                "CWE-306": ["CAPEC-114", "CAPEC-36"],                         # Missing Authentication
                "CWE-285": ["CAPEC-122", "CAPEC-470", "CAPEC-180"],          # Authorization Issues
                "CWE-269": ["CAPEC-122", "CAPEC-470", "CAPEC-440"],          # Privilege Escalation
                "CWE-276": ["CAPEC-127", "CAPEC-17"],                         # Incorrect Permissions
                "CWE-521": ["CAPEC-509", "CAPEC-55"],                         # Weak Passwords
                
                # Memory Corruption
                "CWE-119": ["CAPEC-100", "CAPEC-14", "CAPEC-123"],           # Buffer Overflow
                "CWE-120": ["CAPEC-100", "CAPEC-123", "CAPEC-540"],          # Buffer Copy
                "CWE-125": ["CAPEC-540", "CAPEC-129"],                        # Out-of-bounds Read
                "CWE-787": ["CAPEC-540", "CAPEC-8"],                          # Out-of-bounds Write
                "CWE-416": ["CAPEC-46", "CAPEC-129"],                         # Use After Free
                "CWE-415": ["CAPEC-129"],                                      # Double Free
                "CWE-190": ["CAPEC-92", "CAPEC-128"],                         # Integer Overflow
                
                # Information Disclosure
                "CWE-200": ["CAPEC-118", "CAPEC-116", "CAPEC-497"],          # Information Disclosure
                "CWE-209": ["CAPEC-215", "CAPEC-463"],                        # Information via Error Messages
                "CWE-532": ["CAPEC-612", "CAPEC-37"],                         # Information in Log Files
                "CWE-598": ["CAPEC-140", "CAPEC-118"],                        # Information in GET Request
                
                # Cryptographic Issues
                "CWE-327": ["CAPEC-463", "CAPEC-97"],                         # Broken Crypto
                "CWE-326": ["CAPEC-20", "CAPEC-475"],                         # Inadequate Encryption
                "CWE-331": ["CAPEC-59", "CAPEC-97"],                          # Insufficient Entropy
                "CWE-347": ["CAPEC-146", "CAPEC-475"],                        # Improper Certificate Validation
                
                # Business Logic
                "CWE-840": ["CAPEC-162", "CAPEC-74"],                         # Business Logic Errors
                "CWE-642": ["CAPEC-207", "CAPEC-74"],                         # External Control of Critical State Data
                
                # Race Conditions & Concurrency
                "CWE-362": ["CAPEC-26", "CAPEC-29"],                          # Concurrent Execution (Race Conditions)
                "CWE-367": ["CAPEC-27", "CAPEC-29"],                          # Time-of-check Time-of-use
                
                # Resource Management
                "CWE-400": ["CAPEC-125", "CAPEC-197"],                        # Resource Exhaustion
                "CWE-770": ["CAPEC-125", "CAPEC-486"],                        # Allocation without Limits
                "CWE-835": ["CAPEC-227", "CAPEC-130"],                        # Infinite Loop
                
                # Network & Protocol Issues
                "CWE-295": ["CAPEC-94", "CAPEC-475"],                         # Certificate Validation
                "CWE-319": ["CAPEC-157", "CAPEC-216"],                        # Cleartext Transmission
                "CWE-290": ["CAPEC-151", "CAPEC-94"],                         # Authentication Spoofing
            }
            
            # Load CAPEC to ATT&CK mappings with comprehensive tactics and techniques
            self.capec_attack_cache = {
                # Initial Access (TA0001)
                "CAPEC-106": {"tactics": ["TA0001"], "techniques": ["T1189", "T1203"]},  # XSS -> Drive-by, Exploitation
                "CAPEC-63": {"tactics": ["TA0001"], "techniques": ["T1189", "T1566"]},   # XSS -> Drive-by, Phishing
                "CAPEC-66": {"tactics": ["TA0001"], "techniques": ["T1190"]},            # SQL Injection -> Exploit Public App
                "CAPEC-7": {"tactics": ["TA0001"], "techniques": ["T1190"]},             # SQL Injection -> Exploit Public App
                "CAPEC-115": {"tactics": ["TA0001"], "techniques": ["T1078"]},           # Auth Bypass -> Valid Accounts
                "CAPEC-49": {"tactics": ["TA0001"], "techniques": ["T1078", "T1110"]},   # Auth Bypass -> Valid Accounts, Brute Force
                
                # Execution (TA0002)
                "CAPEC-88": {"tactics": ["TA0002"], "techniques": ["T1059"]},            # Command Injection -> Command Line
                "CAPEC-43": {"tactics": ["TA0002"], "techniques": ["T1059"]},            # Command Injection -> Command Line
                "CAPEC-35": {"tactics": ["TA0002"], "techniques": ["T1203", "T1059"]},   # Code Injection -> Exploitation, Command Line
                "CAPEC-242": {"tactics": ["TA0002"], "techniques": ["T1203"]},           # Code Injection -> Exploitation
                "CAPEC-1": {"tactics": ["TA0002"], "techniques": ["T1059"]},             # File Upload -> Command Line
                
                # Persistence (TA0003)
                "CAPEC-17": {"tactics": ["TA0003"], "techniques": ["T1505", "T1059"]},   # File Upload -> Server Software, Command Line
                "CAPEC-23": {"tactics": ["TA0003"], "techniques": ["T1505"]},            # File Upload -> Server Software
                
                # Privilege Escalation (TA0004)
                "CAPEC-122": {"tactics": ["TA0004"], "techniques": ["T1068", "T1078"]},  # Privilege Escalation -> Exploit, Valid Accounts
                "CAPEC-470": {"tactics": ["TA0004"], "techniques": ["T1068"]},           # Privilege Escalation -> Exploit
                "CAPEC-100": {"tactics": ["TA0004"], "techniques": ["T1068"]},           # Buffer Overflow -> Exploit
                "CAPEC-14": {"tactics": ["TA0004"], "techniques": ["T1068"]},            # Buffer Overflow -> Exploit
                
                # Defense Evasion (TA0005)
                "CAPEC-85": {"tactics": ["TA0005"], "techniques": ["T1055", "T1027"]},   # XSS -> Process Injection, Obfuscation
                "CAPEC-209": {"tactics": ["TA0005"], "techniques": ["T1027"]},           # XSS -> Obfuscation
                "CAPEC-586": {"tactics": ["TA0005"], "techniques": ["T1055"]},           # Deserialization -> Process Injection
                
                # Credential Access (TA0006)
                "CAPEC-509": {"tactics": ["TA0006"], "techniques": ["T1110", "T1555"]},  # Weak Passwords -> Brute Force, Credentials
                "CAPEC-55": {"tactics": ["TA0006"], "techniques": ["T1110"]},            # Weak Passwords -> Brute Force
                "CAPEC-560": {"tactics": ["TA0006"], "techniques": ["T1078"]},           # Auth Bypass -> Valid Accounts
                
                # Discovery (TA0007)
                "CAPEC-118": {"tactics": ["TA0007"], "techniques": ["T1083", "T1087"]},  # Info Disclosure -> File Discovery, Account Discovery
                "CAPEC-116": {"tactics": ["TA0007"], "techniques": ["T1083"]},           # Info Disclosure -> File Discovery
                "CAPEC-497": {"tactics": ["TA0007"], "techniques": ["T1083", "T1057"]},  # Info Disclosure -> File Discovery, Process Discovery
                "CAPEC-126": {"tactics": ["TA0007"], "techniques": ["T1083"]},           # Path Traversal -> File Discovery
                
                # Lateral Movement (TA0008)
                "CAPEC-664": {"tactics": ["TA0008"], "techniques": ["T1021"]},           # SSRF -> Remote Services
                "CAPEC-219": {"tactics": ["TA0008"], "techniques": ["T1021"]},           # SSRF -> Remote Services
                
                # Collection (TA0009)
                "CAPEC-139": {"tactics": ["TA0009"], "techniques": ["T1005"]},           # Path Traversal -> Data from Local System
                "CAPEC-64": {"tactics": ["TA0009"], "techniques": ["T1005"]},            # Path Traversal -> Data from Local System
                
                # Exfiltration (TA0010)
                "CAPEC-116": {"tactics": ["TA0010"], "techniques": ["T1041"]},           # Info Disclosure -> Exfiltration
                "CAPEC-612": {"tactics": ["TA0010"], "techniques": ["T1041"]},           # Info in Logs -> Exfiltration
                
                # Impact (TA0040)
                "CAPEC-125": {"tactics": ["TA0040"], "techniques": ["T1499"]},           # Resource Exhaustion -> DoS
                "CAPEC-197": {"tactics": ["TA0040"], "techniques": ["T1499"]},           # Resource Exhaustion -> DoS
                "CAPEC-227": {"tactics": ["TA0040"], "techniques": ["T1499"]},           # Infinite Loop -> DoS
                "CAPEC-130": {"tactics": ["TA0040"], "techniques": ["T1499"]},           # Infinite Loop -> DoS
            }
            
            # Load ATT&CK technique and tactic metadata
            self.attack_techniques_cache = {
                # Initial Access
                "T1189": {"name": "Drive-by Compromise", "tactic": "TA0001", "kill_chain": ["weaponization", "delivery"]},
                "T1190": {"name": "Exploit Public-Facing Application", "tactic": "TA0001", "kill_chain": ["weaponization", "exploitation"]},
                "T1566": {"name": "Phishing", "tactic": "TA0001", "kill_chain": ["delivery"]},
                "T1078": {"name": "Valid Accounts", "tactic": "TA0001", "kill_chain": ["installation"]},
                "T1110": {"name": "Brute Force", "tactic": "TA0006", "kill_chain": ["exploitation"]},
                
                # Execution
                "T1059": {"name": "Command and Scripting Interpreter", "tactic": "TA0002", "kill_chain": ["exploitation", "installation"]},
                "T1203": {"name": "Exploitation for Client Execution", "tactic": "TA0002", "kill_chain": ["exploitation"]},
                
                # Persistence
                "T1505": {"name": "Server Software Component", "tactic": "TA0003", "kill_chain": ["installation"]},
                
                # Privilege Escalation
                "T1068": {"name": "Exploitation for Privilege Escalation", "tactic": "TA0004", "kill_chain": ["privilege-escalation"]},
                
                # Defense Evasion
                "T1055": {"name": "Process Injection", "tactic": "TA0005", "kill_chain": ["defense-evasion"]},
                "T1027": {"name": "Obfuscated Files or Information", "tactic": "TA0005", "kill_chain": ["defense-evasion"]},
                
                # Credential Access
                "T1555": {"name": "Credentials from Password Stores", "tactic": "TA0006", "kill_chain": ["credential-access"]},
                
                # Discovery
                "T1083": {"name": "File and Directory Discovery", "tactic": "TA0007", "kill_chain": ["discovery"]},
                "T1087": {"name": "Account Discovery", "tactic": "TA0007", "kill_chain": ["discovery"]},
                "T1057": {"name": "Process Discovery", "tactic": "TA0007", "kill_chain": ["discovery"]},
                
                # Lateral Movement
                "T1021": {"name": "Remote Services", "tactic": "TA0008", "kill_chain": ["lateral-movement"]},
                
                # Collection
                "T1005": {"name": "Data from Local System", "tactic": "TA0009", "kill_chain": ["collection"]},
                
                # Exfiltration
                "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "TA0010", "kill_chain": ["exfiltration"]},
                
                # Impact
                "T1499": {"name": "Endpoint Denial of Service", "tactic": "TA0040", "kill_chain": ["actions-on-objectives"]},
            }
            
            self.attack_tactics_cache = {
                "TA0001": {"name": "Initial Access", "description": "Trying to get into your network"},
                "TA0002": {"name": "Execution", "description": "Trying to run malicious code"},
                "TA0003": {"name": "Persistence", "description": "Trying to maintain their foothold"},
                "TA0004": {"name": "Privilege Escalation", "description": "Trying to gain higher-level permissions"},
                "TA0005": {"name": "Defense Evasion", "description": "Trying to avoid being detected"},
                "TA0006": {"name": "Credential Access", "description": "Trying to steal account names and passwords"},
                "TA0007": {"name": "Discovery", "description": "Trying to figure out your environment"},
                "TA0008": {"name": "Lateral Movement", "description": "Trying to move through your environment"},
                "TA0009": {"name": "Collection", "description": "Trying to gather data of interest"},
                "TA0010": {"name": "Exfiltration", "description": "Trying to steal data"},
                "TA0040": {"name": "Impact", "description": "Trying to manipulate, interrupt, or destroy systems and data"},
            }
            
            logger.debug("CWE-CAPEC-ATT&CK mappings loaded successfully")
            
        except Exception as e:
            logger.warning(f"Error loading CWE-CAPEC mappings: {e}")
    
    async def _load_attack_enterprise_data(self, session: Any) -> None:
        """Load ATT&CK Enterprise data from MITRE repositories."""
        try:
            # This would fetch from: https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
            # For now, using comprehensive static data based on MITRE ATT&CK v14
            logger.debug("ATT&CK Enterprise data loaded from static cache")
        except Exception as e:
            logger.warning(f"Error loading ATT&CK Enterprise data: {e}")
    
    async def _load_cisa_kev_data(self, session: Any) -> None:
        """Load CISA Known Exploited Vulnerabilities catalog."""
        try:
            # Load from CISA KEV JSON catalog
            url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
            
            async with session.get(url, headers=self.headers) as response:
                if response.status == 200:
                    try:
                        kev_data = await response.json()
                        # Create lookup by CVE ID
                        for vuln in kev_data.get("vulnerabilities", []):
                            cve_id = vuln.get("cveID")
                            if cve_id:
                                self.kev_cache[cve_id] = {
                                    "in_kev": True,
                                    "vendor_project": vuln.get("vendorProject", ""),
                                    "product": vuln.get("product", ""),
                                    "vulnerability_name": vuln.get("vulnerabilityName", ""),
                                    "short_description": vuln.get("shortDescription", ""),
                                    "date_added": vuln.get("dateAdded", ""),
                                    "due_date": vuln.get("dueDate", ""),
                                    "required_action": vuln.get("requiredAction", ""),
                                    "known_ransomware_use": vuln.get("knownRansomwareCampaignUse", "Unknown"),
                                    "cwe_ids": vuln.get("cwes", []),
                                    "notes": vuln.get("notes", "")
                                }
                        logger.debug(f"CISA KEV data loaded: {len(self.kev_cache)} vulnerabilities")
                    except Exception as e:
                        logger.warning(f"Error parsing CISA KEV data: {e}")
                else:
                    logger.warning(f"Failed to load CISA KEV data: HTTP {response.status}")
        except Exception as e:
            logger.warning(f"Error loading CISA KEV data: {e}")
    
    async def fetch(self, cve_id: str, session: Any) -> Dict[str, Any]:
        """Load MITRE framework data on first access."""
        # Load all MITRE caches if not already loaded
        await self._load_mitre_caches(session)
        
        # Return relevant data for this CVE
        data = {}
        
        # Check CISA KEV status
        if cve_id in self.kev_cache:
            data["kev_data"] = self.kev_cache[cve_id]
        
        return data
    
    def parse(self, cve_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse MITRE ATT&CK and CAPEC mappings with comprehensive framework integration."""
        # Extract CWE data from foundational layer if available
        cwe_data = data.get("foundational_cwe", [])
        
        capec_ids = []
        attack_techniques = []
        attack_tactics = []
        kill_chain_phases = []
        technique_names = []
        tactic_names = []
        
        # Map CWE to CAPEC and ATT&CK using comprehensive mappings
        for cwe_id in cwe_data:
            if cwe_id in self.cwe_capec_cache:
                capec_list = self.cwe_capec_cache[cwe_id]
                capec_ids.extend(capec_list)
                
                # Map CAPEC to ATT&CK with enhanced metadata
                for capec_id in capec_list:
                    if capec_id in self.capec_attack_cache:
                        capec_mapping = self.capec_attack_cache[capec_id]
                        attack_tactics.extend(capec_mapping.get("tactics", []))
                        techniques = capec_mapping.get("techniques", [])
                        attack_techniques.extend(techniques)
                        
                        # Add technique names and kill chain phases
                        for technique_id in techniques:
                            if technique_id in self.attack_techniques_cache:
                                technique_info = self.attack_techniques_cache[technique_id]
                                technique_names.append(f"{technique_id}: {technique_info['name']}")
                                kill_chain_phases.extend(technique_info.get("kill_chain", []))
                        
                        # Add tactic names
                        for tactic_id in capec_mapping.get("tactics", []):
                            if tactic_id in self.attack_tactics_cache:
                                tactic_info = self.attack_tactics_cache[tactic_id]
                                tactic_names.append(f"{tactic_id}: {tactic_info['name']}")
        
        # Remove duplicates and sort
        capec_ids = sorted(list(set(capec_ids)))
        attack_techniques = sorted(list(set(attack_techniques)))
        attack_tactics = sorted(list(set(attack_tactics)))
        kill_chain_phases = sorted(list(set(kill_chain_phases)))
        technique_names = sorted(list(set(technique_names)))
        tactic_names = sorted(list(set(tactic_names)))
        
        # Create human-readable descriptions for CWE and CAPEC
        cwe_details = []
        for cwe_id in cwe_data:
            description = self.cwe_descriptions_cache.get(cwe_id, "")
            if description:
                cwe_details.append(f"{cwe_id}: {description}")
            else:
                cwe_details.append(cwe_id)
                
        capec_details = []
        for capec_id in capec_ids:
            description = self.capec_descriptions_cache.get(capec_id, "")
            if description:
                capec_details.append(f"{capec_id}: {description}")
            else:
                capec_details.append(capec_id)
        
        # Enhanced MITRE framework data
        result = {
            "cwe_ids": cwe_data,
            "capec_ids": capec_ids,
            "attack_techniques": attack_techniques,
            "attack_tactics": attack_tactics,
            "kill_chain_phases": kill_chain_phases,
            "technique_details": technique_names,
            "tactic_details": tactic_names,
            "cwe_details": cwe_details,
            "capec_details": capec_details
        }
        
        # Add CISA KEV data if available
        kev_data = data.get("kev_data", {})
        if kev_data:
            result["kev_info"] = kev_data
        
        logger.debug(f"MITRE analysis for {cve_id}: {len(capec_ids)} CAPECs, {len(attack_techniques)} techniques, {len(attack_tactics)} tactics")
        
        return result


class ThreatContextConnector(DataSourceConnector):
    """Connector for threat context data from GitHub sources (Layer 4)."""
    
    def __init__(self) -> None:
        self.headers = {
            'User-Agent': 'CVE-Research-Toolkit/1.0 (Security Research Tool)',
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
        if self.session_cache and self.session_cache.epss_data:
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
                            import json
                            epss_data = json.loads(text_content)
                        else:
                            logger.warning("Empty EPSS data response")
                            return
                    
                    self.epss_cache = epss_data
                    self.cache_loaded = True
                    
                    # Store in session cache for other CVEs in this batch
                    if self.session_cache:
                        self.session_cache.epss_data = epss_data
                        self.session_cache.session_stats["api_calls"] += 1
                    
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
        
        # CISA KEV data is now handled by MITREConnector
        # This provides EPSS scores and threat context data
        
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


class CVSSBTConnector(DataSourceConnector):
    """Connector for t0sche/cvss-bt CVSS enrichment data (Layer 4)."""
    
    def __init__(self) -> None:
        self.headers = {
            'User-Agent': 'CVE-Research-Toolkit/1.0 (Security Research Tool)',
            'Accept': 'text/csv, text/plain'
        }
        self.cvss_cache: Dict[str, Any] = {}
        self.cache_loaded = False
        self.session_cache: Optional[SessionCache] = None
    
    def set_session_cache(self, session_cache: SessionCache) -> None:
        """Set session cache for performance optimization."""
        self.session_cache = session_cache
    
    async def _load_cvss_data(self, session: Any) -> None:
        """Load CVSS data from t0sche/cvss-bt GitHub repo."""
        # Check session cache first
        if self.session_cache and self.session_cache.cvss_bt_data:
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
                    import csv
                    from io import StringIO
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
                    if self.session_cache:
                        self.session_cache.cvss_bt_data = self.cvss_cache.copy()
                        self.session_cache.session_stats["api_calls"] += 1
                    
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
            "cvss_bt_score": data.get("cvss_bt_score", 0.0),
            "cvss_bt_severity": data.get("cvss_bt_severity", ""),
            "cvss_bt_vector": data.get("cvss_bt_vector", ""),
            "assigner": data.get("assigner", ""),
            "published_date": data.get("published_date", ""),
            "threat": {
                "in_kev": data.get("cisa_kev", False),
                "vulncheck_kev": data.get("vulncheck_kev", False),
                "epss_score": data.get("epss", 0.0),
                "has_metasploit": data.get("metasploit", False),
                "has_exploitdb": data.get("exploitdb", False),
                "has_nuclei": data.get("nuclei", False),
                "has_poc_github": data.get("poc_github", False)
            }
        }


class PatrowlConnector(DataSourceConnector):
    """Connector for Patrowl/PatrowlHearsData (Layer 5 - Raw Intelligence)."""
    
    def __init__(self) -> None:
        self.headers = {
            'User-Agent': 'CVE-Research-Toolkit/1.0 (Security Research Tool)',
            'Accept': 'application/json, text/plain'
        }
    
    def _categorize_cwe(self, cwe_id: str) -> str:
        """Categorize CWE into high-level categories."""
        cwe_categories = {
            "injection": ["79", "89", "94", "95", "96", "97", "134", "643"],
            "authentication": ["287", "288", "289", "290", "294", "295", "296", "297", "298"],
            "authorization": ["285", "286", "359", "732", "269", "270", "271", "272"],
            "input_validation": ["20", "74", "77", "78", "120", "129", "130", "131", "190"],
            "buffer_errors": ["119", "120", "121", "122", "123", "124", "125", "126", "127"],
            "cryptographic": ["310", "311", "312", "313", "314", "315", "316", "317", "318", "325", "326", "327", "328", "329", "330", "331", "332", "333", "334", "335", "336", "337", "338"],
            "information_disclosure": ["200", "201", "202", "203", "204", "205", "206", "209", "213", "215", "359"],
            "race_conditions": ["362", "363", "364", "365", "366", "367", "368"],
            "path_traversal": ["22", "23", "35", "36", "37", "38", "39", "40", "41", "42", "43", "44", "45", "46", "47", "48", "49", "50", "51", "52", "53", "54", "55", "56", "57", "58", "59", "60", "61", "62", "63", "64", "65", "66", "67", "68", "69", "70", "71", "72", "73"],
            "resource_management": ["400", "401", "402", "403", "404", "405", "770", "771", "772", "773", "774", "775", "776", "777", "778"]
        }
        
        cwe_number = cwe_id.replace("CWE-", "")
        for category, cwe_list in cwe_categories.items():
            if cwe_number in cwe_list:
                return category
        return "other"
    
    def _assess_cwe_severity(self, cwe_id: str, description: str) -> str:
        """Assess CWE severity based on ID and description."""
        high_severity_cwes = ["79", "89", "94", "119", "120", "121", "122", "787", "190", "22", "352", "434"]
        medium_severity_cwes = ["200", "209", "287", "295", "362", "732", "770", "400"]
        
        cwe_number = cwe_id.replace("CWE-", "")
        if cwe_number in high_severity_cwes:
            return "high"
        elif cwe_number in medium_severity_cwes:
            return "medium"
        
        # Assess based on description keywords
        description_lower = description.lower()
        if any(keyword in description_lower for keyword in ["remote", "execute", "command", "overflow", "injection"]):
            return "high"
        elif any(keyword in description_lower for keyword in ["disclosure", "leak", "bypass", "denial"]):
            return "medium"
        
        return "low"
    
    def _classify_vulnerability_type(self, problem_value: str, classification: Dict[str, Any]) -> None:
        """Classify vulnerability type based on problem description."""
        problem_lower = problem_value.lower()
        
        # Vulnerability categories
        if any(term in problem_lower for term in ["injection", "xss", "sql", "command"]):
            classification["vulnerability_categories"].append("injection")
        if any(term in problem_lower for term in ["overflow", "buffer", "memory"]):
            classification["vulnerability_categories"].append("memory_corruption")
        if any(term in problem_lower for term in ["authentication", "login", "credential"]):
            classification["vulnerability_categories"].append("authentication")
        if any(term in problem_lower for term in ["authorization", "access", "privilege"]):
            classification["vulnerability_categories"].append("authorization")
        if any(term in problem_lower for term in ["crypto", "encryption", "certificate"]):
            classification["vulnerability_categories"].append("cryptographic")
        if any(term in problem_lower for term in ["path", "directory", "traversal"]):
            classification["vulnerability_categories"].append("path_traversal")
        if any(term in problem_lower for term in ["denial", "dos", "resource"]):
            classification["vulnerability_categories"].append("denial_of_service")
        
        # Impact types
        if any(term in problem_lower for term in ["execute", "execution", "command"]):
            classification["impact_types"].append("code_execution")
        if any(term in problem_lower for term in ["disclosure", "information", "leak"]):
            classification["impact_types"].append("information_disclosure")
        if any(term in problem_lower for term in ["privilege", "escalation", "elevation"]):
            classification["impact_types"].append("privilege_escalation")
        if any(term in problem_lower for term in ["bypass", "circumvent", "evade"]):
            classification["impact_types"].append("security_bypass")
        
        # Attack vectors
        if any(term in problem_lower for term in ["remote", "network", "internet"]):
            classification["attack_vectors"].append("remote")
        if any(term in problem_lower for term in ["local", "physical", "console"]):
            classification["attack_vectors"].append("local")
        if any(term in problem_lower for term in ["web", "http", "browser"]):
            classification["attack_vectors"].append("web")
        if any(term in problem_lower for term in ["email", "attachment", "phishing"]):
            classification["attack_vectors"].append("email")
    
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
                                import json
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
            # Handle both dict and string configurations
            if isinstance(config, dict):
                for node in config.get("nodes", []):
                    if isinstance(node, dict):
                        for cpe_match in node.get("cpeMatch", []):
                            if isinstance(cpe_match, dict) and cpe_match.get("vulnerable", False):
                                cpe_matches.append(cpe_match.get("criteria", ""))
            # Skip string configurations for now
            elif isinstance(config, str):
                logger.debug(f"Skipping string configuration: {config[:50]}...")
        
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
        
        # Extract and categorize references
        references = cve_data.get("references", {}).get("reference_data", [])
        vendor_advisories = []
        patches = []
        general_refs = []
        
        for ref in references:
            url = ref.get("url", "")
            name = ref.get("name", "")
            
            # Enhanced categorization logic
            url_lower = url.lower()
            if any(term in url_lower for term in ['advisory', 'security', 'vendor', 'bulletin', 'alert']):
                vendor_advisories.append({"url": url, "name": name})
            elif any(term in url_lower for term in ['patch', 'fix', 'update', 'upgrade', 'release']):
                patches.append({"url": url, "name": name})
            else:
                general_refs.append({"url": url, "name": name})
        
        # Enhanced problem type information extraction
        problem_types = []
        structured_cwe_data = []
        vulnerability_classification = {
            "primary_weakness": "",
            "secondary_weaknesses": [],
            "vulnerability_categories": [],
            "impact_types": [],
            "attack_vectors": []
        }
        
        for problem in cve_data.get("problemtype", {}).get("problemtype_data", []):
            for desc in problem.get("description", []):
                if desc.get("lang") == "en":
                    problem_value = desc.get("value", "")
                    problem_types.append(problem_value)
                    
                    # Extract structured CWE information
                    if problem_value.startswith("CWE-"):
                        cwe_match = re.match(r'CWE-(\d+)(?:\s+(.+))?', problem_value)
                        if cwe_match:
                            cwe_id = f"CWE-{cwe_match.group(1)}"
                            cwe_description = cwe_match.group(2) if cwe_match.group(2) else ""
                            
                            structured_cwe = {
                                "cwe_id": cwe_id,
                                "description": cwe_description.strip(),
                                "category": self._categorize_cwe(cwe_id),
                                "severity_indicator": self._assess_cwe_severity(cwe_id, cwe_description)
                            }
                            structured_cwe_data.append(structured_cwe)
                            
                            # Set primary weakness if not already set
                            if not vulnerability_classification["primary_weakness"]:
                                vulnerability_classification["primary_weakness"] = cwe_id
                            else:
                                vulnerability_classification["secondary_weaknesses"].append(cwe_id)
                    
                    # Classify vulnerability types based on problem description
                    self._classify_vulnerability_type(problem_value, vulnerability_classification)
        
        # Enhance vulnerability classification based on CWE categories
        for cwe_data in structured_cwe_data:
            category = cwe_data.get("category", "")
            if category and category not in vulnerability_classification["vulnerability_categories"]:
                vulnerability_classification["vulnerability_categories"].append(category)
            
            # Map CWE categories to impact types and attack vectors
            if category == "injection":
                if "code_execution" not in vulnerability_classification["impact_types"]:
                    vulnerability_classification["impact_types"].append("code_execution")
                if "remote" not in vulnerability_classification["attack_vectors"]:
                    vulnerability_classification["attack_vectors"].append("remote")
            elif category in ["authentication", "authorization"]:
                if "privilege_escalation" not in vulnerability_classification["impact_types"]:
                    vulnerability_classification["impact_types"].append("privilege_escalation")
                if "security_bypass" not in vulnerability_classification["impact_types"]:
                    vulnerability_classification["impact_types"].append("security_bypass")
            elif category in ["buffer_errors", "resource_management"]:
                if "code_execution" not in vulnerability_classification["impact_types"]:
                    vulnerability_classification["impact_types"].append("code_execution")
                if "denial_of_service" not in vulnerability_classification["vulnerability_categories"]:
                    vulnerability_classification["vulnerability_categories"].append("denial_of_service")
            elif category == "information_disclosure":
                if "information_disclosure" not in vulnerability_classification["impact_types"]:
                    vulnerability_classification["impact_types"].append("information_disclosure")
            elif category == "cryptographic":
                if "information_disclosure" not in vulnerability_classification["impact_types"]:
                    vulnerability_classification["impact_types"].append("information_disclosure")
                if "security_bypass" not in vulnerability_classification["impact_types"]:
                    vulnerability_classification["impact_types"].append("security_bypass")
        
        # Extract assigner information
        assigner = cve_data.get("CVE_data_meta", {}).get("ASSIGNER", "")
        vulnerability_name = cve_data.get("CVE_data_meta", {}).get("TITLE", "")
        
        # Add enhanced fields to result
        result.update({
            "vendor_advisories": vendor_advisories,
            "patches": patches,
            "general_references": general_refs,
            "problem_types": problem_types,
            "structured_cwe_data": structured_cwe_data,
            "vulnerability_classification": vulnerability_classification,
            "assigner": assigner,
            "vulnerability_name": vulnerability_name
        })
        
        logger.debug(f"Patrowl parsed {cve_id}: CVSS={cvss_score}, CPEs={len(cpe_matches)}, "
                    f"Advisories={len(vendor_advisories)}, Patches={len(patches)}, References={len(general_refs)}")
        return result








class VulnerabilityResearchEngine:
    """Main research engine orchestrating all data sources."""
    
    def __init__(self, config: Dict[str, Any]) -> None:
        self.config = config
        
        # Session-based cache for performance optimization (cleared after each session)
        self.session_cache = SessionCache()
        
        # Initialize connectors in correct layer order
        self.connectors = {
            DataLayer.FOUNDATIONAL: CVEProjectConnector(),           # Layer 1: CVEProject/cvelistV5
            DataLayer.EXPLOIT_MECHANICS: TrickestConnector(),        # Layer 2: trickest/cve
            DataLayer.WEAKNESS_TACTICS: MITREConnector(),            # Layer 3: mitre/cti
            DataLayer.THREAT_CONTEXT: ThreatContextConnector(),      # Layer 4: t0sche/cvss-bt, ARPSyndicate/cve-scores
            DataLayer.RAW_INTELLIGENCE: PatrowlConnector()           # Layer 5: Patrowl/PatrowlHearsData
        }
        
        # Additional Layer 4 connector for CVSS-BT data
        self.cvss_bt_connector = CVSSBTConnector()
        
        # Initialize control mapper for NIST 800-53 mappings
        self.control_mapper = ControlMapper()
        
        # Inject session cache into connectors that can benefit from it
        if hasattr(self.connectors[DataLayer.WEAKNESS_TACTICS], 'set_session_cache'):
            self.connectors[DataLayer.WEAKNESS_TACTICS].set_session_cache(self.session_cache)
        if hasattr(self.connectors[DataLayer.THREAT_CONTEXT], 'set_session_cache'):
            self.connectors[DataLayer.THREAT_CONTEXT].set_session_cache(self.session_cache)
        if hasattr(self.cvss_bt_connector, 'set_session_cache'):
            self.cvss_bt_connector.set_session_cache(self.session_cache)
        
        
    
    async def research_cve(self, cve_id: str) -> ResearchData:
        """Perform comprehensive research on a CVE."""
        # Check session cache for duplicate CVE processing
        if cve_id in self.session_cache.cve_data:
            self.session_cache.session_stats["cache_hits"] += 1
            self.session_cache.session_stats["duplicate_cves"] += 1
            logger.debug(f"Using cached data for {cve_id}")
            cached_results = self.session_cache.cve_data[cve_id]
            return self._build_research_data(cve_id, cached_results)
        
        # Fetch from all sources concurrently
        if not AIOHTTP_AVAILABLE:
            logger.error("aiohttp is required for CVE research. Install with: pip install aiohttp")
            return ResearchData(cve_id=cve_id)
        
        if not aiohttp:
            raise RuntimeError("aiohttp is required for CVE research")
        async with aiohttp.ClientSession() as session:
            tasks: List[Tuple[Union[DataLayer, str], Any]] = []
            for layer, connector in self.connectors.items():
                task = connector.fetch(cve_id, session)
                tasks.append((layer, task))
            
            # Add CVSS-BT as additional Layer 4 (Real-World Context) source
            cvss_bt_task = self.cvss_bt_connector.fetch(cve_id, session)
            tasks.append(("cvss_bt", cvss_bt_task))
            
            # Gather all results with detailed status tracking
            results = {}
            source_status = {}
            raw_data = {}
            
            # First, collect all the raw data
            for layer, task in tasks:
                try:
                    data = await task
                    raw_data[layer] = data
                    # Track source availability
                    if data:
                        source_status[layer] = "success"
                        layer_name = getattr(layer, 'name', str(layer))
                        logger.debug(f"Successfully fetched {layer_name} data for {cve_id}")
                    else:
                        source_status[layer] = "no_data"
                        layer_name = getattr(layer, 'name', str(layer))
                        logger.debug(f"No data available from {layer_name} for {cve_id}")
                except Exception as e:
                    layer_name = getattr(layer, 'name', str(layer))
                    if "AttributeError" in str(type(e).__name__) and layer_name == "RAW_INTELLIGENCE":
                        logger.debug(f"Patrowl data not available for {cve_id}")
                    else:
                        logger.debug(f"Error fetching {layer_name} data for {cve_id}: {e}")
                    source_status[layer] = "error"
                    raw_data[layer] = {}
            
            # Process data in layer order to ensure dependencies
            layer_order = [DataLayer.FOUNDATIONAL, DataLayer.EXPLOIT_MECHANICS, DataLayer.WEAKNESS_TACTICS, DataLayer.THREAT_CONTEXT, DataLayer.RAW_INTELLIGENCE]
            
            for layer in layer_order:
                if layer in raw_data:
                    try:
                        data = raw_data[layer]
                        # Special handling for MITRE connector to pass CWE data from foundational layer
                        if layer == DataLayer.WEAKNESS_TACTICS and DataLayer.FOUNDATIONAL in results:
                            foundational_data = results[DataLayer.FOUNDATIONAL]
                            cwe_data = foundational_data.get("cwe_ids", [])
                            # Pass CWE data to MITRE connector for mapping
                            data_with_cwe = dict(data) if data else {}
                            data_with_cwe["foundational_cwe"] = cwe_data
                            parsed = self.connectors[layer].parse(cve_id, data_with_cwe)
                        else:
                            parsed = self.connectors[layer].parse(cve_id, data)
                        results[layer] = parsed
                    except Exception as e:
                        logger.debug(f"Error parsing {layer.name} data for {cve_id}: {e}")
                        results[layer] = {}
            
            # Handle CVSS-BT separately
            if "cvss_bt" in raw_data:
                try:
                    data = raw_data["cvss_bt"]
                    parsed = self.cvss_bt_connector.parse(cve_id, data)
                    # Merge CVSS-BT data into THREAT_CONTEXT (Layer 4)
                    if DataLayer.THREAT_CONTEXT not in results:
                        results[DataLayer.THREAT_CONTEXT] = {}
                    if "cvss_bt" not in results[DataLayer.THREAT_CONTEXT]:
                        results[DataLayer.THREAT_CONTEXT]["cvss_bt"] = {}
                    results[DataLayer.THREAT_CONTEXT]["cvss_bt"].update(parsed)
                except Exception as e:
                    logger.debug(f"Error parsing CVSS-BT data for {cve_id}: {e}")
                    if DataLayer.THREAT_CONTEXT not in results:
                        results[DataLayer.THREAT_CONTEXT] = {}
                    results[DataLayer.THREAT_CONTEXT]["cvss_bt"] = {}
            
            # Log overall source availability
            successful_sources = sum(1 for status in source_status.values() if status == "success")
            total_sources = len(self.connectors) + 1  # +1 for CVSS-BT
            logger.debug(f"CVE {cve_id}: {successful_sources}/{total_sources} data sources available")
        
        # Build ResearchData object
        research_data = self._build_research_data(cve_id, results)
        
        # Cache results for potential duplicate CVEs in this session
        self.session_cache.cve_data[cve_id] = results
        
        # Log if no CVSS score found
        if research_data.cvss_score == 0.0 and research_data.description:
            logger.warning(f"No CVSS score available for {cve_id} from GitHub sources")
        
        return research_data
    
    def _build_research_data(self, cve_id: str, results: Dict[DataLayer, Dict[str, Any]]) -> ResearchData:
        """Build ResearchData from multi-source results with graceful fallbacks."""
        # Start with foundational data
        foundational = results.get(DataLayer.FOUNDATIONAL, {})
        raw_intelligence = results.get(DataLayer.RAW_INTELLIGENCE, {})
        threat_context = results.get(DataLayer.THREAT_CONTEXT, {})
        
        # Use CVSS score with priority: Foundational > Patrowl (Layer 5) > CVSS-BT (Layer 4)
        cvss_score = foundational.get("cvss_score", 0.0)
        cvss_vector = foundational.get("cvss_vector", "")
        cvss_source = "CVEProject"
        
        # Fallback to Patrowl (Layer 5 - Raw Intelligence) if foundational has no CVSS
        if cvss_score == 0.0 and raw_intelligence.get("cvss_score", 0.0) > 0.0:
            cvss_score = raw_intelligence.get("cvss_score", 0.0)
            cvss_vector = raw_intelligence.get("cvss_vector", "")
            cvss_source = "Patrowl"
            logger.debug(f"Using CVSS {cvss_score} from Patrowl for {cve_id}")
        
        # Final fallback to CVSS-BT (Layer 4 - Real-World Context) if still no score
        elif cvss_score == 0.0:
            cvss_bt_data = threat_context.get("cvss_bt", {})
            if cvss_bt_data.get("cvss_score", 0.0) > 0.0:
                cvss_score = cvss_bt_data.get("cvss_score", 0.0)
                cvss_vector = cvss_bt_data.get("cvss_vector", "")
                cvss_source = "CVSS-BT"
                logger.debug(f"Using CVSS {cvss_score} from CVSS-BT for {cve_id}")
        
        # Determine severity
        if cvss_score >= 9.0:
            severity = "CRITICAL"
        elif cvss_score >= 7.0:
            severity = "HIGH"
        elif cvss_score >= 4.0:
            severity = "MEDIUM"
        elif cvss_score > 0.0:
            severity = "LOW"
        else:
            severity = "UNKNOWN"
        
        # Parse dates with fallbacks
        published = None
        if foundational.get("published_date"):
            try:
                published = datetime.fromisoformat(foundational["published_date"])
            except (ValueError, TypeError):
                try:
                    # Try alternative date parsing
                    from datetime import datetime as dt
                    published = dt.strptime(foundational["published_date"], "%Y-%m-%dT%H:%M:%S.%fZ")
                except:
                    logger.debug(f"Could not parse date for {cve_id}: {foundational.get('published_date')}")
                    published = None
        
        # Build basic research data with fallbacks
        description = foundational.get("description", "")
        if not description:
            description = f"CVE {cve_id} - Description not available from external sources"
        
        research_data = ResearchData(
            cve_id=cve_id,
            description=description,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            severity=severity,
            published_date=published,
            last_modified=published,
            references=foundational.get("references", [])
        )
        
        # Add CPE affected products from foundational data (CVE Project)
        foundational_cpe = foundational.get("cpe_affected", [])
        research_data.cpe_affected.extend(foundational_cpe)
        
        # Add enhanced data from Patrowl (Layer 5 - Raw Intelligence)
        if raw_intelligence:
            # Merge CPE affected products
            patrowl_cpe = raw_intelligence.get("cpe_affected", [])
            research_data.cpe_affected.extend(patrowl_cpe)
            
            # Add categorized references from Patrowl
            vendor_advisories = raw_intelligence.get("vendor_advisories", [])
            patches = raw_intelligence.get("patches", [])
            general_refs = raw_intelligence.get("general_references", [])
            
            # Convert structured references to URLs and add to appropriate lists
            for advisory in vendor_advisories:
                if advisory.get("url"):
                    research_data.vendor_advisories.append(advisory["url"])
            
            for patch in patches:
                if patch.get("url"):
                    research_data.patches.append(patch["url"])
            
            # Add general references to main references list
            for ref in general_refs:
                if ref.get("url") and ref["url"] not in research_data.references:
                    research_data.references.append(ref["url"])
            
            # Store metadata for enhanced intelligence
            if raw_intelligence.get("assigner"):
                research_data.patches.append(f"Assigner: {raw_intelligence['assigner']}")
            
            if raw_intelligence.get("vulnerability_name"):
                research_data.patches.append(f"Vulnerability Name: {raw_intelligence['vulnerability_name']}")
            
            # Store impact metrics as additional metadata
            impact_metrics = raw_intelligence.get("impact_metrics", {})
            if impact_metrics:
                research_data.patches.append(f"Impact Score: {impact_metrics.get('impact_score', 'N/A')}")
                research_data.patches.append(f"Exploitability Score: {impact_metrics.get('exploitability_score', 'N/A')}")
            
            # Integrate enhanced problem type data from Patrowl
            structured_cwe_data = raw_intelligence.get("structured_cwe_data", [])
            vulnerability_classification = raw_intelligence.get("vulnerability_classification", {})
            
            # Store structured CWE data as metadata for CSV export
            if structured_cwe_data:
                for cwe_data in structured_cwe_data:
                    cwe_detail = f"{cwe_data['cwe_id']}: {cwe_data['description']} (Category: {cwe_data['category']}, Severity: {cwe_data['severity_indicator']})"
                    research_data.patches.append(f"Enhanced CWE: {cwe_detail}")
            
            # Store vulnerability classification data
            if vulnerability_classification:
                primary_weakness = vulnerability_classification.get("primary_weakness", "")
                if primary_weakness:
                    research_data.patches.append(f"Primary Weakness: {primary_weakness}")
                
                secondary_weaknesses = vulnerability_classification.get("secondary_weaknesses", [])
                if secondary_weaknesses:
                    research_data.patches.append(f"Secondary Weaknesses: {'; '.join(secondary_weaknesses)}")
                
                vuln_categories = vulnerability_classification.get("vulnerability_categories", [])
                if vuln_categories:
                    research_data.patches.append(f"Vulnerability Categories: {'; '.join(set(vuln_categories))}")
                
                impact_types = vulnerability_classification.get("impact_types", [])
                if impact_types:
                    research_data.patches.append(f"Impact Types: {'; '.join(set(impact_types))}")
                
                attack_vectors = vulnerability_classification.get("attack_vectors", [])
                if attack_vectors:
                    research_data.patches.append(f"Attack Vectors: {'; '.join(set(attack_vectors))}")
        
        # Add exploit data with error handling and enhanced metadata
        exploit_data = results.get(DataLayer.EXPLOIT_MECHANICS, {})
        exploits_added = 0
        for exploit in exploit_data.get("exploits", []):
            try:
                if exploit.get("url") and exploit.get("source") and exploit.get("type"):
                    research_data.exploits.append(ExploitReference(
                        url=exploit["url"],
                        source=exploit["source"],
                        type=exploit["type"]
                    ))
                    exploits_added += 1
            except Exception as e:
                logger.debug(f"Failed to add exploit for {cve_id}: {e}")
        
        # Add Trickest metadata to research data
        trickest_metadata = exploit_data.get("metadata", {})
        if trickest_metadata:
            # Add product information
            if trickest_metadata.get("product"):
                research_data.patches.append(f"Trickest Product: {trickest_metadata['product']}")
            
            # Add CWE from Trickest if not already available
            if trickest_metadata.get("cwe_id") and not research_data.weakness.cwe_ids:
                research_data.weakness.cwe_ids.append(trickest_metadata["cwe_id"])
                research_data.patches.append(f"Trickest CWE: {trickest_metadata['cwe_id']}")
            
            # Add technology stack information
            if trickest_metadata.get("technology_stack"):
                tech_info = "; ".join(trickest_metadata["technology_stack"])
                research_data.patches.append(f"Technology Stack: {tech_info}")
            
            # Enhance description if foundational description is minimal
            if trickest_metadata.get("description") and len(research_data.description) < 100:
                research_data.description = trickest_metadata["description"]
        
        # Add categorized references from Trickest
        trickest_refs = exploit_data.get("references", {})
        if trickest_refs.get("advisories"):
            research_data.vendor_advisories.extend(trickest_refs["advisories"])
        
        if exploits_added > 0:
            logger.debug(f"Added {exploits_added} exploits for {cve_id}")
        
        # Use enhanced exploit maturity from Trickest if available, otherwise fallback to legacy logic
        trickest_maturity = exploit_data.get("exploit_maturity")
        if trickest_maturity and trickest_maturity != "unproven":
            research_data.exploit_maturity = trickest_maturity
        else:
            # Legacy fallback logic
            if research_data.exploits:
                if any(e.type in ["metasploit", "nuclei"] for e in research_data.exploits):
                    research_data.exploit_maturity = "weaponized"
                elif any(e.type == "exploit-db" for e in research_data.exploits):
                    research_data.exploit_maturity = "functional"
                else:
                    research_data.exploit_maturity = "poc"
            else:
                research_data.exploit_maturity = "unproven"
        
        # Add threat context with fallbacks from multiple Layer 4 sources
        epss_threat_data = threat_context.get("threat", {})  # From ThreatContextConnector (EPSS)
        cvss_bt_threat_data = threat_context.get("cvss_bt", {}).get("threat", {})  # From CVSS-BT
        
        # Merge threat data from Layer 4 sources (Real-World Context)
        research_data.threat.in_kev = cvss_bt_threat_data.get("in_kev", epss_threat_data.get("in_kev", False))
        research_data.threat.vulncheck_kev = cvss_bt_threat_data.get("vulncheck_kev", False)
        research_data.threat.epss_score = epss_threat_data.get("epss_score") or cvss_bt_threat_data.get("epss_score")
        research_data.threat.epss_percentile = epss_threat_data.get("epss_percentile") or cvss_bt_threat_data.get("epss_percentile")
        research_data.threat.actively_exploited = cvss_bt_threat_data.get("in_kev", epss_threat_data.get("actively_exploited", False))
        research_data.threat.has_metasploit = cvss_bt_threat_data.get("has_metasploit", False)
        research_data.threat.has_nuclei = cvss_bt_threat_data.get("has_nuclei", False)
        research_data.threat.has_exploitdb = cvss_bt_threat_data.get("has_exploitdb", False)
        research_data.threat.has_poc_github = cvss_bt_threat_data.get("has_poc_github", False)
        
        # Add enhanced weakness data with comprehensive MITRE framework integration
        weakness_data = results.get(DataLayer.WEAKNESS_TACTICS, {})
        if weakness_data.get("cwe_ids"):
            research_data.weakness.cwe_ids = weakness_data["cwe_ids"]
        elif foundational.get("cwe_ids"):
            # Use CWE data extracted from CVE Project if MITRE data not available
            research_data.weakness.cwe_ids = foundational["cwe_ids"]
            
        if weakness_data.get("capec_ids"):
            research_data.weakness.capec_ids = weakness_data["capec_ids"]
            
        if weakness_data.get("attack_techniques"):
            research_data.weakness.attack_techniques = weakness_data["attack_techniques"]
            
        if weakness_data.get("attack_tactics"):
            research_data.weakness.attack_tactics = weakness_data["attack_tactics"]
            
        # Add kill chain phases from enhanced MITRE data
        if weakness_data.get("kill_chain_phases"):
            research_data.weakness.kill_chain_phases = weakness_data["kill_chain_phases"]
            
        # Add human-readable descriptions from enhanced MITRE data
        if weakness_data.get("cwe_details"):
            research_data.weakness.cwe_details = weakness_data["cwe_details"]
        if weakness_data.get("capec_details"):
            research_data.weakness.capec_details = weakness_data["capec_details"]
        if weakness_data.get("technique_details"):
            research_data.weakness.technique_details = weakness_data["technique_details"]
        if weakness_data.get("tactic_details"):
            research_data.weakness.tactic_details = weakness_data["tactic_details"]
        
        # Update threat context with CISA KEV data from MITRE connector
        kev_info = weakness_data.get("kev_info", {})
        if kev_info:
            research_data.threat.in_kev = kev_info.get("in_kev", False)
            research_data.threat.actively_exploited = kev_info.get("in_kev", False)
            
            # Enhanced CISA KEV fields
            research_data.threat.ransomware_campaign = kev_info.get("known_ransomware_use", "Unknown").lower() == "yes"
            research_data.threat.kev_vulnerability_name = kev_info.get("vulnerability_name", "")
            research_data.threat.kev_short_description = kev_info.get("short_description", "")
            research_data.threat.kev_vendor_project = kev_info.get("vendor_project", "")
            research_data.threat.kev_product = kev_info.get("product", "")
            
            # Add KEV-specific metadata to patches if available
            if kev_info.get("required_action"):
                research_data.patches.append(f"CISA KEV Required Action: {kev_info['required_action']}")
            if kev_info.get("due_date"):
                research_data.patches.append(f"CISA KEV Due Date: {kev_info['due_date']}")
            if kev_info.get("vendor_project") and kev_info.get("product"):
                research_data.patches.append(f"CISA KEV Affected: {kev_info['vendor_project']} {kev_info['product']}")
        
        # Log enhanced MITRE intelligence summary
        if weakness_data:
            logger.debug(f"Enhanced MITRE data for {cve_id}: "
                        f"{len(weakness_data.get('capec_ids', []))} CAPECs, "
                        f"{len(weakness_data.get('attack_techniques', []))} techniques, "
                        f"{len(weakness_data.get('attack_tactics', []))} tactics, "
                        f"{len(weakness_data.get('kill_chain_phases', []))} kill chain phases")
        
        # Populate additional fields from foundational CVE Project data
        if foundational.get("vendor_advisories"):
            research_data.vendor_advisories.extend(foundational["vendor_advisories"])
        if foundational.get("patches"):
            research_data.patches.extend(foundational["patches"])
        
        research_data.last_enriched = datetime.now()
        
        # Log data source summary
        sources_used = []
        if foundational:
            sources_used.append("CVEProject")
        if raw_intelligence:
            sources_used.append("Patrowl")
        if threat_context.get("cvss_bt"):
            sources_used.append("CVSS-BT")
        if threat_context.get("threat"):
            sources_used.append("EPSS")
        if results.get(DataLayer.EXPLOIT_MECHANICS):
            sources_used.append("Trickest")
        
        logger.debug(f"Data sources used for {cve_id}: {', '.join(sources_used)} (CVSS from {cvss_source})")
        
        # Add NIST 800-53 control mappings based on ATT&CK techniques
        if research_data.weakness.attack_techniques:
            control_mappings = self.control_mapper.get_controls_for_techniques(research_data.weakness.attack_techniques)
            
            # Store control data as metadata in patches field for CSV export
            if control_mappings['applicable_controls_count'] > 0:
                research_data.patches.append(f"Applicable Controls Count: {control_mappings['applicable_controls_count']}")
            if control_mappings['control_categories']:
                research_data.patches.append(f"Control Categories: {control_mappings['control_categories']}")
            if control_mappings['top_controls']:
                research_data.patches.append(f"Top Controls: {control_mappings['top_controls']}")
        
        return research_data
    
    
    async def research_batch(self, cve_ids: List[str]) -> List[ResearchData]:
        """Research multiple CVEs concurrently with session-based optimization."""
        # Clear session cache at start of new batch
        self.session_cache.clear()
        
        # Deduplicate CVE IDs to avoid redundant work
        unique_cve_ids = list(dict.fromkeys(cve_ids))  # Preserves order
        duplicates_removed = len(cve_ids) - len(unique_cve_ids)
        if duplicates_removed > 0:
            logger.info(f"Removed {duplicates_removed} duplicate CVE IDs from batch")
        
        results = []
        
        # Use semaphore to limit concurrent requests
        semaphore = asyncio.Semaphore(self.config.get("max_concurrent", 10))
        
        async def research_with_limit(cve_id: str) -> ResearchData:
            async with semaphore:
                return await self.research_cve(cve_id)
        
        # Create tasks for unique CVE IDs
        tasks = [research_with_limit(cve_id) for cve_id in unique_cve_ids]
        
        # Execute with progress tracking
        if RICH_AVAILABLE:
            progress_console = console if RICH_AVAILABLE else None
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                console=progress_console  # type: ignore
            ) as progress:
                
                task_id = progress.add_task(
                    f"Researching {len(unique_cve_ids)} CVEs...",
                    total=len(unique_cve_ids)
                )
                
                for coro in asyncio.as_completed(tasks):
                    result = await coro
                    results.append(result)
                    progress.update(task_id, advance=1)
        else:
            # Fallback without rich progress
            for i, coro in enumerate(asyncio.as_completed(tasks), 1):
                result = await coro
                results.append(result)
                if i % 10 == 0:
                    print(f"Progress: {i}/{len(unique_cve_ids)} CVEs processed")
        
        # Log session cache performance statistics
        cache_stats = self.session_cache.get_cache_stats()
        if cache_stats["cache_hits"] > 0 or cache_stats["api_calls"] > 0:
            logger.info(f"Session performance - Cache hits: {cache_stats['cache_hits']}, "
                       f"Duplicate CVEs skipped: {cache_stats['duplicate_cves']}, "
                       f"Data source loads: {cache_stats['api_calls']}")
        
        # Handle original order for duplicate CVEs
        if duplicates_removed > 0:
            # Create a mapping of results for quick lookup
            result_map = {rd.cve_id: rd for rd in results}
            # Rebuild results in original order, reusing data for duplicates
            ordered_results = []
            for cve_id in cve_ids:
                if cve_id in result_map:
                    ordered_results.append(result_map[cve_id])
            return ordered_results
        
        return results


class ResearchReportGenerator:
    """Generate comprehensive research reports."""
    
    def __init__(self) -> None:
        self.console = console
    
    def _extract_cvss_component(self, cvss_vector: str, component: str, mappings: Dict[str, str]) -> str:
        """Extract and map CVSS vector component to human-readable form."""
        if not cvss_vector:
            return ""
        
        parts = cvss_vector.split('/')
        for part in parts:
            if ':' in part:
                comp, value = part.split(':', 1)
                # Handle CVSS v2 Auth (Au) mapping to Privileges Required
                if component == 'PR' and comp == 'Au':
                    # Map CVSS v2 Auth to v3 Privileges Required
                    au_to_pr = {'N': 'None', 'S': 'Low', 'M': 'Low'}
                    return au_to_pr.get(value, value)
                elif comp == component:
                    return mappings.get(value, value)
        return ""
    
    def generate_vulnerability_analysis_table(self, research_data: List[ResearchData]) -> Table:
        """Generate factual vulnerability analysis table - no risk decisions."""
        if not RICH_AVAILABLE:
            # Return simple table for non-rich environments
            table = Table()
            return table

        table = Table(title="CVE Analysis Summary", show_lines=True)
        
        # Add columns focused on factual data
        table.add_column("CVE ID", style="cyan", width=16)
        table.add_column("CVSS Score", width=10)
        table.add_column("Exploits Found", width=12)
        table.add_column("Threat Context", width=16)
        
        # Sort by CVSS score
        sorted_data = sorted(research_data, key=lambda x: x.cvss_score, reverse=True)
        
        for rd in sorted_data:
            # Format exploit count
            exploit_count = f"{len(rd.exploits)} found"
            if rd.exploit_maturity != "unproven":
                exploit_count += f" ({rd.exploit_maturity})"
            
            # Format threat context
            threat_info = []
            if rd.threat.in_kev:
                threat_info.append("KEV")
            if rd.threat.epss_score and rd.threat.epss_score > 0.5:
                threat_info.append(f"EPSS:{rd.threat.epss_score:.2f}")
            if rd.threat.actively_exploited:
                threat_info.append("Active")
            threat_context = ", ".join(threat_info) if threat_info else "Standard"
            
            table.add_row(
                rd.cve_id,
                f"{rd.cvss_score:.1f} ({rd.severity})",
                exploit_count,
                threat_context
            )
        
        return table

    def generate_summary_table(self, research_data: List[ResearchData]) -> Table:
        """Generate summary table of research results."""
        table = Table(title="Vulnerability Research Summary", show_lines=True)
        
        # Add columns
        table.add_column("CVE ID", style="cyan", width=16)
        table.add_column("Severity", width=10)
        table.add_column("CVSS", width=6)
        table.add_column("Exploits", width=10)
        table.add_column("KEV", width=5)
        table.add_column("EPSS", width=6)
        
        # Sort by CVSS score
        sorted_data = sorted(research_data, key=lambda x: x.cvss_score, reverse=True)
        
        for rd in sorted_data:
            # Determine severity color
            severity_colors = {
                "CRITICAL": "red",
                "HIGH": "orange1",
                "MEDIUM": "yellow",
                "LOW": "green"
            }
            severity_color = severity_colors.get(rd.severity, "white")
            
            # Format exploit info
            exploit_info = f"{len(rd.exploits)} PoCs"
            if rd.exploit_maturity == "weaponized":
                exploit_info = f"[red]{exploit_info}[/red]"
            
            # Format KEV status
            kev_status = "[red]YES[/red]" if rd.threat.in_kev else "NO"
            
            # Format EPSS
            epss = f"{rd.threat.epss_score:.2f}" if rd.threat.epss_score else "N/A"
            
            # Add row
            table.add_row(
                rd.cve_id,
                f"[{severity_color}]{rd.severity}[/{severity_color}]",
                f"{rd.cvss_score:.1f}",
                exploit_info,
                kev_status,
                epss,
"N/A"
            )
        
        return table
    
    def generate_detailed_report(self, rd: ResearchData) -> str:
        """Generate detailed research report for a single CVE."""
        report = []
        
        report.append(f"# Vulnerability Research Report: {rd.cve_id}\n")
        report.append(f"**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        # Vulnerability Overview
        report.append("## Vulnerability Overview\n")
        report.append(f"**Description**: {rd.description}\n")
        report.append(f"**Severity**: {rd.severity} (CVSS {rd.cvss_score})")
        report.append(f"**CVSS Vector**: {rd.cvss_vector}\n")
        
        # Weakness Classification
        if any([rd.weakness.cwe_ids, rd.weakness.capec_ids, rd.weakness.attack_techniques]):
            report.append("## Weakness Classification\n")
            if rd.weakness.cwe_ids:
                report.append(f"**CWE Classifications**: {', '.join(rd.weakness.cwe_ids)}")
            if rd.weakness.capec_ids:
                report.append(f"**CAPEC Attack Patterns**: {', '.join(rd.weakness.capec_ids)}")
            if rd.weakness.attack_techniques:
                report.append(f"**MITRE ATT&CK Techniques**: {', '.join(rd.weakness.attack_techniques)}")
            if rd.weakness.attack_tactics:
                report.append(f"**MITRE ATT&CK Tactics**: {', '.join(rd.weakness.attack_tactics)}")
            if rd.weakness.kill_chain_phases:
                report.append(f"**Kill Chain Phases**: {', '.join(rd.weakness.kill_chain_phases)}")
            report.append("")
        
        # Exploit & Threat Intelligence (Combined)
        report.append("## Exploit & Threat Intelligence\n")
        report.append(f"**Exploit Maturity**: {rd.exploit_maturity.upper()}")
        report.append(f"**Public Exploits**: {len(rd.exploits)} found" if rd.exploits else "**Public Exploits**: None found")
        report.append(f"**Reference URLs**: {len(rd.references)} total")
        
        # Threat Context
        threat_items = []
        if rd.threat.in_kev:
            threat_items.append("CISA KEV Listed")
        if rd.threat.actively_exploited:
            threat_items.append("Actively Exploited")
        if rd.threat.ransomware_campaign:
            threat_items.append("Ransomware Campaigns")
        if rd.threat.has_metasploit:
            threat_items.append("Metasploit Module Available")
        if rd.threat.has_nuclei:
            threat_items.append("Nuclei Template Available")
        
        if threat_items:
            report.append(f"**Threat Indicators**: {', '.join(threat_items)}")
        
        if rd.threat.epss_score:
            percentile_str = f"{rd.threat.epss_percentile:.1f}%" if rd.threat.epss_percentile else "N/A"
            report.append(f"**EPSS Score**: {rd.threat.epss_score:.4f} (Percentile: {percentile_str})")
        if rd.threat.vedas_score:
            report.append(f"**VEDAS Score**: {rd.threat.vedas_score:.3f}")
        report.append("")
        
        # Affected Products & Remediation
        if rd.cpe_affected or rd.vendor_advisories or rd.patches:
            report.append("## Affected Products & Remediation\n")
            if rd.cpe_affected:
                report.append(f"**Affected Products** ({len(rd.cpe_affected)} total):")
                for cpe in rd.cpe_affected:
                    report.append(f"- {cpe}")
                report.append("")
            
            if rd.vendor_advisories:
                report.append(f"**Vendor Advisories** ({len(rd.vendor_advisories)} total):")
                for advisory in rd.vendor_advisories:
                    report.append(f"- {advisory}")
                report.append("")
            
            if rd.patches:
                report.append(f"**Available Patches** ({len(rd.patches)} total):")
                for patch in rd.patches:
                    report.append(f"- {patch}")
                report.append("")
        
        # URLs & References
        report.append("## URLs & References\n")
        
        if rd.references:
            report.append(f"**Reference URLs** ({len(rd.references)} total):")
            for ref in rd.references:
                report.append(f"- {ref}")
            report.append("")
        
        if rd.exploits:
            report.append(f"**Exploit URLs** ({len(rd.exploits)} total):")
            for exploit in rd.exploits:
                verified_status = ' (VERIFIED)' if exploit.verified else ''
                report.append(f"- **[{exploit.type.upper()}]** {exploit.url}{verified_status}")
                if exploit.date_found:
                    report.append(f"  - Found: {exploit.date_found.strftime('%Y-%m-%d')}")
            report.append("")
        
        return "\n".join(report)
    
    def export_research_data(self, research_data: List[ResearchData], format: str, output_path: Path) -> None:
        """Export research data in specified format.
        
        Supported formats:
        - json: Comprehensive data export for programmatic use and web UI
        - csv: Tabular format for spreadsheet analysis  
        - excel: Excel format with all fields (same structure as CSV)
        
        Note: Use --detailed flag for interactive Web UI visualization
        """
        if format == "json" or format == "webui":
            # JSON and WebUI use the same comprehensive format
            self._export_json(research_data, output_path)
            if format == "webui":
                console.print(f"[cyan]Start the web UI with: python3 cve_research_ui.py --data-file {output_path}[/cyan]")
        elif format == "csv":
            self._export_csv(research_data, output_path)
        elif format == "excel":
            self._export_excel(research_data, output_path)
        elif format == "markdown":
            # Keep markdown support for backward compatibility but not in main CLI
            self._export_markdown(research_data, output_path)
        else:
            raise ValueError(f"Unsupported export format: {format}. Supported: json, csv, excel")
    
    def _export_json(self, data: List[ResearchData], path: Path) -> None:
        """Export to JSON format."""
        json_data = [self._research_data_to_dict(rd) for rd in data]
        
        with open(path, 'w') as f:
            json.dump(json_data, f, indent=2, default=str)
        
        console.print(f"[green]Research data exported to {path}[/green]")
    
    def _research_data_to_dict(self, rd: ResearchData) -> Dict[str, Any]:
        """Convert ResearchData to comprehensive dictionary for JSON export."""
        # Get the standardized row data
        row_data = self._generate_export_row(rd)
        
        # Also include structured data for programmatic access
        return {
            # Core identification
            "cve_id": rd.cve_id,
            "description": rd.description,
            
            # CVSS information
            "cvss_score": rd.cvss_score,
            "cvss_vector": rd.cvss_vector,
            "severity": rd.severity,
            
            # Dates
            "published_date": rd.published_date.isoformat() if rd.published_date else None,
            "last_modified": rd.last_modified.isoformat() if rd.last_modified else None,
            "last_enriched": rd.last_enriched.isoformat() if rd.last_enriched else None,
            
            # References and remediation
            "references": rd.references,
            "vendor_advisories": rd.vendor_advisories,
            "patches": rd.patches,
            "cpe_affected": rd.cpe_affected,
            
            # Exploits
            "exploits": [
                {
                    "url": e.url,
                    "source": e.source,
                    "type": e.type,
                    "verified": e.verified
                } for e in rd.exploits
            ],
            "exploit_maturity": rd.exploit_maturity,
            
            # MITRE Framework
            "weakness": {
                "cwe_ids": rd.weakness.cwe_ids,
                "cwe_details": rd.weakness.cwe_details,
                "capec_ids": rd.weakness.capec_ids,
                "capec_details": rd.weakness.capec_details,
                "attack_techniques": rd.weakness.attack_techniques,
                "attack_tactics": rd.weakness.attack_tactics,
                "kill_chain_phases": rd.weakness.kill_chain_phases
            },
            
            # Threat intelligence
            "threat": {
                "in_kev": rd.threat.in_kev,
                "vulncheck_kev": rd.threat.vulncheck_kev,
                "epss_score": rd.threat.epss_score,
                "epss_percentile": rd.threat.epss_percentile,
                "vedas_score": rd.threat.vedas_score,
                "has_metasploit": rd.threat.has_metasploit,
                "has_nuclei": rd.threat.has_nuclei,
                "has_exploitdb": rd.threat.has_exploitdb,
                "has_poc_github": rd.threat.has_poc_github,
                "actively_exploited": rd.threat.actively_exploited,
                "ransomware_campaign": rd.threat.ransomware_campaign,
                "kev_vulnerability_name": rd.threat.kev_vulnerability_name,
                "kev_short_description": rd.threat.kev_short_description,
                "kev_vendor_project": rd.threat.kev_vendor_project,
                "kev_product": rd.threat.kev_product
            },
            
            # Include all CSV/Excel fields for consistency
            "csv_row_data": row_data
        }
    
    def _sanitize_csv_text(self, text: str) -> str:
        """Sanitize text for CSV export by removing problematic characters."""
        if not text:
            return ""
        
        import re
        
        # Remove HTML tags
        text = re.sub(r'<[^>]+>', '', text)
        
        # Replace multiple whitespace/newlines with single space
        text = re.sub(r'\s+', ' ', text)
        
        # Remove non-printable characters except common ones
        text = ''.join(char for char in text if char.isprintable() or char in '\t\n\r')
        
        # Trim whitespace
        text = text.strip()
        
        return text

    def _generate_export_row(self, rd: ResearchData) -> Dict[str, Any]:
        """Generate a standardized row of data for CSV/Excel export with all fields."""
        # Extract fix/upgrade references
        fix_versions = []
        mitigations = []
        for ref in rd.references:
            # Simple heuristic for upgrade/fix URLs
            if any(word in ref.lower() for word in ['upgrade', 'update', 'patch', 'fix', 'release']):
                fix_versions.append(ref)
            elif any(word in ref.lower() for word in ['advisory', 'bulletin', 'security', 'mitigat']):
                mitigations.append(ref)
        
        # Format affected products (vendor, product, version)
        affected_str = ""
        if rd.cpe_affected:
            # Parse CPE strings to extract vendor/product/version
            affected_parts = []
            for cpe in rd.cpe_affected[:10]:  # Limit to 10 for readability
                parts = cpe.split(':')
                if len(parts) >= 5:
                    vendor = parts[3]
                    product = parts[4]
                    version = parts[5] if len(parts) > 5 else '*'
                    affected_parts.append(f"{vendor} {product} {version}")
            affected_str = "; ".join(affected_parts)
        
        # Filter ExploitRefs to only include actual exploit URLs (not NVD references)
        exploit_urls = []
        for exploit in rd.exploits:
            if exploit.url and not any(domain in exploit.url.lower() for domain in ['cve.mitre.org', 'nvd.nist.gov']):
                exploit_urls.append(exploit.url)
        
        return {
            # Core CVE fields
            'CVE ID': rd.cve_id,
            'Description': self._sanitize_csv_text(rd.description),
            'CVSS': rd.cvss_score,
            'Severity': rd.severity,
            'Vector': rd.cvss_vector,
            'CWE': self._sanitize_csv_text('; '.join(rd.weakness.cwe_details) if rd.weakness.cwe_details else '; '.join(rd.weakness.cwe_ids) if rd.weakness.cwe_ids else ''),
            'Exploit': 'Yes' if exploit_urls else 'No',
            'ExploitRefs': self._sanitize_csv_text('; '.join(exploit_urls)),
            'FixVersion': self._sanitize_csv_text(fix_versions[0] if fix_versions else ''),
            'Mitigations': self._sanitize_csv_text('; '.join(mitigations[:3]) if mitigations else ''),
            'Affected': self._sanitize_csv_text(affected_str),
            'References': self._sanitize_csv_text(', '.join(rd.references)),
            
            # CVSS Metric Breakdown
            'Attack Vector': self._extract_cvss_component(rd.cvss_vector, 'AV', {'N': 'Network', 'A': 'Adjacent', 'L': 'Local', 'P': 'Physical'}),
            'Attack Complexity': self._extract_cvss_component(rd.cvss_vector, 'AC', {'L': 'Low', 'H': 'High'}),
            'Privileges Required': self._extract_cvss_component(rd.cvss_vector, 'PR', {'N': 'None', 'L': 'Low', 'H': 'High'}),
            'User Interaction': self._extract_cvss_component(rd.cvss_vector, 'UI', {'N': 'None', 'R': 'Required'}),
            'Scope': self._extract_cvss_component(rd.cvss_vector, 'S', {'U': 'Unchanged', 'C': 'Changed'}),
            'Confidentiality Impact': self._extract_cvss_component(rd.cvss_vector, 'C', {'N': 'None', 'L': 'Low', 'H': 'High'}),
            'Integrity Impact': self._extract_cvss_component(rd.cvss_vector, 'I', {'N': 'None', 'L': 'Low', 'H': 'High'}),
            'Availability Impact': self._extract_cvss_component(rd.cvss_vector, 'A', {'N': 'None', 'L': 'Low', 'H': 'High'}),
            
            # Threat intelligence fields
            'Exploit Count': len(exploit_urls),
            'Exploit Maturity': rd.exploit_maturity,
            'Exploit Types': self._sanitize_csv_text('; '.join([e.type for e in rd.exploits]) if rd.exploits else ''),
            'Technology Stack': self._sanitize_csv_text(next((p.replace('Technology Stack: ', '') for p in rd.patches if p.startswith('Technology Stack:')), '')),
            'CISA KEV': 'Yes' if rd.threat.in_kev else 'No',
            'Ransomware Campaign Use': 'Yes' if rd.threat.ransomware_campaign else 'No',
            'KEV Vulnerability Name': self._sanitize_csv_text(rd.threat.kev_vulnerability_name or ''),
            'KEV Vendor Project': self._sanitize_csv_text(rd.threat.kev_vendor_project or ''),
            'KEV Product': self._sanitize_csv_text(rd.threat.kev_product or ''),
            'VulnCheck KEV': 'Yes' if rd.threat.vulncheck_kev else 'No',
            'EPSS Score': rd.threat.epss_score if rd.threat.epss_score else '',
            'EPSS Percentile': rd.threat.epss_percentile if rd.threat.epss_percentile else '',
            'Actively Exploited': 'Yes' if rd.threat.actively_exploited else 'No',
            'Has Metasploit': 'Yes' if rd.threat.has_metasploit else 'No',
            'Has Nuclei': 'Yes' if rd.threat.has_nuclei else 'No',
            'Has ExploitDB': 'Yes' if rd.threat.has_exploitdb else 'No',
            'Has PoC GitHub': 'Yes' if rd.threat.has_poc_github else 'No',
            'CAPEC IDs': self._sanitize_csv_text('; '.join(rd.weakness.capec_details) if rd.weakness.capec_details else '; '.join(rd.weakness.capec_ids) if rd.weakness.capec_ids else ''),
            'Attack Techniques': self._sanitize_csv_text('; '.join(rd.weakness.technique_details) if rd.weakness.technique_details else '; '.join(rd.weakness.attack_techniques) if rd.weakness.attack_techniques else ''),
            'Attack Tactics': self._sanitize_csv_text('; '.join(rd.weakness.tactic_details) if rd.weakness.tactic_details else '; '.join(rd.weakness.attack_tactics) if rd.weakness.attack_tactics else ''),
            'Kill Chain Phases': self._sanitize_csv_text('; '.join(rd.weakness.kill_chain_phases) if rd.weakness.kill_chain_phases else ''),
            'Reference Count': len(rd.references),
            'CPE Affected Count': len(rd.cpe_affected),
            'Vendor Advisory Count': len(rd.vendor_advisories),
            'Patch Reference Count': len([p for p in rd.patches if p.startswith('http')]),
            'Vendor Advisories': self._sanitize_csv_text('; '.join(rd.vendor_advisories) if rd.vendor_advisories else ''),
            'Patches': self._sanitize_csv_text('; '.join([p for p in rd.patches if p.startswith('http')]) if rd.patches else ''),
            
            # Enhanced Problem Type Analysis fields
            'Primary Weakness': self._sanitize_csv_text(next((p.replace('Primary Weakness: ', '') for p in rd.patches if p.startswith('Primary Weakness:')), '')),
            'Secondary Weaknesses': self._sanitize_csv_text(next((p.replace('Secondary Weaknesses: ', '') for p in rd.patches if p.startswith('Secondary Weaknesses:')), '')),
            'Vulnerability Categories': self._sanitize_csv_text(next((p.replace('Vulnerability Categories: ', '') for p in rd.patches if p.startswith('Vulnerability Categories:')), '')),
            'Impact Types': self._sanitize_csv_text(next((p.replace('Impact Types: ', '') for p in rd.patches if p.startswith('Impact Types:')), '')),
            'Attack Vectors (Classification)': self._sanitize_csv_text(next((p.replace('Attack Vectors: ', '') for p in rd.patches if p.startswith('Attack Vectors:')), '')),
            'Enhanced CWE Details': self._sanitize_csv_text('; '.join([p.replace('Enhanced CWE: ', '') for p in rd.patches if p.startswith('Enhanced CWE:')])),
            
            # NIST 800-53 Control Mapping fields
            'Applicable_Controls_Count': next((p.replace('Applicable Controls Count: ', '') for p in rd.patches if p.startswith('Applicable Controls Count:')), '0'),
            'Control_Categories': self._sanitize_csv_text(next((p.replace('Control Categories: ', '') for p in rd.patches if p.startswith('Control Categories:')), '')),
            'Top_Controls': self._sanitize_csv_text(next((p.replace('Top Controls: ', '') for p in rd.patches if p.startswith('Top Controls:')), ''))
        }

    def _export_csv(self, data: List[ResearchData], path: Path) -> None:
        """Export to CSV format with all fields using standardized row generation."""
        rows = []
        for rd in data:
            rows.append(self._generate_export_row(rd))
        
        if not pd:
            raise RuntimeError("pandas is required for CSV export")
        df = pd.DataFrame(rows)
        df.to_csv(path, index=False)
        
        console.print(f"[green]Research data exported to {path}[/green]")
    
    def _export_markdown(self, data: List[ResearchData], path: Path) -> None:
        """Export detailed markdown reports."""
        with open(path, 'w') as f:
            f.write("# Vulnerability Research Report\n\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(f"Total CVEs Analyzed: {len(data)}\n\n")
            
            # Summary statistics
            critical = sum(1 for rd in data if rd.severity == "CRITICAL")
            high = sum(1 for rd in data if rd.severity == "HIGH")
            exploited = sum(1 for rd in data if rd.threat.actively_exploited)
            weaponized = sum(1 for rd in data if rd.exploit_maturity == "weaponized")
            
            f.write("## Summary Statistics\n\n")
            f.write(f"- Critical Severity: {critical}\n")
            f.write(f"- High Severity: {high}\n")
            f.write(f"- Actively Exploited: {exploited}\n")
            f.write(f"- Weaponized Exploits: {weaponized}\n\n")
            
            # Top severity CVEs
            f.write("## Top Severity CVEs\n\n")
            sorted_data = sorted(data, key=lambda x: x.cvss_score, reverse=True)
            
            for rd in sorted_data:  # Show ALL CVEs, not just top 10
                f.write(f"### {rd.cve_id} (CVSS: {rd.cvss_score})\n")
                f.write(f"- Severity: {rd.severity} ({rd.cvss_score})\n")
                f.write(f"- Exploits: {len(rd.exploits)} ({rd.exploit_maturity})\n")
                f.write(f"- KEV: {'Yes' if rd.threat.in_kev else 'No'}\n")
                f.write(f"- **Full Description**: {rd.description}\n")
                f.write(f"- **CVSS Vector**: {rd.cvss_vector}\n")
                f.write(f"- **Published Date**: {rd.published_date.strftime('%Y-%m-%d') if rd.published_date else 'Unknown'}\n")
                
                # Add threat intelligence
                threat_info = []
                if rd.threat.in_kev:
                    threat_info.append("CISA KEV Listed")
                if rd.threat.epss_score and rd.threat.epss_score > 0.5:
                    threat_info.append(f"High EPSS ({rd.threat.epss_score:.3f})")
                if rd.threat.has_metasploit:
                    threat_info.append("Metasploit Available")
                if rd.threat.actively_exploited:
                    threat_info.append("Actively Exploited")
                if threat_info:
                    f.write(f"- **Threat Intelligence**: {', '.join(threat_info)}\n")
                
                # Add CWE information
                if rd.weakness.cwe_ids:
                    f.write(f"- **CWE Classifications**: {', '.join(rd.weakness.cwe_ids)}\n")
                
                # Add attack vector analysis
                if rd.cvss_vector:
                    attack_vector = self._extract_cvss_component(rd.cvss_vector, 'AV', {'N': 'Network', 'A': 'Adjacent', 'L': 'Local', 'P': 'Physical'})
                    attack_complexity = self._extract_cvss_component(rd.cvss_vector, 'AC', {'L': 'Low', 'H': 'High'})
                    if attack_vector or attack_complexity:
                        f.write(f"- **Attack Vector**: {attack_vector} (Complexity: {attack_complexity})\n")
                
                # Add exploit details
                if rd.exploits:
                    f.write(f"- **Exploit References**:\n")
                    for exploit in rd.exploits:
                        f.write(f"  - [{exploit.type}] {exploit.url}\n")
                
                # Add references
                if rd.references:
                    f.write(f"- **References** ({len(rd.references)} total):\n")
                    for ref in rd.references[:10]:  # Show top 10 references
                        f.write(f"  - {ref}\n")
                    if len(rd.references) > 10:
                        f.write(f"  - ... and {len(rd.references) - 10} more references\n")
                
                # Add affected products
                if rd.cpe_affected:
                    f.write(f"- **Affected Products**: {', '.join(rd.cpe_affected[:5])}")
                    if len(rd.cpe_affected) > 5:
                        f.write(f" and {len(rd.cpe_affected) - 5} more")
                    f.write("\n")
                
                
                f.write("\n")
        
        console.print(f"[green]Research report exported to {path}[/green]")
    
    def _export_excel(self, data: List[ResearchData], path: Path) -> None:
        """Export to Excel format with all fields using standardized row generation."""
        if not PANDAS_AVAILABLE:
            print("Excel export requires pandas. Install with: pip install pandas openpyxl")
            return
        
        rows = []
        for rd in data:
            rows.append(self._generate_export_row(rd))
        
        if pd is not None:
            df = pd.DataFrame(rows)
            df.to_excel(path, index=False)
        else:
            print("Pandas not available for Excel export")
        console.print(f"[green]Research data exported to {path}[/green]")


def cli_main() -> None:
    """CLI entry point with click integration."""
    if not CLICK_AVAILABLE or click is None:
        print("Click not available, using basic CLI")
        import sys
        if len(sys.argv) > 1:
            main_research(input_file=sys.argv[1])
        else:
            main_research()
        return
    
    @click.command()
    @click.argument('input_file', type=click.Path(exists=True), default='cves.txt')
    @click.option('--format', '-f', multiple=True, 
                  type=click.Choice(['json', 'csv', 'excel']),
                  default=['csv'], help='Output format(s)')
    @click.option('--output-dir', '-o', default='research_output', 
                  help='Output directory for reports')
    @click.option('--config', '-c', type=click.Path(), default=DEFAULT_CONFIG,
                  help='Configuration file')
    @click.option('--detailed', is_flag=True,
                  help='Generate comprehensive JSON data for Web UI visualization')
    @click.option('--quiet', '-q', is_flag=True,
                  help='Suppress informational logging messages')
    def click_main(input_file: str, format: Tuple[str, ...], output_dir: str, config: str, detailed: bool, quiet: bool) -> None:
        """CVE Research Toolkit - Multi-Source Intelligence Platform"""
        main_research(input_file, list(format), output_dir, config, detailed, quiet)
    
    click_main()

def main_research(input_file: str = 'cves.txt', format: List[str] = ['csv'], output_dir: str = 'research_output', 
                 config: str = DEFAULT_CONFIG, detailed: bool = False, quiet: bool = False) -> None:
    """CVE Research Toolkit - Multi-Source Intelligence Platform
    
    Integrates data from:
    - CVEProject/cvelistV5 (Foundational)
    - trickest/cve (Exploit PoCs)
    - MITRE CTI (Tactics & Weaknesses)
    - CISA KEV & EPSS (Threat Context)
    """
    
    # Configure logging level based on quiet flag
    if quiet:
        logging.getLogger().setLevel(logging.WARNING)  # Only show warnings and errors
    # Display banner
    console.print(Panel.fit(
        "[bold blue]CVE Research Toolkit[/bold blue]\n"
        "[dim]Multi-Source Vulnerability Intelligence Platform[/dim]",
        border_style="blue"
    ))
    
    # Load configuration
    config_data: Dict[str, Any] = {}
    if Path(config).exists() and YAML_AVAILABLE and yaml is not None:
        with open(config) as f:
            config_data = yaml.safe_load(f) or {}
    elif Path(config).exists():
        console.print(f"[yellow]Warning: YAML not available, skipping config file {config}[/yellow]")
    
    # Read CVE list
    input_path = Path(input_file)
    cve_ids = [
        line.strip()
        for line in input_path.read_text().splitlines()
        if line.strip() and line.strip().startswith("CVE-")
    ]
    
    if not cve_ids:
        console.print("[red]No valid CVE IDs found in input file[/red]")
        return
    
    console.print(f"[cyan]Found {len(cve_ids)} CVE IDs to research[/cyan]\n")
    
    # Initialize research engine
    engine = VulnerabilityResearchEngine(config_data)
    
    
    # Perform research
    console.print("[bold]Starting multi-source vulnerability research...[/bold]\n")
    
    # Run async research
    research_results = asyncio.run(engine.research_batch(cve_ids))
    
    console.print(f"\n[green]Research complete![/green] Analyzed {len(research_results)} CVEs.\n")
    
    # Generate reports
    report_gen = ResearchReportGenerator()
    
    # Show vulnerability analysis table
    if research_results:
        analysis_table = report_gen.generate_vulnerability_analysis_table(research_results)
        console.print(analysis_table)
        console.print("")
    
    # Create output directory
    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True)
    
    # Export in requested formats
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    for fmt in format:
        filename = f"research_report_{timestamp}.{fmt}"
        if fmt == "excel":
            filename = f"research_report_{timestamp}.xlsx"
        
        report_gen.export_research_data(
            research_results,
            fmt,
            output_path / filename
        )
    
    # Generate detailed reports if requested
    if detailed:
        # Generate comprehensive JSON data for Web UI
        webui_path = output_path / f"webui_data_{timestamp}.json"
        report_gen.export_research_data(research_results, "json", webui_path)
        console.print(f"[green]Comprehensive JSON data saved to {webui_path}[/green]")
        console.print(f"[cyan]Start the Web UI with: python3 cve_research_ui.py --data-file {webui_path}[/cyan]")
    
    # Show statistics
    console.print("\n[bold]Research Statistics:[/bold]")
    console.print(f"- Total CVEs analyzed: {len(research_results)}")
    console.print(f"- CVEs with public exploits: {sum(1 for rd in research_results if rd.exploits)}")
    console.print(f"- CVEs in CISA KEV: {sum(1 for rd in research_results if rd.threat.in_kev)}")
    console.print(f"- Average CVSS score: {sum(rd.cvss_score for rd in research_results) / len(research_results):.1f}")
    console.print(f"- Threat intelligence coverage: {sum(1 for rd in research_results if rd.threat.epss_score or rd.threat.in_kev)}/{len(research_results)} CVEs")


if __name__ == "__main__":
    cli_main()