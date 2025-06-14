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
    
    # Type aliases for mypy
    Console = RichConsole
    Panel = RichPanel
    Table = RichTable
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
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    vedas_score: Optional[float] = None
    has_metasploit: bool = False
    has_nuclei: bool = False
    actively_exploited: bool = False
    ransomware_campaign: bool = False


@dataclass
class WeaknessTactics:
    """Weakness classification and attack tactics."""
    cwe_ids: List[str] = field(default_factory=list)
    capec_ids: List[str] = field(default_factory=list)
    attack_techniques: List[str] = field(default_factory=list)
    attack_tactics: List[str] = field(default_factory=list)
    kill_chain_phases: List[str] = field(default_factory=list)




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
        
        logger.debug(f"TrickestConnector found {len(exploits)} exploit URLs for {cve_id}")
        return {"exploits": exploits}


class MITREConnector(DataSourceConnector):
    """Connector for MITRE CTI data (Layer 3)."""
    
    def __init__(self) -> None:
        self.capec_cache: Dict[str, Any] = {}
        self.attack_cache: Dict[str, Any] = {}
        self._load_caches()
    
    def _load_caches(self) -> None:
        """Load MITRE data caches."""
        # In production, would load from MITRE CTI STIX bundles
        # For now, using placeholder
        pass
    
    async def fetch(self, cve_id: str, session: Any) -> Dict[str, Any]:
        """MITRE data is typically cached locally."""
        # Would implement STIX bundle fetching
        return {}
    
    def parse(self, cve_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse MITRE ATT&CK and CAPEC mappings."""
        # Placeholder for MITRE parsing
        return {
            "cwe_ids": [],
            "capec_ids": [],
            "attack_techniques": [],
            "attack_tactics": []
        }


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
                            import json
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


class PatrowlConnector(DataSourceConnector):
    """Connector for Patrowl/PatrowlHearsData (Layer 5 - Raw Intelligence)."""
    
    def __init__(self) -> None:
        self.headers = {
            'User-Agent': 'CVE-Research-Toolkit/1.0 (Security Research Tool)',
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








class VulnerabilityResearchEngine:
    """Main research engine orchestrating all data sources."""
    
    def __init__(self, config: Dict[str, Any]) -> None:
        self.config = config
        
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
        
        
    
    async def research_cve(self, cve_id: str) -> ResearchData:
        """Perform comprehensive research on a CVE."""
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
            
            for layer, task in tasks:
                try:
                    data = await task
                    if isinstance(layer, str) and layer == "cvss_bt":
                        parsed = self.cvss_bt_connector.parse(cve_id, data)
                        # Merge CVSS-BT data into THREAT_CONTEXT (Layer 4)
                        if DataLayer.THREAT_CONTEXT not in results:
                            results[DataLayer.THREAT_CONTEXT] = {}
                        if "cvss_bt" not in results[DataLayer.THREAT_CONTEXT]:
                            results[DataLayer.THREAT_CONTEXT]["cvss_bt"] = {}
                        results[DataLayer.THREAT_CONTEXT]["cvss_bt"].update(parsed)
                    elif isinstance(layer, DataLayer):
                        parsed = self.connectors[layer].parse(cve_id, data)
                        results[layer] = parsed
                    
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
                    # Only log as debug for expected failures like missing data
                    if "AttributeError" in str(type(e).__name__) and layer_name == "RAW_INTELLIGENCE":
                        logger.debug(f"Patrowl data not available for {cve_id}")
                    else:
                        logger.warning(f"Error fetching {layer_name} data for {cve_id}: {type(e).__name__}: {e}")
                    if isinstance(layer, str) and layer == "cvss_bt":
                        if DataLayer.THREAT_CONTEXT not in results:
                            results[DataLayer.THREAT_CONTEXT] = {}
                        results[DataLayer.THREAT_CONTEXT].update({"cvss_bt": {}})
                    elif isinstance(layer, DataLayer):
                        results[layer] = {}
                    source_status[layer] = "error"
            
            # Log overall source availability
            successful_sources = sum(1 for status in source_status.values() if status == "success")
            total_sources = len(self.connectors) + 1  # +1 for CVSS-BT
            logger.debug(f"CVE {cve_id}: {successful_sources}/{total_sources} data sources available")
        
        # Build ResearchData object
        research_data = self._build_research_data(cve_id, results)
        
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
        
        # Add enhanced data from Patrowl (Layer 5 - Raw Intelligence)
        if raw_intelligence:
            # Merge CPE affected products
            patrowl_cpe = raw_intelligence.get("cpe_affected", [])
            research_data.cpe_affected.extend(patrowl_cpe)
            
            # Store impact metrics as additional metadata
            impact_metrics = raw_intelligence.get("impact_metrics", {})
            if impact_metrics:
                # Store in a way that doesn't conflict with existing fields
                research_data.patches.append(f"Impact Score: {impact_metrics.get('impact_score', 'N/A')}")
                research_data.patches.append(f"Exploitability Score: {impact_metrics.get('exploitability_score', 'N/A')}")
        
        # Add exploit data with error handling
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
        
        if exploits_added > 0:
            logger.debug(f"Added {exploits_added} exploits for {cve_id}")
        
        # Determine exploit maturity with fallback
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
        research_data.threat.epss_score = epss_threat_data.get("epss_score") or cvss_bt_threat_data.get("epss_score")
        research_data.threat.actively_exploited = cvss_bt_threat_data.get("in_kev", epss_threat_data.get("actively_exploited", False))
        research_data.threat.has_metasploit = cvss_bt_threat_data.get("has_metasploit", False)
        research_data.threat.has_nuclei = False  # Would come from other sources
        
        # Add weakness data with fallback
        weakness_data = results.get(DataLayer.WEAKNESS_TACTICS, {})
        if weakness_data.get("cwe_ids"):
            research_data.weakness.cwe_ids = weakness_data["cwe_ids"]
        if weakness_data.get("attack_techniques"):
            research_data.weakness.attack_techniques = weakness_data["attack_techniques"]
        
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
        
        return research_data
    
    
    async def research_batch(self, cve_ids: List[str]) -> List[ResearchData]:
        """Research multiple CVEs concurrently."""
        results = []
        
        # Use semaphore to limit concurrent requests
        semaphore = asyncio.Semaphore(self.config.get("max_concurrent", 10))
        
        async def research_with_limit(cve_id: str) -> ResearchData:
            async with semaphore:
                return await self.research_cve(cve_id)
        
        # Create tasks
        tasks = [research_with_limit(cve_id) for cve_id in cve_ids]
        
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
                    f"Researching {len(cve_ids)} CVEs...",
                    total=len(cve_ids)
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
                    print(f"Progress: {i}/{len(cve_ids)} CVEs processed")
        
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
        """Export research data to various formats."""
        if format == "json":
            self._export_json(research_data, output_path)
        elif format == "csv":
            self._export_csv(research_data, output_path)
        elif format == "markdown":
            self._export_markdown(research_data, output_path)
        elif format == "excel":
            self._export_excel(research_data, output_path)
    
    def _export_json(self, data: List[ResearchData], path: Path) -> None:
        """Export to JSON format."""
        json_data = [self._research_data_to_dict(rd) for rd in data]
        
        with open(path, 'w') as f:
            json.dump(json_data, f, indent=2, default=str)
        
        console.print(f"[green]✓[/green] Research data exported to {path}")
    
    def _research_data_to_dict(self, rd: ResearchData) -> Dict[str, Any]:
        """Convert ResearchData to dictionary for JSON export."""
        return {
            "cve_id": rd.cve_id,
            "description": rd.description,
            "cvss_score": rd.cvss_score,
            "cvss_vector": rd.cvss_vector,
            "severity": rd.severity,
            "published_date": rd.published_date.isoformat() if rd.published_date else None,
            "last_modified": rd.last_modified.isoformat() if rd.last_modified else None,
            "references": rd.references,
            "exploits": [
                {
                    "url": e.url,
                    "source": e.source,
                    "type": e.type,
                    "verified": e.verified
                } for e in rd.exploits
            ],
            "exploit_maturity": rd.exploit_maturity,
            "weakness": {
                "cwe_ids": rd.weakness.cwe_ids,
                "capec_ids": rd.weakness.capec_ids,
                "attack_techniques": rd.weakness.attack_techniques,
                "attack_tactics": rd.weakness.attack_tactics
            },
            "threat": {
                "in_kev": rd.threat.in_kev,
                "epss_score": rd.threat.epss_score,
                "epss_percentile": rd.threat.epss_percentile,
                "has_metasploit": rd.threat.has_metasploit,
                "has_nuclei": rd.threat.has_nuclei,
                "actively_exploited": rd.threat.actively_exploited,
                "ransomware_campaign": rd.threat.ransomware_campaign,
                "vedas_score": rd.threat.vedas_score
            },
            "cpe_affected": rd.cpe_affected,
            "vendor_advisories": rd.vendor_advisories,
            "patches": rd.patches,
            "last_enriched": rd.last_enriched.isoformat() if rd.last_enriched else None
        }
    
    def _export_csv(self, data: List[ResearchData], path: Path) -> None:
        """Export to CSV format with clean, relevant fields only."""
        rows = []
        for rd in data:
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
            
            rows.append({
                # Core CVE fields
                'CVE ID': rd.cve_id,
                'Description': rd.description,
                'CVSS': rd.cvss_score,
                'Severity': rd.severity,
                'Vector': rd.cvss_vector,
                'CWE': '; '.join(rd.weakness.cwe_ids) if rd.weakness.cwe_ids else '',
                'Exploit': 'Yes' if exploit_urls else 'No',
                'ExploitRefs': '; '.join(exploit_urls),
                'FixVersion': fix_versions[0] if fix_versions else '',
                'Mitigations': '; '.join(mitigations[:3]) if mitigations else '',
                'Affected': affected_str,
                'References': ', '.join(rd.references),
                
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
                'Exploit Types': '; '.join([e.type for e in rd.exploits]) if rd.exploits else '',
                'CISA KEV': 'Yes' if rd.threat.in_kev else 'No',
                'EPSS Score': rd.threat.epss_score if rd.threat.epss_score else '',
                'EPSS Percentile': rd.threat.epss_percentile if rd.threat.epss_percentile else '',
                'Actively Exploited': 'Yes' if rd.threat.actively_exploited else 'No',
                'Has Metasploit': 'Yes' if rd.threat.has_metasploit else 'No',
                'Has Nuclei': 'Yes' if rd.threat.has_nuclei else 'No',
                'CAPEC IDs': '; '.join(rd.weakness.capec_ids) if rd.weakness.capec_ids else '',
                'Attack Techniques': '; '.join(rd.weakness.attack_techniques) if rd.weakness.attack_techniques else '',
                'Attack Tactics': '; '.join(rd.weakness.attack_tactics) if rd.weakness.attack_tactics else '',
                'Reference Count': len(rd.references),
                'CPE Affected Count': len(rd.cpe_affected),
                'Vendor Advisories': '; '.join(rd.vendor_advisories) if rd.vendor_advisories else '',
                'Patches': '; '.join(rd.patches) if rd.patches else ''
            })
        
        if not pd:
            raise RuntimeError("pandas is required for CSV export")
        df = pd.DataFrame(rows)
        df.to_csv(path, index=False)
        
        console.print(f"[green]✓[/green] Research data exported to {path}")
    
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
        
        console.print(f"[green]✓[/green] Research report exported to {path}")
    
    def _export_excel(self, data: List[ResearchData], path: Path) -> None:
        """Export to Excel format with clean, relevant fields only."""
        if not PANDAS_AVAILABLE:
            print("Excel export requires pandas. Install with: pip install pandas openpyxl")
            return
        
        rows = []
        for rd in data:
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
            
            rows.append({
                # Core CVE fields
                'CVE ID': rd.cve_id,
                'Description': rd.description,
                'CVSS': rd.cvss_score,
                'Severity': rd.severity,
                'Vector': rd.cvss_vector,
                'CWE': '; '.join(rd.weakness.cwe_ids) if rd.weakness.cwe_ids else '',
                'Exploit': 'Yes' if exploit_urls else 'No',
                'ExploitRefs': '; '.join(exploit_urls),
                'FixVersion': fix_versions[0] if fix_versions else '',
                'Mitigations': '; '.join(mitigations[:3]) if mitigations else '',
                'Affected': affected_str,
                'References': ', '.join(rd.references),
                
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
                'Exploit Types': '; '.join([e.type for e in rd.exploits]) if rd.exploits else '',
                'CISA KEV': 'Yes' if rd.threat.in_kev else 'No',
                'EPSS Score': rd.threat.epss_score if rd.threat.epss_score else '',
                'EPSS Percentile': rd.threat.epss_percentile if rd.threat.epss_percentile else '',
                'Actively Exploited': 'Yes' if rd.threat.actively_exploited else 'No',
                'Has Metasploit': 'Yes' if rd.threat.has_metasploit else 'No',
                'Has Nuclei': 'Yes' if rd.threat.has_nuclei else 'No',
                'CAPEC IDs': '; '.join(rd.weakness.capec_ids) if rd.weakness.capec_ids else '',
                'Attack Techniques': '; '.join(rd.weakness.attack_techniques) if rd.weakness.attack_techniques else '',
                'Attack Tactics': '; '.join(rd.weakness.attack_tactics) if rd.weakness.attack_tactics else '',
                'Reference Count': len(rd.references),
                'CPE Affected Count': len(rd.cpe_affected),
                'Vendor Advisories': '; '.join(rd.vendor_advisories) if rd.vendor_advisories else '',
                'Patches': '; '.join(rd.patches) if rd.patches else ''
            })
        
        if pd is not None:
            df = pd.DataFrame(rows)
            df.to_excel(path, index=False)
        else:
            print("Pandas not available for Excel export")
        console.print(f"[green]✓[/green] Research data exported to {path}")


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
                  type=click.Choice(['json', 'csv', 'markdown', 'excel']),
                  default=['markdown'], help='Output format(s)')
    @click.option('--output-dir', '-o', default='research_output', 
                  help='Output directory for reports')
    @click.option('--config', '-c', type=click.Path(), default=DEFAULT_CONFIG,
                  help='Configuration file')
    @click.option('--detailed', is_flag=True,
                  help='Generate detailed reports for each CVE')
    def click_main(input_file: str, format: Tuple[str, ...], output_dir: str, config: str, detailed: bool) -> None:
        """CVE Research Toolkit - Multi-Source Intelligence Platform"""
        main_research(input_file, list(format), output_dir, config, detailed)
    
    click_main()

def main_research(input_file: str = 'cves.txt', format: List[str] = ['markdown'], output_dir: str = 'research_output', 
                 config: str = DEFAULT_CONFIG, detailed: bool = False) -> None:
    """CVE Research Toolkit - Multi-Source Intelligence Platform
    
    Integrates data from:
    - CVEProject/cvelistV5 (Foundational)
    - trickest/cve (Exploit PoCs)
    - MITRE CTI (Tactics & Weaknesses)
    - CISA KEV & EPSS (Threat Context)
    """
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
        details_dir = output_path / f"detailed_reports_{timestamp}"
        details_dir.mkdir(exist_ok=True)
        
        for rd in research_results[:20]:  # Limit to top 20
            report_content = report_gen.generate_detailed_report(rd)
            report_path = details_dir / f"{rd.cve_id}_report.md"
            report_path.write_text(report_content)
        
        console.print(f"[green]✓[/green] Detailed reports saved to {details_dir}")
    
    # Show statistics
    console.print("\n[bold]Research Statistics:[/bold]")
    console.print(f"- Total CVEs analyzed: {len(research_results)}")
    console.print(f"- CVEs with public exploits: {sum(1 for rd in research_results if rd.exploits)}")
    console.print(f"- CVEs in CISA KEV: {sum(1 for rd in research_results if rd.threat.in_kev)}")
    console.print(f"- Average CVSS score: {sum(rd.cvss_score for rd in research_results) / len(research_results):.1f}")
    console.print(f"- Threat intelligence coverage: {sum(1 for rd in research_results if rd.threat.epss_score or rd.threat.in_kev)}/{len(research_results)} CVEs")


if __name__ == "__main__":
    cli_main()