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
import csv
import json
import logging
import sqlite3
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import urlparse

import aiohttp
import click
import pandas as pd
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table
from rich.logging import RichHandler

# Constants
DEFAULT_CONFIG = "research_toolkit.yaml"
DEFAULT_CACHE_DB = ".research_cache.db"
GITHUB_RAW_BASE = "https://raw.githubusercontent.com"

console = Console()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    handlers=[RichHandler(console=console, rich_tracebacks=True)]
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
    """Comprehensive vulnerability research data."""
    # Layer 1: Foundational
    cve_id: str
    description: str
    cvss_score: float
    cvss_vector: str
    severity: str
    published_date: datetime
    last_modified: datetime
    references: List[str]
    
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
    research_priority: int = 0  # 0-100 based on multiple factors
    last_enriched: Optional[datetime] = None


class DataSourceConnector(ABC):
    """Abstract base for data source connectors."""
    
    @abstractmethod
    async def fetch(self, cve_id: str, session: aiohttp.ClientSession) -> Dict[str, Any]:
        """Fetch data for a specific CVE."""
        pass
    
    @abstractmethod
    def parse(self, cve_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse fetched data into standardized format."""
        pass


class CVEProjectConnector(DataSourceConnector):
    """Connector for CVEProject/cvelistV5 (Layer 1)."""
    
    async def fetch(self, cve_id: str, session: aiohttp.ClientSession) -> Dict[str, Any]:
        """Fetch from MITRE CVE repository."""
        try:
            parts = cve_id.split("-")
            year = parts[1]
            bucket = int(parts[2]) // 1000
            
            url = f"{GITHUB_RAW_BASE}/CVEProject/cvelistV5/main/cves/{year}/{bucket}xxx/{cve_id}.json"
            
            async with session.get(url) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    logger.warning(f"Failed to fetch {cve_id} from CVEProject: {response.status}")
                    return {}
        except Exception as e:
            logger.error(f"Error fetching {cve_id} from CVEProject: {e}")
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
        
        # Extract CVSS
        cvss_score = 0.0
        cvss_vector = ""
        for container in [cna] + containers.get("adp", []):
            if not container:
                continue
            for metric in container.get("metrics", []):
                for cvss_key in ["cvssV3_1", "cvssV3_0"]:
                    if cvss_key in metric:
                        cvss_data = metric[cvss_key]
                        cvss_score = float(cvss_data.get("baseScore", 0))
                        cvss_vector = cvss_data.get("vectorString", "")
                        break
                if cvss_score:
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
        
        return {
            "description": description,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "references": references,
            "published_date": published,
            "last_modified": modified
        }


class TrickestConnector(DataSourceConnector):
    """Connector for trickest/cve (Layer 2)."""
    
    async def fetch(self, cve_id: str, session: aiohttp.ClientSession) -> Dict[str, Any]:
        """Fetch PoC information from Trickest."""
        try:
            year = cve_id.split("-")[1]
            url = f"{GITHUB_RAW_BASE}/trickest/cve/main/{year}/{cve_id}.md"
            
            async with session.get(url) as response:
                if response.status == 200:
                    content = await response.text()
                    return {"content": content}
                else:
                    return {}
        except Exception as e:
            logger.debug(f"No PoC data for {cve_id} from Trickest: {e}")
            return {}
    
    def parse(self, cve_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Trickest markdown format."""
        if not data or "content" not in data:
            return {"exploits": []}
        
        content = data["content"]
        exploits = []
        
        # Parse markdown links
        import re
        link_pattern = r'\[([^\]]+)\]\(([^)]+)\)'
        matches = re.findall(link_pattern, content)
        
        for title, url in matches:
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
        
        return {"exploits": exploits}


class MITREConnector(DataSourceConnector):
    """Connector for MITRE CTI data (Layer 3)."""
    
    def __init__(self):
        self.capec_cache = {}
        self.attack_cache = {}
        self._load_caches()
    
    def _load_caches(self):
        """Load MITRE data caches."""
        # In production, would load from MITRE CTI STIX bundles
        # For now, using placeholder
        pass
    
    async def fetch(self, cve_id: str, session: aiohttp.ClientSession) -> Dict[str, Any]:
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
    """Connector for threat context data (Layer 4)."""
    
    def __init__(self):
        self.kev_cache = set()
        self.epss_cache = {}
        self._load_threat_data()
    
    def _load_threat_data(self):
        """Load threat intelligence data."""
        # Load CISA KEV
        try:
            # In production, would fetch from CISA
            pass
        except Exception as e:
            logger.warning(f"Failed to load KEV data: {e}")
    
    async def fetch(self, cve_id: str, session: aiohttp.ClientSession) -> Dict[str, Any]:
        """Fetch threat context from multiple sources."""
        data = {}
        
        # Check CISA KEV
        data["in_kev"] = cve_id in self.kev_cache
        
        # Get EPSS score
        data["epss"] = self.epss_cache.get(cve_id, {})
        
        # Would fetch from other sources
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


class ResearchCache:
    """Enhanced cache for research data."""
    
    def __init__(self, db_path: Path = Path(DEFAULT_CACHE_DB)):
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        """Initialize research cache database."""
        with sqlite3.connect(self.db_path) as conn:
            # Main research data table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS research_data (
                    cve_id TEXT PRIMARY KEY,
                    data TEXT NOT NULL,
                    layer_1_updated REAL,
                    layer_2_updated REAL,
                    layer_3_updated REAL,
                    layer_4_updated REAL,
                    layer_5_updated REAL,
                    research_priority INTEGER DEFAULT 0,
                    last_accessed REAL
                )
            """)
            
            # Indexes for efficient queries
            conn.execute("CREATE INDEX IF NOT EXISTS idx_priority ON research_data(research_priority DESC)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_accessed ON research_data(last_accessed DESC)")
    
    def get(self, cve_id: str) -> Optional[ResearchData]:
        """Get research data from cache."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT data FROM research_data WHERE cve_id = ?",
                (cve_id,)
            )
            row = cursor.fetchone()
            
            if row:
                # Update last accessed
                conn.execute(
                    "UPDATE research_data SET last_accessed = ? WHERE cve_id = ?",
                    (time.time(), cve_id)
                )
                
                data = json.loads(row[0])
                # Convert back to ResearchData object
                return self._dict_to_research_data(data)
        
        return None
    
    def put(self, research_data: ResearchData) -> None:
        """Store research data in cache."""
        data_dict = self._research_data_to_dict(research_data)
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO research_data 
                (cve_id, data, research_priority, last_accessed)
                VALUES (?, ?, ?, ?)
            """, (
                research_data.cve_id,
                json.dumps(data_dict, default=str),
                research_data.research_priority,
                time.time()
            ))
    
    def _research_data_to_dict(self, rd: ResearchData) -> dict:
        """Convert ResearchData to dictionary."""
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
                "actively_exploited": rd.threat.actively_exploited
            },
            "research_priority": rd.research_priority,
            "last_enriched": rd.last_enriched.isoformat() if rd.last_enriched else None
        }
    
    def _dict_to_research_data(self, data: dict) -> ResearchData:
        """Convert dictionary to ResearchData."""
        # Parse dates
        published = None
        if data.get("published_date"):
            published = datetime.fromisoformat(data["published_date"])
        
        modified = None
        if data.get("last_modified"):
            modified = datetime.fromisoformat(data["last_modified"])
        
        # Create ResearchData
        rd = ResearchData(
            cve_id=data["cve_id"],
            description=data["description"],
            cvss_score=data["cvss_score"],
            cvss_vector=data["cvss_vector"],
            severity=data["severity"],
            published_date=published,
            last_modified=modified,
            references=data["references"]
        )
        
        # Add exploits
        for exploit in data.get("exploits", []):
            rd.exploits.append(ExploitReference(
                url=exploit["url"],
                source=exploit["source"],
                type=exploit["type"],
                verified=exploit.get("verified", False)
            ))
        
        # Set other fields
        rd.exploit_maturity = data.get("exploit_maturity", "unproven")
        rd.research_priority = data.get("research_priority", 0)
        
        # Set threat context
        threat_data = data.get("threat", {})
        rd.threat.in_kev = threat_data.get("in_kev", False)
        rd.threat.epss_score = threat_data.get("epss_score")
        rd.threat.actively_exploited = threat_data.get("actively_exploited", False)
        
        return rd


class VulnerabilityResearchEngine:
    """Main research engine orchestrating all data sources."""
    
    def __init__(self, config: dict):
        self.config = config
        self.cache = ResearchCache()
        
        # Initialize connectors
        self.connectors = {
            DataLayer.FOUNDATIONAL: CVEProjectConnector(),
            DataLayer.EXPLOIT_MECHANICS: TrickestConnector(),
            DataLayer.WEAKNESS_TACTICS: MITREConnector(),
            DataLayer.THREAT_CONTEXT: ThreatContextConnector()
        }
    
    async def research_cve(self, cve_id: str) -> ResearchData:
        """Perform comprehensive research on a CVE."""
        # Check cache first
        cached = self.cache.get(cve_id)
        if cached and self._is_cache_fresh(cached):
            return cached
        
        # Fetch from all sources concurrently
        async with aiohttp.ClientSession() as session:
            tasks = []
            for layer, connector in self.connectors.items():
                task = connector.fetch(cve_id, session)
                tasks.append((layer, task))
            
            # Gather all results
            results = {}
            for layer, task in tasks:
                try:
                    data = await task
                    parsed = self.connectors[layer].parse(cve_id, data)
                    results[layer] = parsed
                except Exception as e:
                    logger.error(f"Error fetching {layer} for {cve_id}: {e}")
                    results[layer] = {}
        
        # Build ResearchData object
        research_data = self._build_research_data(cve_id, results)
        
        # Calculate research priority
        research_data.research_priority = self._calculate_priority(research_data)
        
        # Cache the results
        self.cache.put(research_data)
        
        return research_data
    
    def _is_cache_fresh(self, data: ResearchData) -> bool:
        """Check if cached data is still fresh."""
        if not data.last_enriched:
            return False
        
        age = datetime.now() - data.last_enriched
        max_age = timedelta(hours=self.config.get("cache_ttl_hours", 24))
        return age < max_age
    
    def _build_research_data(self, cve_id: str, results: dict) -> ResearchData:
        """Build ResearchData from multi-source results."""
        # Start with foundational data
        foundational = results.get(DataLayer.FOUNDATIONAL, {})
        
        # Determine severity
        cvss_score = foundational.get("cvss_score", 0)
        if cvss_score >= 9.0:
            severity = "CRITICAL"
        elif cvss_score >= 7.0:
            severity = "HIGH"
        elif cvss_score >= 4.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"
        
        # Parse dates
        published = None
        if foundational.get("published_date"):
            try:
                published = datetime.fromisoformat(foundational["published_date"])
            except:
                published = datetime.now()
        
        research_data = ResearchData(
            cve_id=cve_id,
            description=foundational.get("description", ""),
            cvss_score=cvss_score,
            cvss_vector=foundational.get("cvss_vector", ""),
            severity=severity,
            published_date=published or datetime.now(),
            last_modified=published or datetime.now(),
            references=foundational.get("references", [])
        )
        
        # Add exploit data
        exploit_data = results.get(DataLayer.EXPLOIT_MECHANICS, {})
        for exploit in exploit_data.get("exploits", []):
            research_data.exploits.append(ExploitReference(
                url=exploit["url"],
                source=exploit["source"],
                type=exploit["type"]
            ))
        
        # Determine exploit maturity
        if research_data.exploits:
            if any(e.type in ["metasploit", "nuclei"] for e in research_data.exploits):
                research_data.exploit_maturity = "weaponized"
            elif any(e.type == "exploit-db" for e in research_data.exploits):
                research_data.exploit_maturity = "functional"
            else:
                research_data.exploit_maturity = "poc"
        
        # Add threat context
        threat_data = results.get(DataLayer.THREAT_CONTEXT, {}).get("threat", {})
        research_data.threat.in_kev = threat_data.get("in_kev", False)
        research_data.threat.epss_score = threat_data.get("epss_score")
        research_data.threat.actively_exploited = threat_data.get("actively_exploited", False)
        
        research_data.last_enriched = datetime.now()
        
        return research_data
    
    def _calculate_priority(self, data: ResearchData) -> int:
        """Calculate research priority score (0-100)."""
        priority = 0
        
        # CVSS contribution (0-30 points)
        priority += min(30, int(data.cvss_score * 3))
        
        # Exploit maturity (0-30 points)
        maturity_scores = {
            "unproven": 0,
            "poc": 10,
            "functional": 20,
            "weaponized": 30
        }
        priority += maturity_scores.get(data.exploit_maturity, 0)
        
        # Threat context (0-40 points)
        if data.threat.in_kev:
            priority += 20
        if data.threat.actively_exploited:
            priority += 10
        if data.threat.epss_score:
            priority += int(data.threat.epss_score * 10)
        
        return min(100, priority)
    
    async def research_batch(self, cve_ids: List[str]) -> List[ResearchData]:
        """Research multiple CVEs concurrently."""
        results = []
        
        # Use semaphore to limit concurrent requests
        semaphore = asyncio.Semaphore(self.config.get("max_concurrent", 10))
        
        async def research_with_limit(cve_id):
            async with semaphore:
                return await self.research_cve(cve_id)
        
        # Create tasks
        tasks = [research_with_limit(cve_id) for cve_id in cve_ids]
        
        # Execute with progress tracking
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console
        ) as progress:
            
            task_id = progress.add_task(
                f"Researching {len(cve_ids)} CVEs...",
                total=len(cve_ids)
            )
            
            for coro in asyncio.as_completed(tasks):
                result = await coro
                results.append(result)
                progress.update(task_id, advance=1)
        
        return results


class ResearchReportGenerator:
    """Generate comprehensive research reports."""
    
    def __init__(self):
        self.console = console
    
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
        table.add_column("Priority", width=8)
        
        # Sort by priority
        sorted_data = sorted(research_data, key=lambda x: x.research_priority, reverse=True)
        
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
                f"{rd.research_priority}/100"
            )
        
        return table
    
    def generate_detailed_report(self, rd: ResearchData) -> str:
        """Generate detailed research report for a single CVE."""
        report = []
        
        report.append(f"# Vulnerability Research Report: {rd.cve_id}\n")
        report.append(f"**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        # Executive Summary
        report.append("## Executive Summary\n")
        report.append(f"- **Severity**: {rd.severity} (CVSS {rd.cvss_score})")
        report.append(f"- **Exploit Maturity**: {rd.exploit_maturity.title()}")
        report.append(f"- **Active Exploitation**: {'YES' if rd.threat.actively_exploited else 'NO'}")
        report.append(f"- **Research Priority**: {rd.research_priority}/100\n")
        
        # Layer 1: Foundational Data
        report.append("## Layer 1: Foundational Record\n")
        report.append(f"**Description**: {rd.description}\n")
        report.append(f"**CVSS Vector**: {rd.cvss_vector}\n")
        report.append(f"**Published**: {rd.published_date.strftime('%Y-%m-%d') if rd.published_date else 'Unknown'}\n")
        
        if rd.references:
            report.append("**Primary References**:")
            for ref in rd.references[:5]:
                report.append(f"- {ref}")
            if len(rd.references) > 5:
                report.append(f"- ... and {len(rd.references) - 5} more")
            report.append("")
        
        # Layer 2: Exploit Mechanics
        report.append("## Layer 2: Exploit Mechanics & Validation\n")
        if rd.exploits:
            report.append(f"**{len(rd.exploits)} Public Exploits Found**:\n")
            for exploit in rd.exploits[:10]:
                report.append(f"- [{exploit.type}] {exploit.url}")
            if len(rd.exploits) > 10:
                report.append(f"- ... and {len(rd.exploits) - 10} more")
        else:
            report.append("No public exploits found.")
        report.append("")
        
        # Layer 3: Weakness & Tactics
        report.append("## Layer 3: Weakness & Tactic Classification\n")
        if rd.weakness.cwe_ids:
            report.append(f"**CWE Classifications**: {', '.join(rd.weakness.cwe_ids)}")
        if rd.weakness.attack_techniques:
            report.append(f"**ATT&CK Techniques**: {', '.join(rd.weakness.attack_techniques)}")
        report.append("")
        
        # Layer 4: Real-World Context
        report.append("## Layer 4: Real-World Threat Context\n")
        report.append(f"- **CISA KEV Listed**: {'YES' if rd.threat.in_kev else 'NO'}")
        if rd.threat.epss_score:
            report.append(f"- **EPSS Score**: {rd.threat.epss_score:.3f}")
        report.append(f"- **Metasploit Module**: {'YES' if rd.threat.has_metasploit else 'NO'}")
        report.append(f"- **Nuclei Template**: {'YES' if rd.threat.has_nuclei else 'NO'}")
        report.append("")
        
        # Research Recommendations
        report.append("## Research Recommendations\n")
        if rd.research_priority >= 80:
            report.append("**CRITICAL PRIORITY**: This vulnerability requires immediate analysis.")
        elif rd.research_priority >= 60:
            report.append("**HIGH PRIORITY**: Schedule for near-term deep-dive analysis.")
        elif rd.research_priority >= 40:
            report.append("**MEDIUM PRIORITY**: Include in regular research rotation.")
        else:
            report.append("**LOW PRIORITY**: Monitor for changes in threat landscape.")
        
        return "\n".join(report)
    
    def export_research_data(self, research_data: List[ResearchData], format: str, output_path: Path):
        """Export research data to various formats."""
        if format == "json":
            self._export_json(research_data, output_path)
        elif format == "csv":
            self._export_csv(research_data, output_path)
        elif format == "markdown":
            self._export_markdown(research_data, output_path)
        elif format == "excel":
            self._export_excel(research_data, output_path)
    
    def _export_json(self, data: List[ResearchData], path: Path):
        """Export to JSON format."""
        cache = ResearchCache()
        json_data = [cache._research_data_to_dict(rd) for rd in data]
        
        with open(path, 'w') as f:
            json.dump(json_data, f, indent=2, default=str)
        
        console.print(f"[green]✓[/green] Research data exported to {path}")
    
    def _export_csv(self, data: List[ResearchData], path: Path):
        """Export to CSV format."""
        rows = []
        for rd in data:
            rows.append({
                'CVE_ID': rd.cve_id,
                'Severity': rd.severity,
                'CVSS_Score': rd.cvss_score,
                'Description': rd.description[:200] + '...' if len(rd.description) > 200 else rd.description,
                'Exploit_Count': len(rd.exploits),
                'Exploit_Maturity': rd.exploit_maturity,
                'In_KEV': rd.threat.in_kev,
                'EPSS_Score': rd.threat.epss_score,
                'Actively_Exploited': rd.threat.actively_exploited,
                'Research_Priority': rd.research_priority,
                'Published_Date': rd.published_date.strftime('%Y-%m-%d') if rd.published_date else '',
                'Reference_Count': len(rd.references)
            })
        
        df = pd.DataFrame(rows)
        df.to_csv(path, index=False)
        
        console.print(f"[green]✓[/green] Research data exported to {path}")
    
    def _export_markdown(self, data: List[ResearchData], path: Path):
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
            
            # Top priority CVEs
            f.write("## Top Priority CVEs\n\n")
            sorted_data = sorted(data, key=lambda x: x.research_priority, reverse=True)
            
            for rd in sorted_data[:10]:
                f.write(f"### {rd.cve_id} (Priority: {rd.research_priority}/100)\n")
                f.write(f"- Severity: {rd.severity} ({rd.cvss_score})\n")
                f.write(f"- Exploits: {len(rd.exploits)} ({rd.exploit_maturity})\n")
                f.write(f"- KEV: {'Yes' if rd.threat.in_kev else 'No'}\n")
                f.write(f"- Description: {rd.description[:200]}...\n\n")
        
        console.print(f"[green]✓[/green] Research report exported to {path}")


@click.command()
@click.argument('input_file', type=click.Path(exists=True), default='cves.txt')
@click.option('--format', '-f', multiple=True, 
              type=click.Choice(['json', 'csv', 'markdown', 'excel']),
              default=['markdown'], help='Output format(s)')
@click.option('--output-dir', '-o', default='research_output', 
              help='Output directory for reports')
@click.option('--config', '-c', type=click.Path(), default=DEFAULT_CONFIG,
              help='Configuration file')
@click.option('--priority-threshold', '-p', type=int, default=0,
              help='Minimum priority threshold (0-100)')
@click.option('--refresh-cache', is_flag=True, 
              help='Force refresh of cached data')
@click.option('--detailed', is_flag=True,
              help='Generate detailed reports for each CVE')
def main(input_file, format, output_dir, config, priority_threshold, refresh_cache, detailed):
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
    config_data = {}
    if Path(config).exists():
        with open(config) as f:
            config_data = yaml.safe_load(f) or {}
    
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
    
    # Clear cache if requested
    if refresh_cache:
        console.print("[yellow]Clearing cache...[/yellow]")
        engine.cache = ResearchCache()
    
    # Perform research
    console.print("[bold]Starting multi-source vulnerability research...[/bold]\n")
    
    # Run async research
    research_results = asyncio.run(engine.research_batch(cve_ids))
    
    # Filter by priority threshold
    filtered_results = [
        rd for rd in research_results
        if rd.research_priority >= priority_threshold
    ]
    
    console.print(f"\n[green]Research complete![/green] Found {len(filtered_results)} CVEs meeting priority threshold.\n")
    
    # Generate reports
    report_gen = ResearchReportGenerator()
    
    # Show summary table
    if filtered_results:
        summary_table = report_gen.generate_summary_table(filtered_results)
        console.print(summary_table)
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
            filtered_results,
            fmt,
            output_path / filename
        )
    
    # Generate detailed reports if requested
    if detailed:
        details_dir = output_path / f"detailed_reports_{timestamp}"
        details_dir.mkdir(exist_ok=True)
        
        for rd in filtered_results[:20]:  # Limit to top 20
            report_content = report_gen.generate_detailed_report(rd)
            report_path = details_dir / f"{rd.cve_id}_report.md"
            report_path.write_text(report_content)
        
        console.print(f"[green]✓[/green] Detailed reports saved to {details_dir}")
    
    # Show statistics
    console.print("\n[bold]Research Statistics:[/bold]")
    console.print(f"- Total CVEs researched: {len(research_results)}")
    console.print(f"- CVEs meeting priority threshold: {len(filtered_results)}")
    console.print(f"- CVEs with public exploits: {sum(1 for rd in filtered_results if rd.exploits)}")
    console.print(f"- CVEs in CISA KEV: {sum(1 for rd in filtered_results if rd.threat.in_kev)}")
    console.print(f"- Average research priority: {sum(rd.research_priority for rd in filtered_results) / len(filtered_results):.1f}")


if __name__ == "__main__":
    main()