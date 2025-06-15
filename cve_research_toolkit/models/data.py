"""Data models for CVE research."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import List, Optional


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