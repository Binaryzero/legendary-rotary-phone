"""Data models for CVE research."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Any, Dict, List, Optional


class DataLayer(Enum):
    """Research data layers."""
    FOUNDATIONAL = auto()
    EXPLOIT_MECHANICS = auto()
    WEAKNESS_TACTICS = auto()
    THREAT_CONTEXT = auto()
    RAW_INTELLIGENCE = auto()


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


@dataclass
class EnhancedProblemType:
    """Enhanced problem type analysis with structured vulnerability classification."""
    primary_weakness: str = ""
    secondary_weaknesses: List[str] = field(default_factory=list)
    vulnerability_categories: List[str] = field(default_factory=list)
    impact_types: List[str] = field(default_factory=list)
    attack_vectors: List[str] = field(default_factory=list)
    enhanced_cwe_details: List[str] = field(default_factory=list)


@dataclass
class ControlMappings:
    """NIST 800-53 control mappings for risk assessment."""
    applicable_controls_count: int = 0
    control_categories: List[str] = field(default_factory=list)
    top_controls: List[str] = field(default_factory=list)


@dataclass
class ProductIntelligence:
    """Enhanced product and platform intelligence from CVE affected objects."""
    vendors: List[str] = field(default_factory=list)
    products: List[str] = field(default_factory=list)
    affected_versions: List[str] = field(default_factory=list)
    platforms: List[str] = field(default_factory=list)
    modules: List[str] = field(default_factory=list)


@dataclass
class ExploitReference:
    """Exploit reference information."""
    url: str
    source: str
    type: str  # poc, metasploit, nuclei, exploit-db, github-poc, packetstorm
    verified: bool = False
    date_found: Optional[datetime] = None
    title: str = ""  # Enhanced: exploit title/description


@dataclass
class ThreatContext:
    """Real-world threat intelligence."""
    in_kev: bool = False
    vulncheck_kev: bool = False
    epss_score: Optional[float] = None
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
    kev_date_added: str = ""
    kev_due_date: str = ""
    kev_required_action: str = ""
    kev_known_ransomware: str = ""
    kev_notes: str = ""
    # Temporal CVSS fields (extracted from CVSS vectors)
    exploit_code_maturity: str = ""
    remediation_level: str = ""
    report_confidence: str = ""


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
    # Phase 3: Enhanced MITRE human-readable descriptions  
    enhanced_technique_descriptions: List[str] = field(default_factory=list)
    enhanced_tactic_descriptions: List[str] = field(default_factory=list)
    enhanced_capec_descriptions: List[str] = field(default_factory=list)
    alternative_cwe_mappings: List[str] = field(default_factory=list)  # Additional CWE from ADP


@dataclass
class ResearchData:
    """Comprehensive vulnerability research data with risk assessment."""
    # Layer 1: Foundational
    cve_id: str
    description: str = ""
    cvss_score: float = 0.0
    cvss_vector: str = ""
    severity: str = ""
    cvss_version: str = ""  # CVSS version (e.g., "3.1", "2.0")
    cvss_bt_score: float = 0.0  # Enhanced CVSS-BT score
    cvss_bt_severity: str = ""  # Enhanced CVSS-BT severity
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
    
    # Enhanced Reference Categorization (Phase 2)
    mitigations: List[str] = field(default_factory=list)
    fix_versions: List[str] = field(default_factory=list)
    
    # Phase 2 Intelligence Enhancement
    alternative_cvss_scores: List[Dict[str, Any]] = field(default_factory=list)  # Additional CVSS from ADP
    reference_tags: List[str] = field(default_factory=list)  # Actual CVE reference tags
    
    # Enhanced Analysis (Structured Fields)
    enhanced_problem_type: EnhancedProblemType = field(default_factory=EnhancedProblemType)
    control_mappings: ControlMappings = field(default_factory=ControlMappings)
    product_intelligence: ProductIntelligence = field(default_factory=ProductIntelligence)
    
    # Research Metadata
    last_enriched: Optional[datetime] = None