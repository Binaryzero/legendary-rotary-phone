"""ODIN (OSINT Data Intelligence Nexus) - Multi-Source Vulnerability Intelligence Platform

Integrates multiple FOSS vulnerability data sources to provide comprehensive
research intelligence across four layers:
1. Foundational Record (CVEProject/cvelistV5)
2. Exploit Mechanics (trickest/cve)
3. Weakness & Tactics (mitre/cti)
4. Raw Intelligence (Patrowl/PatrowlHearsData + t0sche/cvss-bt)

"""

# Import version information from central version module
from .version import __version__, __build__, __release_name__, get_version_string, get_version_info

__author__ = "CVE Research Team"

from .core.engine import VulnerabilityResearchEngine
from .models.data import ResearchData
from .reporting.generator import ResearchReportGenerator
from . import exceptions

__all__ = [
    "VulnerabilityResearchEngine",
    "ResearchData", 
    "ResearchReportGenerator",
    "exceptions",
    "__version__",
    "__build__",
    "__release_name__",
    "get_version_string",
    "get_version_info"
]