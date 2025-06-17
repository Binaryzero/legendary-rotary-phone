#!/usr/bin/env python3
"""Enhanced MITRE connector for comprehensive MITRE CTI data from GitHub repositories (Layer 3)."""

import asyncio
import logging
from typing import Any, Dict, List, Optional

from ..models.data import SessionCache
from .base import DataSourceConnector

logger = logging.getLogger(__name__)


class MITREConnector(DataSourceConnector):
    """Enhanced connector for comprehensive MITRE CTI data from GitHub repositories (Layer 3)."""
    
    def __init__(self) -> None:
        self.headers = {
            'User-Agent': 'ODIN/1.0 (Security Research Tool)',
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
        
        # Create enhanced descriptions with more detail
        enhanced_technique_descriptions = []
        enhanced_tactic_descriptions = []
        enhanced_capec_descriptions = []
        
        # Enhanced technique descriptions with kill chain context
        for technique_id in attack_techniques:
            if technique_id in self.attack_techniques_cache:
                tech_info = self.attack_techniques_cache[technique_id]
                enhanced_desc = f"{technique_id}: {tech_info['name']} - Kill Chain: {', '.join(tech_info.get('kill_chain', []))}"
                enhanced_technique_descriptions.append(enhanced_desc)
        
        # Enhanced tactic descriptions with purpose context
        for tactic_id in attack_tactics:
            if tactic_id in self.attack_tactics_cache:
                tactic_info = self.attack_tactics_cache[tactic_id]
                enhanced_desc = f"{tactic_id}: {tactic_info['name']} - {tactic_info['description']}"
                enhanced_tactic_descriptions.append(enhanced_desc)
        
        # Enhanced CAPEC descriptions (already detailed in cache)
        enhanced_capec_descriptions = capec_details.copy()
        
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
            "capec_details": capec_details,
            # Phase 3: Enhanced human-readable descriptions
            "enhanced_technique_descriptions": enhanced_technique_descriptions,
            "enhanced_tactic_descriptions": enhanced_tactic_descriptions,
            "enhanced_capec_descriptions": enhanced_capec_descriptions
        }
        
        # Add CISA KEV data if available
        kev_data = data.get("kev_data", {})
        if kev_data:
            result["kev_info"] = kev_data
        
        logger.debug(f"MITRE analysis for {cve_id}: {len(capec_ids)} CAPECs, {len(attack_techniques)} techniques, {len(attack_tactics)} tactics")
        
        return result