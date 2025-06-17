"""Vulnerability Research Engine - Main orchestration of CVE research."""

import asyncio
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple, Union

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
    from rich.console import Console as RichConsole
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    RICH_AVAILABLE = True
    Console = RichConsole
except ImportError:
    RICH_AVAILABLE = False
    class Console:  # type: ignore
        def print(self, *args: Any) -> None:
            print(*args)

# Import models from the new modular structure
from ..models.data import (
    DataLayer, 
    ResearchData, 
    ExploitReference, 
    ThreatContext, 
    WeaknessTactics,
    SessionCache,
    EnhancedProblemType,
    ControlMappings,
    ProductIntelligence
)

# Import utilities
from ..utils.control_mapper import ControlMapper

# Import connectors from the new modular structure
from ..connectors import (
    CVEProjectConnector,
    TrickestConnector,
    MITREConnector,
    ThreatContextConnector,
    CVSSBTConnector,
    PatrowlConnector
)

logger = logging.getLogger(__name__)
console = Console()


class VulnerabilityResearchEngine:
    """Main research engine orchestrating all data sources."""
    
    def __init__(self, config: Dict[str, Any]) -> None:
        self.config = config
        
        # Initialize session cache for performance optimization
        self.session_cache = SessionCache()
        
        # Initialize connectors in correct layer order
        self.connectors = {
            DataLayer.FOUNDATIONAL: CVEProjectConnector(),           # Layer 1: CVEProject/cvelistV5
            DataLayer.EXPLOIT_MECHANICS: TrickestConnector(),        # Layer 2: trickest/cve
            DataLayer.WEAKNESS_TACTICS: MITREConnector(),            # Layer 3: mitre/cti
            DataLayer.THREAT_CONTEXT: ThreatContextConnector(),      # Layer 4: t0sche/cvss-bt, ARPSyndicate/cve-scores
            DataLayer.RAW_INTELLIGENCE: PatrowlConnector()           # Layer 5: Patrowl/PatrowlHearsData
        }
        
        # Initialize control mapper for NIST 800-53 mappings
        self.control_mapper = ControlMapper()
        
        # Additional Layer 4 connector for CVSS-BT data
        self.cvss_bt_connector = CVSSBTConnector()
        
        # Set session cache for connectors that support it
        for connector in [self.connectors[DataLayer.THREAT_CONTEXT], 
                         self.connectors[DataLayer.WEAKNESS_TACTICS], 
                         self.cvss_bt_connector]:
            if hasattr(connector, 'set_session_cache'):
                connector.set_session_cache(self.session_cache)
        
        
    
    async def research_cve(self, cve_id: str) -> ResearchData:
        """Perform comprehensive research on a CVE."""
        # Check session cache for duplicate CVE research
        if cve_id in self.session_cache.cve_data:
            self.session_cache.session_stats["cache_hits"] += 1
            self.session_cache.session_stats["duplicate_cves"] += 1
            logger.debug(f"Using cached data for duplicate CVE: {cve_id}")
            # Build from cached data
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
                        # Special handling for MITRE connector to pass foundational CWE data
                        if layer == DataLayer.WEAKNESS_TACTICS:
                            foundational_data = results.get(DataLayer.FOUNDATIONAL, {})
                            cwe_ids = foundational_data.get("cwe_ids", [])
                            data["foundational_cwe"] = cwe_ids
                            logger.debug(f"Passing {len(cwe_ids)} CWE IDs to MITRE connector for {cve_id}")
                        
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
        
        # Store results in session cache for potential duplicate lookups
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
        
        # Extract CVSS version and CVSS-BT data
        cvss_version = foundational.get("cvss_version", "")
        cvss_bt_data = threat_context.get("cvss_bt", {})
        cvss_bt_score = cvss_bt_data.get("cvss_bt_score", 0.0)
        cvss_bt_severity = cvss_bt_data.get("cvss_bt_severity", "")

        research_data = ResearchData(
            cve_id=cve_id,
            description=description,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            severity=severity,
            cvss_version=cvss_version,
            cvss_bt_score=cvss_bt_score,
            cvss_bt_severity=cvss_bt_severity,
            published_date=published,
            last_modified=published,
            references=foundational.get("references", [])
        )
        
        # Add enhanced data from CVE Project (Layer 1 - Foundational)
        if foundational:
            # Use CVE Project's CPE data as primary source
            cve_cpe = foundational.get("cpe_affected", [])
            if cve_cpe:
                research_data.cpe_affected.extend(cve_cpe)
            
            # Map vendor advisories and patches from categorized references
            research_data.vendor_advisories = foundational.get("vendor_advisories", [])
            research_data.patches = foundational.get("patches", [])
            research_data.mitigations = foundational.get("mitigations", [])
            research_data.fix_versions = foundational.get("fix_versions", [])
            research_data.alternative_cvss_scores = foundational.get("alternative_cvss_scores", [])
            research_data.reference_tags = foundational.get("reference_tags", [])
            
            # Map product intelligence
            product_intel = foundational.get("product_intelligence", {})
            if product_intel:
                research_data.product_intelligence.vendors = product_intel.get("vendors", [])
                research_data.product_intelligence.products = product_intel.get("products", [])
                research_data.product_intelligence.affected_versions = product_intel.get("affected_versions", [])
                research_data.product_intelligence.platforms = product_intel.get("platforms", [])
                research_data.product_intelligence.modules = product_intel.get("modules", [])
            
            # Map enhanced problem type
            enhanced_problem = foundational.get("enhanced_problem_type", {})
            if enhanced_problem:
                research_data.enhanced_problem_type.type = enhanced_problem.get("type", "")
                research_data.enhanced_problem_type.description = enhanced_problem.get("description", "")
                research_data.enhanced_problem_type.cwe_mapping = enhanced_problem.get("cwe_mapping", [])
                research_data.enhanced_problem_type.primary_weakness = enhanced_problem.get("primary_weakness", "")
                research_data.enhanced_problem_type.secondary_weaknesses = enhanced_problem.get("secondary_weaknesses", [])
                research_data.enhanced_problem_type.vulnerability_categories = enhanced_problem.get("vulnerability_categories", [])
                research_data.enhanced_problem_type.impact_types = enhanced_problem.get("impact_types", [])
                research_data.enhanced_problem_type.attack_vectors = enhanced_problem.get("attack_vectors", [])
                research_data.enhanced_problem_type.enhanced_cwe_details = enhanced_problem.get("enhanced_cwe_details", [])
            
            # Map control mappings
            control_map = foundational.get("control_mappings", {})
            if control_map:
                research_data.control_mappings.nist_controls = control_map.get("nist_controls", [])
                research_data.control_mappings.recommended_controls = control_map.get("recommended_controls", [])
                research_data.control_mappings.security_categories = control_map.get("security_categories", [])
        
        # Add enhanced data from Patrowl (Layer 5 - Raw Intelligence) as fallback
        if raw_intelligence and not research_data.cpe_affected:
            # Use Patrowl CPE only if CVE Project didn't provide any
            patrowl_cpe = raw_intelligence.get("cpe_affected", [])
            research_data.cpe_affected.extend(patrowl_cpe)
        
        # Add exploit data with error handling and enhanced fields
        exploit_data = results.get(DataLayer.EXPLOIT_MECHANICS, {})
        exploits_added = 0
        for exploit in exploit_data.get("exploits", []):
            try:
                if exploit.get("url") and exploit.get("source") and exploit.get("type"):
                    research_data.exploits.append(ExploitReference(
                        url=exploit["url"],
                        source=exploit["source"],
                        type=exploit["type"],
                        verified=exploit.get("verified", False),
                        title=exploit.get("title", "")
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
        
        # Use threat data from Layer 4 sources (Real-World Context)
        # ThreatContextConnector now returns empty data after ARPSyndicate removal
        research_data.threat.in_kev = cvss_bt_threat_data.get("in_kev", False)
        research_data.threat.epss_score = cvss_bt_threat_data.get("epss_score")
        research_data.threat.actively_exploited = cvss_bt_threat_data.get("in_kev", False)
        research_data.threat.has_metasploit = cvss_bt_threat_data.get("has_metasploit", False)
        research_data.threat.has_nuclei = False  # Would come from other sources
        research_data.threat.has_exploitdb = cvss_bt_threat_data.get("has_exploitdb", False)
        research_data.threat.has_poc_github = cvss_bt_threat_data.get("has_poc_github", False)
        research_data.threat.vulncheck_kev = cvss_bt_threat_data.get("vulncheck_kev", False)
        
        # Add temporal CVSS fields - prefer CVE Project data over CVSS-BT
        temporal_cvss = foundational.get("temporal_cvss", {})
        if temporal_cvss:
            # Use temporal data from CVE Project (authoritative source)
            research_data.threat.exploit_code_maturity = temporal_cvss.get("exploit_code_maturity", "")
            research_data.threat.remediation_level = temporal_cvss.get("remediation_level", "")
            research_data.threat.report_confidence = temporal_cvss.get("report_confidence", "")
        else:
            # Fallback to CVSS-BT temporal data
            research_data.threat.exploit_code_maturity = cvss_bt_threat_data.get("exploit_code_maturity", "")
            research_data.threat.remediation_level = cvss_bt_threat_data.get("remediation_level", "")
            research_data.threat.report_confidence = cvss_bt_threat_data.get("report_confidence", "")
        
        # Add weakness data with complete mapping including Phase 3 enhancements
        weakness_data = results.get(DataLayer.WEAKNESS_TACTICS, {})
        if weakness_data:
            research_data.weakness.cwe_ids = weakness_data.get("cwe_ids", [])
            research_data.weakness.capec_ids = weakness_data.get("capec_ids", [])
            research_data.weakness.attack_techniques = weakness_data.get("attack_techniques", [])
            research_data.weakness.attack_tactics = weakness_data.get("attack_tactics", [])
            research_data.weakness.kill_chain_phases = weakness_data.get("kill_chain_phases", [])
            research_data.weakness.cwe_details = weakness_data.get("cwe_details", [])
            research_data.weakness.capec_details = weakness_data.get("capec_details", [])
            research_data.weakness.technique_details = weakness_data.get("technique_details", [])
            research_data.weakness.tactic_details = weakness_data.get("tactic_details", [])
            # Phase 3: Enhanced MITRE human-readable descriptions
            research_data.weakness.enhanced_technique_descriptions = weakness_data.get("enhanced_technique_descriptions", [])
            research_data.weakness.enhanced_tactic_descriptions = weakness_data.get("enhanced_tactic_descriptions", [])
            research_data.weakness.enhanced_capec_descriptions = weakness_data.get("enhanced_capec_descriptions", [])
            
        # Add alternative CWE mappings from CVE Project ADP entries
        if foundational:
            research_data.weakness.alternative_cwe_mappings = foundational.get("alternative_cwe_mappings", [])

        # Map CISA KEV details from MITRE connector if available
        mitre_kev_data = weakness_data.get("kev_info", {})
        if mitre_kev_data and mitre_kev_data.get("in_kev"):
            research_data.threat.in_kev = True
            research_data.threat.kev_vulnerability_name = mitre_kev_data.get("vulnerability_name", "")
            research_data.threat.kev_short_description = mitre_kev_data.get("short_description", "")
            research_data.threat.kev_vendor_project = mitre_kev_data.get("vendor_project", "")
            research_data.threat.kev_product = mitre_kev_data.get("product", "")
            research_data.threat.kev_date_added = mitre_kev_data.get("date_added", "")
            research_data.threat.kev_due_date = mitre_kev_data.get("due_date", "")
            research_data.threat.kev_required_action = mitre_kev_data.get("required_action", "")
            research_data.threat.kev_known_ransomware = mitre_kev_data.get("known_ransomware_use", "Unknown")
            research_data.threat.kev_notes = mitre_kev_data.get("notes", "")
        
        research_data.last_enriched = datetime.now()
        
        # Log data source summary
        sources_used = []
        if foundational:
            sources_used.append("CVEProject")
        if raw_intelligence:
            sources_used.append("Patrowl")
        if threat_context.get("cvss_bt"):
            sources_used.append("CVSS-BT")
        if results.get(DataLayer.EXPLOIT_MECHANICS):
            sources_used.append("Trickest")
        
        logger.debug(f"Data sources used for {cve_id}: {', '.join(sources_used)} (CVSS from {cvss_source}, EPSS from CVSS-BT)")
        
        # Add NIST 800-53 control mappings based on ATT&CK techniques
        if research_data.weakness.attack_techniques:
            control_mappings = self.control_mapper.get_controls_for_techniques(research_data.weakness.attack_techniques)
            
            # Store control data in structured control mappings field
            research_data.control_mappings.applicable_controls_count = control_mappings['applicable_controls_count']
            if control_mappings['control_categories']:
                research_data.control_mappings.control_categories = control_mappings['control_categories'].split('; ')
            if control_mappings['top_controls']:
                research_data.control_mappings.top_controls = control_mappings['top_controls'].split('; ')
        
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
        
        # Log session cache statistics
        logger.info(f"Session cache statistics: "
                   f"cache_hits={self.session_cache.session_stats['cache_hits']}, "
                   f"api_calls={self.session_cache.session_stats['api_calls']}, "
                   f"duplicate_cves={self.session_cache.session_stats['duplicate_cves']}")
        
        return results