#!/usr/bin/env python3
"""Report generation module for ODIN.

Provides comprehensive reporting capabilities including Excel, CSV, JSON,
and Markdown export formats with detailed vulnerability analysis.
"""

import csv
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from ..version import get_version_info, get_version_string

# Optional imports with fallbacks
try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    pd = None
    PANDAS_AVAILABLE = False

try:
    from rich.console import Console as RichConsole
    from rich.table import Table as RichTable
    RICH_AVAILABLE = True
    
    # Type aliases for mypy
    Console = RichConsole
    Table = RichTable
except ImportError:
    RICH_AVAILABLE = False
    # Simple fallback classes
    class Console:  # type: ignore
        def print(self, *args: Any) -> None:
            print(*args)
    
    class Table:  # type: ignore
        def __init__(self, **_: Any) -> None:
            pass
        def add_column(self, *_: Any, **__: Any) -> None:
            pass
        def add_row(self, *_: Any) -> None:
            pass

# Import models from the new structure
from ..models.data import ResearchData

console = Console()


class ResearchReportGenerator:
    """Generate comprehensive research reports."""
    
    def __init__(self) -> None:
        self.console = console
    
    def _sanitize_csv_text(self, text: str) -> str:
        """Sanitize text for CSV export by removing problematic characters."""
        if not text:
            return ""
        
        # Remove HTML tags
        text = re.sub(r'<[^>]+>', '', text)
        
        # Replace multiple whitespace/newlines with single space
        text = re.sub(r'\s+', ' ', text)
        
        # Remove non-printable characters except common ones
        text = ''.join(char for char in text if char.isprintable() or char in '\t\n\r')
        
        # Trim whitespace
        text = text.strip()
        
        return text
    
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
                threat_info.append(f"EPSS:{rd.threat.epss_score * 100:.1f}%")
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
            epss = f"{rd.threat.epss_score * 100:.1f}%" if rd.threat.epss_score else "N/A"
            
            # Add row
            table.add_row(
                rd.cve_id,
                f"[{severity_color}]{rd.severity}[/{severity_color}]",
                f"{rd.cvss_score:.1f}",
                exploit_info,
                kev_status,
                epss,
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
            report.append(f"**EPSS Score**: {rd.threat.epss_score * 100:.1f}%")
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
        - webui: JSON format optimized for web UI visualization
        - markdown: Detailed markdown reports
        
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
            self._export_markdown(research_data, output_path)
        else:
            raise ValueError(f"Unsupported export format: {format}. Supported: json, csv, excel, webui, markdown")
    
    def _export_json(self, data: List[ResearchData], path: Path) -> None:
        """Export to JSON format with version metadata."""
        json_data = [self._research_data_to_dict(rd) for rd in data]
        
        # Add version metadata to export
        export_data = {
            "metadata": {
                **get_version_info(),
                "export_timestamp": datetime.now().isoformat(),
                "total_cves": len(data),
                "format": "ODIN JSON Export"
            },
            "data": json_data
        }
        
        with open(path, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)
        
        console.print(f"[green]✓[/green] Research data exported to {path}")
    
    def _research_data_to_dict(self, rd: ResearchData) -> Dict[str, Any]:
        """Convert ResearchData to comprehensive dictionary for JSON export."""
        # Get the standardized row data for consistency
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
                "has_metasploit": rd.threat.has_metasploit,
                "has_nuclei": rd.threat.has_nuclei,
                "has_exploitdb": rd.threat.has_exploitdb,
                "has_poc_github": rd.threat.has_poc_github,
                "actively_exploited": rd.threat.actively_exploited,
                "ransomware_campaign": rd.threat.ransomware_campaign,
                "kev_vulnerability_name": rd.threat.kev_vulnerability_name,
                "kev_short_description": rd.threat.kev_short_description,
                "kev_vendor_project": rd.threat.kev_vendor_project,
                "kev_product": rd.threat.kev_product,
                "kev_date_added": rd.threat.kev_date_added,
                "kev_due_date": rd.threat.kev_due_date,
                "kev_required_action": rd.threat.kev_required_action,
                "kev_known_ransomware": rd.threat.kev_known_ransomware,
                "kev_notes": rd.threat.kev_notes,
                "exploit_code_maturity": rd.threat.exploit_code_maturity,
                "remediation_level": rd.threat.remediation_level,
                "report_confidence": rd.threat.report_confidence
            },
            
            # Phase 1 Enhanced Fields
            "cvss_version": rd.cvss_version,
            "cvss_bt_score": rd.cvss_bt_score,
            "cvss_bt_severity": rd.cvss_bt_severity,
            "alternative_cvss_scores": rd.alternative_cvss_scores,
            "reference_tags": rd.reference_tags,
            "mitigations": rd.mitigations,
            "fix_versions": rd.fix_versions,
            
            # Enhanced problem type analysis
            "enhanced_problem_type": {
                "primary_weakness": rd.enhanced_problem_type.primary_weakness,
                "secondary_weaknesses": rd.enhanced_problem_type.secondary_weaknesses,
                "vulnerability_categories": rd.enhanced_problem_type.vulnerability_categories,
                "impact_types": rd.enhanced_problem_type.impact_types,
                "attack_vectors": rd.enhanced_problem_type.attack_vectors,
                "enhanced_cwe_details": rd.enhanced_problem_type.enhanced_cwe_details
            },
            
            # Product intelligence
            "product_intelligence": {
                "vendors": rd.product_intelligence.vendors,
                "products": rd.product_intelligence.products,
                "affected_versions": rd.product_intelligence.affected_versions,
                "platforms": rd.product_intelligence.platforms,
                "modules": rd.product_intelligence.modules
            },
            
            # Control mappings
            "control_mappings": {
                "applicable_controls_count": rd.control_mappings.applicable_controls_count,
                "control_categories": rd.control_mappings.control_categories,
                "top_controls": rd.control_mappings.top_controls
            },
            
            # Include all CSV/Excel fields for consistency
            "csv_row_data": row_data
        }
    

    def _generate_export_row(self, rd: ResearchData) -> Dict[str, Any]:
        """
        Generates a standardized dictionary representing a single CVE's data for CSV or Excel export.
        
        The export row includes core CVE details, CVSS metrics, threat intelligence, exploit information, enhanced vulnerability classification, NIST 800-53 control mappings, and detailed product intelligence. Fields are formatted and sanitized for compatibility with tabular data exports.
        
        Args:
            rd: The ResearchData object containing aggregated vulnerability intelligence.
        
        Returns:
            A dictionary mapping column names to values for export.
        """
        # Use structured patch and vendor advisory data (already categorized by CVE Project)
        fix_versions = rd.patches if rd.patches else []
        mitigations = rd.vendor_advisories if rd.vendor_advisories else []
        
        # Format affected products using product intelligence first, then CPE fallback
        affected_str = ""
        if rd.product_intelligence.vendors and rd.product_intelligence.products:
            # Use structured product intelligence
            affected_parts = []
            vendors = rd.product_intelligence.vendors[:5]  # Limit to 5 vendors
            products = rd.product_intelligence.products[:5]  # Limit to 5 products
            versions = rd.product_intelligence.affected_versions[:10] if rd.product_intelligence.affected_versions else ['*']
            
            for vendor in vendors:
                for product in products:
                    for version in versions[:3]:  # Max 3 versions per product
                        affected_parts.append(f"{vendor} {product} {version}")
            
            affected_str = "; ".join(affected_parts)
        elif rd.cpe_affected:
            # Fallback to parsing CPE strings
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
            'Description': rd.description,
            'CVSS': rd.cvss_score,
            'Severity': rd.severity,
            'Vector': rd.cvss_vector,
            'CVSS Version': rd.cvss_version,
            'CVSS-BT Score': rd.cvss_bt_score,
            'CVSS-BT Severity': rd.cvss_bt_severity,
            'CWE': self._sanitize_csv_text('; '.join(rd.weakness.cwe_details) if rd.weakness.cwe_details else '; '.join(rd.weakness.cwe_ids) if rd.weakness.cwe_ids else ''),
            'Exploit': 'Yes' if exploit_urls else 'No',
            'ExploitRefs': self._sanitize_csv_text('; '.join(exploit_urls)),
            'FixVersion': fix_versions[0] if fix_versions else '',
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
            'Technology Stack': self._sanitize_csv_text('; '.join(rd.product_intelligence.products) if rd.product_intelligence.products else ''),
            'CISA KEV': 'Yes' if rd.threat.in_kev else 'No',
            'Ransomware Campaign Use': 'Yes' if rd.threat.ransomware_campaign else 'No',
            'KEV Vulnerability Name': self._sanitize_csv_text(rd.threat.kev_vulnerability_name or ''),
            'KEV Vendor Project': self._sanitize_csv_text(rd.threat.kev_vendor_project or ''),
            'KEV Product': self._sanitize_csv_text(rd.threat.kev_product or ''),
            'KEV Short Description': self._sanitize_csv_text(rd.threat.kev_short_description or ''),
            'KEV Date Added': rd.threat.kev_date_added or '',
            'KEV Due Date': rd.threat.kev_due_date or '',
            'KEV Required Action': self._sanitize_csv_text(rd.threat.kev_required_action or ''),
            'KEV Known Ransomware': rd.threat.kev_known_ransomware or '',
            'KEV Notes': self._sanitize_csv_text(rd.threat.kev_notes or ''),
            'VulnCheck KEV': 'Yes' if rd.threat.vulncheck_kev else 'No',
            'EPSS Score': f"{rd.threat.epss_score * 100:.1f}%" if rd.threat.epss_score else '',
            'Actively Exploited': 'Yes' if rd.threat.actively_exploited else 'No',
            'Has Metasploit': 'Yes' if rd.threat.has_metasploit else 'No',
            'Has Nuclei': 'Yes' if rd.threat.has_nuclei else 'No',
            'Has ExploitDB': 'Yes' if rd.threat.has_exploitdb else 'No',
            'Has PoC GitHub': 'Yes' if rd.threat.has_poc_github else 'No',
            
            # Temporal CVSS fields (extracted from CVSS vectors)
            'Exploit Code Maturity': rd.threat.exploit_code_maturity or '',
            'Remediation Level': rd.threat.remediation_level or '',
            'Report Confidence': rd.threat.report_confidence or '',
            
            'CAPEC IDs': self._sanitize_csv_text('; '.join(rd.weakness.capec_details) if rd.weakness.capec_details else '; '.join(rd.weakness.capec_ids) if rd.weakness.capec_ids else ''),
            'Attack Techniques': self._sanitize_csv_text('; '.join(rd.weakness.technique_details) if rd.weakness.technique_details else '; '.join(rd.weakness.attack_techniques) if rd.weakness.attack_techniques else ''),
            'Attack Tactics': self._sanitize_csv_text('; '.join(rd.weakness.tactic_details) if rd.weakness.tactic_details else '; '.join(rd.weakness.attack_tactics) if rd.weakness.attack_tactics else ''),
            'Kill Chain Phases': self._sanitize_csv_text('; '.join(rd.weakness.kill_chain_phases) if rd.weakness.kill_chain_phases else ''),
            'Reference Count': len(rd.references),
            'CPE Affected Count': len(rd.cpe_affected),
            'Vendor Advisory Count': len(rd.vendor_advisories),
            'Patch Reference Count': len(rd.patches),
            'Vendor Advisories': self._sanitize_csv_text('; '.join(rd.vendor_advisories) if rd.vendor_advisories else ''),
            'Patches': self._sanitize_csv_text('; '.join(rd.patches) if rd.patches else ''),
            'Mitigations': self._sanitize_csv_text('; '.join(rd.mitigations) if rd.mitigations else ''),
            'Fix Versions': self._sanitize_csv_text('; '.join(rd.fix_versions) if rd.fix_versions else ''),
            
            # Phase 2 Intelligence Enhancement
            'Alternative CVSS Count': len(rd.alternative_cvss_scores),
            'Alternative CVSS Scores': self._sanitize_csv_text('; '.join([f"{alt['provider']}: {alt['score']}" for alt in rd.alternative_cvss_scores]) if rd.alternative_cvss_scores else ''),
            'Reference Tags': self._sanitize_csv_text('; '.join(rd.reference_tags) if rd.reference_tags else ''),
            'Verified Exploits': sum(1 for e in rd.exploits if e.verified),
            'Exploit Titles': self._sanitize_csv_text('; '.join([e.title for e in rd.exploits if e.title]) if rd.exploits else ''),
            
            # Enhanced Problem Type Analysis fields
            'Primary Weakness': self._sanitize_csv_text(rd.enhanced_problem_type.primary_weakness),
            'Secondary Weaknesses': self._sanitize_csv_text('; '.join(rd.enhanced_problem_type.secondary_weaknesses)),
            'Vulnerability Categories': self._sanitize_csv_text('; '.join(rd.enhanced_problem_type.vulnerability_categories)),
            'Impact Types': self._sanitize_csv_text('; '.join(rd.enhanced_problem_type.impact_types)),
            'Attack Vectors (Classification)': self._sanitize_csv_text('; '.join(rd.enhanced_problem_type.attack_vectors)),
            'Enhanced CWE Details': self._sanitize_csv_text('; '.join(rd.enhanced_problem_type.enhanced_cwe_details)),
            
            # Phase 3 MITRE Enhancement
            'Enhanced ATT&CK Techniques': self._sanitize_csv_text('; '.join(rd.weakness.enhanced_technique_descriptions)),
            'Enhanced ATT&CK Tactics': self._sanitize_csv_text('; '.join(rd.weakness.enhanced_tactic_descriptions)),
            'Enhanced CAPEC Descriptions': self._sanitize_csv_text('; '.join(rd.weakness.enhanced_capec_descriptions)),
            'Alternative CWE Mappings': self._sanitize_csv_text('; '.join(rd.weakness.alternative_cwe_mappings)),
            
            # NIST 800-53 Control Mapping fields
            'Applicable_Controls_Count': str(rd.control_mappings.applicable_controls_count),
            'Control_Categories': self._sanitize_csv_text('; '.join(rd.control_mappings.control_categories)),
            'Top_Controls': self._sanitize_csv_text('; '.join(rd.control_mappings.top_controls)),
            
            # Enhanced Product Intelligence fields
            'Affected Vendors': self._sanitize_csv_text('; '.join(rd.product_intelligence.vendors)),
            'Affected Products': self._sanitize_csv_text('; '.join(rd.product_intelligence.products)),
            'Affected Versions': self._sanitize_csv_text('; '.join(rd.product_intelligence.affected_versions)),
            'Affected Platforms': self._sanitize_csv_text('; '.join(rd.product_intelligence.platforms)),
            'Affected Modules': self._sanitize_csv_text('; '.join(rd.product_intelligence.modules))
        }
    
    def _truncate_field(self, value: Any, limit: int, is_url_field: bool = False) -> Any:
        """
        Truncate a field value if it exceeds the character limit.
        
        For URL fields (containing semicolons), truncate at the nearest semicolon
        to preserve complete URLs rather than breaking mid-URL.
        
        Args:
            value: The field value to potentially truncate
            limit: Maximum character limit
            is_url_field: Whether this field contains semicolon-separated URLs
            
        Returns:
            The original value or truncated value if it exceeded the limit
        """
        if not isinstance(value, str) or len(value) <= limit:
            return value
        
        if is_url_field and ';' in value:
            # Find the last semicolon before the limit
            truncated = value[:limit]
            last_semicolon = truncated.rfind(';')
            if last_semicolon > 0:
                # Truncate at the semicolon to keep complete URLs
                return value[:last_semicolon]
        
        # For non-URL fields or if no semicolon found, just truncate
        return value[:limit]
    
    def _export_csv(self, data: List[ResearchData], path: Path) -> None:
        """
        Exports research data to a CSV file with standardized fields.
        
        Ensures Excel compatibility by truncating fields that exceed Excel's 
        32,767 character limit per cell.
        
        Args:
            data: List of ResearchData objects to export.
            path: Destination file path for the CSV output.
        
        Raises:
            RuntimeError: If pandas is not available.
        """
        rows = []
        for rd in data:
            rows.append(self._generate_export_row(rd))
        
        if not pd:
            raise RuntimeError("pandas is required for CSV export")
        
        # Convert to DataFrame
        df = pd.DataFrame(rows)
        
        # Excel has a 32,767 character limit per cell
        EXCEL_CHAR_LIMIT = 32767
        
        # Truncate any fields that exceed Excel's character limit
        # For URL fields (containing semicolons), truncate at the nearest semicolon
        url_columns = ['ExploitRefs', 'References', 'Mitigations', 'Patches', 'Vendor Advisories']
        
        for col in df.columns:
            df[col] = df[col].apply(lambda x: self._truncate_field(x, EXCEL_CHAR_LIMIT, col in url_columns))
        
        # Export with proper CSV settings for Excel compatibility
        df.to_csv(path, index=False, encoding='utf-8-sig', quoting=csv.QUOTE_MINIMAL)
        
        console.print(f"[green]✓[/green] Research data exported to {path} (Excel-compatible)")
    
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
                    threat_info.append(f"High EPSS ({rd.threat.epss_score * 100:.1f}%)")
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
        console.print(f"[green]✓[/green] Research data exported to {path}")