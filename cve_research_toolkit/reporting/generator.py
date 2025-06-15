#!/usr/bin/env python3
"""Report generation module for CVE Research Toolkit.

Provides comprehensive reporting capabilities including Excel, CSV, JSON,
and Markdown export formats with detailed vulnerability analysis.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

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