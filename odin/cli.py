#!/usr/bin/env python3
"""Command-line interface for ODIN.

Provides click-based CLI for multi-source vulnerability intelligence research.
"""

import asyncio
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple

# Optional imports with fallbacks
try:
    import click
    CLICK_AVAILABLE = True
except ImportError:
    click = None  # type: ignore
    CLICK_AVAILABLE = False


try:
    from rich.console import Console as RichConsole
    from rich.panel import Panel as RichPanel
    from rich.logging import RichHandler
    RICH_AVAILABLE = True
    
    # Type aliases for mypy
    Console = RichConsole
    Panel = RichPanel
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
    
    RichHandler = None  # type: ignore

# Import components from the modular structure
from .core.engine import VulnerabilityResearchEngine
from .reporting.generator import ResearchReportGenerator
from .utils.config import load_config, DEFAULT_CONFIG

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
        """ODIN (OSINT Data Intelligence Nexus) - Multi-Source Intelligence Platform"""
        main_research(input_file, list(format), output_dir, config, detailed)
    
    click_main()


def main_research(input_file: str = 'cves.txt', format: List[str] = ['markdown'], output_dir: str = 'research_output', 
                 config: str = DEFAULT_CONFIG, detailed: bool = False) -> None:
    """ODIN (OSINT Data Intelligence Nexus) - Multi-Source Intelligence Platform
    
    Integrates data from:
    - CVEProject/cvelistV5 (Foundational)
    - trickest/cve (Exploit PoCs)
    - MITRE CTI (Tactics & Weaknesses)
    - CISA KEV & EPSS (Threat Context)
    """
    # Display banner
    console.print(Panel.fit(
        "[bold blue]ODIN (OSINT Data Intelligence Nexus)[/bold blue]\n"
        "[dim]Multi-Source Vulnerability Intelligence Platform[/dim]",
        border_style="blue"
    ))
    
    # Load configuration
    config_data = load_config(config)
    
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
    if research_results:
        avg_cvss = sum(rd.cvss_score for rd in research_results) / len(research_results)
        console.print(f"- Average CVSS score: {avg_cvss:.1f}")
    else:
        console.print("- Average CVSS score: N/A")
    console.print(f"- Threat intelligence coverage: {sum(1 for rd in research_results if rd.threat.epss_score or rd.threat.in_kev)}/{len(research_results)} CVEs")


if __name__ == "__main__":
    cli_main()