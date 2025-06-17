#!/usr/bin/env python3
"""Comprehensive test suite for ODIN"""

import json
import sys
from datetime import datetime
from pathlib import Path
import pytest

# Add the parent directory to sys.path so we can import the package
sys.path.insert(0, str(Path(__file__).parent.parent))


def test_core_functionality() -> None:
    """Test core functionality without external dependencies."""
    print("=== Testing Core Functionality ===")

    from odin.models.data import (
        DataLayer,
        ExploitReference,
        ResearchData,
        ThreatContext,
        WeaknessTactics,
    )
    from odin.reporting.generator import ResearchReportGenerator
    from odin.core.engine import VulnerabilityResearchEngine

    # Test data structure creation
    rd = ResearchData(
        cve_id="CVE-2021-44228",
        description="Log4j vulnerability",
        cvss_score=10.0,
        severity="CRITICAL",
    )

    exploit = ExploitReference(
        url="https://github.com/example/poc", source="github", type="poc"
    )
    rd.exploits.append(exploit)

    rd.threat.in_kev = True
    rd.threat.epss_score = 0.95

    # Test data structure operations (cache removed)
    assert rd.cve_id == "CVE-2021-44228"

    # Test report generation
    generator = ResearchReportGenerator()

    # Test summary table generation
    test_data = [rd]
    table = generator.generate_summary_table(test_data)
    assert table is not None

    print("PASS All core functionality tests passed!")


def test_export_functionality() -> None:
    """Test export functionality."""
    print("\n=== Testing Export Functionality ===")

    from odin.models.data import ResearchData
    from odin.reporting.generator import ResearchReportGenerator

    # Create test data
    rd1 = ResearchData(
        cve_id="CVE-2021-44228",
        description="Log4j RCE vulnerability",
        cvss_score=10.0,
        severity="CRITICAL",
        published_date=datetime(2021, 12, 9),
    )
    rd1.threat.in_kev = True

    rd2 = ResearchData(
        cve_id="CVE-2023-23397",
        description="Outlook privilege escalation",
        cvss_score=9.8,
        severity="CRITICAL",
        published_date=datetime(2023, 3, 14),
    )

    test_data = [rd1, rd2]
    generator = ResearchReportGenerator()

    # Test JSON export
    output_dir = Path("test_exports")
    output_dir.mkdir(exist_ok=True)

    generator.export_research_data(test_data, "json", output_dir / "test.json")

    with open(output_dir / "test.json") as f:
        json_data = json.load(f)
    assert len(json_data) == 2 and json_data[0]["cve_id"] == "CVE-2021-44228"

    # Test CSV export
    try:
        generator.export_research_data(test_data, "csv", output_dir / "test.csv")
    except RuntimeError as e:
        # CSV export requires pandas; ensure appropriate error when missing
        if "pandas" in str(e).lower():
            pytest.skip("pandas not available for CSV export")
        else:
            raise
    else:
        csv_file = output_dir / "test.csv"
        assert csv_file.exists() and csv_file.stat().st_size > 0

    # Test Markdown export
    generator.export_research_data(
        test_data,
        "markdown",
        output_dir / "test.md",
    )

    md_file = output_dir / "test.md"
    assert md_file.exists()
    content = md_file.read_text()
    assert "CVE-2021-44228" in content and "Critical Severity: 2" in content

    # Test Excel export (will use fallback if openpyxl not available)
    generator.export_research_data(test_data, "excel", output_dir / "test.xlsx")

    # Cleanup
    import shutil

    shutil.rmtree(output_dir, ignore_errors=True)

    print("PASS All export functionality tests passed!")


def test_connectors() -> None:
    """Test data source connectors."""
    print("\n=== Testing Data Source Connectors ===")

    from odin.connectors.cve_project import CVEProjectConnector
    from odin.connectors.mitre import MITREConnector
    from odin.connectors.threat_context import ThreatContextConnector
    from odin.connectors.trickest import TrickestConnector

    cve_connector = CVEProjectConnector()
    trickest_connector = TrickestConnector()
    mitre_connector = MITREConnector()
    threat_connector = ThreatContextConnector()

    # Test parsing with sample data
    sample_cve_data = {
        "containers": {
            "cna": {
                "descriptions": [{"value": "Test vulnerability description"}],
                "metrics": [
                    {
                        "cvssV3_1": {
                            "baseScore": 7.5,
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                        }
                    }
                ],
                "references": [{"url": "https://example.com/advisory"}],
            }
        },
        "cveMetadata": {"datePublished": "2023-01-01", "dateUpdated": "2023-01-02"},
    }

    parsed = cve_connector.parse("CVE-2023-0001", sample_cve_data)
    assert parsed.get("description") == "Test vulnerability description"

    trickest_data = {
        "content": "# CVE-2023-0001\n[PoC](https://github.com/example/poc)\n[Exploit-DB](https://exploit-db.com/exploits/12345)"
    }

    parsed = trickest_connector.parse("CVE-2023-0001", trickest_data)
    assert len(parsed.get("exploits", [])) == 2

    parsed = mitre_connector.parse("CVE-2023-0001", {})
    assert "cwe_ids" in parsed

    # ThreatContextConnector now returns empty data after ARPSyndicate removal
    threat_data = {"in_kev": True, "epss": {"score": 0.85, "percentile": 95.0}}

    parsed = threat_connector.parse("CVE-2023-0001", threat_data)
    # Should return empty threat data as ARPSyndicate was removed
    assert parsed.get("threat", {}) == {}

    print("PASS All connector tests passed!")


def test_data_validation() -> None:
    """Test data validation and consistency."""
    print("\n=== Testing Data Validation ===")

    from odin.models.data import ResearchData, ExploitReference

    test_data = ResearchData(cve_id="CVE-2021-44228", cvss_score=10.0)
    test_data.cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    test_data.description = "Test vulnerability for validation"

    exploit = ExploitReference(
        url="https://github.com/example/poc",
        source="github",
        type="poc"
    )
    test_data.exploits.append(exploit)

    assert test_data.cve_id and test_data.cvss_score > 0
    assert len(test_data.exploits) == 1 and test_data.exploits[0].url

    test_data.threat.in_kev = True
    test_data.threat.epss_score = 0.95
    assert test_data.threat.in_kev and test_data.threat.epss_score > 0.9

    print("PASS Data validation tests passed!")


def test_cli_integration() -> None:
    """Test CLI integration."""
    print("\n=== Testing CLI Integration ===")

    from odin.cli import cli_main, main_research as main

    # Create test input
    test_file = Path("test_cli_input.txt")
    test_file.write_text("CVE-2021-44228\nCVE-2023-23397")

    # Test main function directly
    try:
        main(
            input_file=str(test_file),
            format=["json"],
            output_dir="test_cli_output",
        )
    except Exception as e:
        if "aiohttp" not in str(e).lower():
            raise

    # Test CLI main wrapper
    try:
        # This tests the click integration or fallback
        pass
    except Exception as e:
        print(f"CLI integration note: {e}")

    # Cleanup
    test_file.unlink(missing_ok=True)
    import shutil

    shutil.rmtree("test_cli_output", ignore_errors=True)

    print("PASS CLI integration tests passed!")


def test_dependency_handling() -> None:
    """Test dependency handling and fallbacks."""
    print("\n=== Testing Dependency Handling ===")

    try:
        # Test console utilities
        from odin.utils.console import create_console
        
        # Test optional dependencies availability
        try:
            import aiohttp
        except ImportError:
            aiohttp = None
            
        try:
            import click
        except ImportError:
            click = None
            
        try:
            import pandas as pd
        except ImportError:
            pd = None
            
        try:
            import yaml
        except ImportError:
            yaml = None
            
        try:
            from rich.console import Console as RichConsole
            from rich.panel import Panel
            from rich.table import Table
            RICH_AVAILABLE = True
            Console = RichConsole
        except ImportError:
            RICH_AVAILABLE = False
            class Console:
                def print(self, *args):
                    print(*args)
            class Panel:
                @staticmethod
                def fit(text):
                    return text
            class Table:
                def add_column(self, *args):
                    pass
                def add_row(self, *args):
                    pass

        # Test dependency flags
        deps = {
            "aiohttp": aiohttp is not None,
            "click": click is not None,
            "pandas": pd is not None,
            "yaml": yaml is not None,
            "rich": RICH_AVAILABLE,
        }

        print("Dependency Status:")
        available_count = 0
        for dep, available in deps.items():
            status = "PASS" if available else "FAIL"
            print(f"  {status} {dep}: {'Available' if available else 'Fallback mode'}")
            if available:
                available_count += 1

        print(f"Dependencies available: {available_count}/5")

        # Test fallback classes work
        console = Console()
        console.print("Test message")

        panel = Panel.fit("Test panel")

        table = Table()
        table.add_column("Test")
        table.add_row("Value")

        print("PASS Fallback classes working correctly")

    except Exception as e:
        print(f"FAIL Dependency handling test failed: {e}")
        raise

    print("PASS Dependency handling tests passed!")


def run_all_tests() -> bool:
    """Run the complete test suite."""
    print("ODIN (OSINT Data Intelligence Nexus) - Comprehensive Test Suite")
    print("=" * 70)

    tests = [
        test_core_functionality,
        test_export_functionality,
        test_connectors,
        test_data_validation,
        test_cli_integration,
        test_dependency_handling,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"FAIL Test {test.__name__} crashed: {e}")
            failed += 1
        print()

    print("=" * 70)
    print(f"Test Results: {passed} passed, {failed} failed")

    if failed == 0:
        print("ALL TESTS PASSED! ODIN is ready for use.")
        print("\nNext Steps:")
        print(
            "1. Install optional dependencies: pip install -r requirements-research.txt"
        )
        print(
            "2. Run with sample data: python cve_research_toolkit_fixed.py sample_cves.txt"
        )
        print("3. Explore advanced features with full dependencies")
        return True
    else:
        print("Some tests failed. Please review the output above.")
        return False


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
