"""Test CLI entry points and integration."""

import subprocess
import sys
from pathlib import Path


def test_odin_cli_import():
    """Test that odin_cli.py can import correctly."""
    # Add project root to path
    project_root = Path(__file__).parent.parent
    sys.path.insert(0, str(project_root))
    
    try:
        from odin.cli import cli_main, main_research
        from odin.core.engine import VulnerabilityResearchEngine
        assert True, "CLI imports successful"
    except ImportError as e:
        assert False, f"CLI import failed: {e}"


def test_odin_cli_help():
    """Test that odin_cli.py --help works."""
    project_root = Path(__file__).parent.parent
    cli_path = project_root / "odin_cli.py"
    
    result = subprocess.run(
        [sys.executable, str(cli_path), "--help"],
        capture_output=True,
        text=True,
        cwd=project_root
    )
    
    assert result.returncode == 0, f"CLI help failed: {result.stderr}"
    assert "ODIN (OSINT Data Intelligence Nexus)" in result.stdout
    assert "Multi-Source Intelligence Platform" in result.stdout


def test_engine_creation():
    """Test that VulnerabilityResearchEngine can be created."""
    project_root = Path(__file__).parent.parent
    sys.path.insert(0, str(project_root))
    
    from odin.core.engine import VulnerabilityResearchEngine
    
    config = {'sources': {'cve_project': True}}
    try:
        engine = VulnerabilityResearchEngine(config)
        assert engine is not None, "Engine creation failed"
    except Exception as e:
        assert False, f"Engine creation failed: {e}"


def test_start_odin_ui_exists():
    """Test that start_odin_ui.py exists and is executable."""
    project_root = Path(__file__).parent.parent
    ui_path = project_root / "start_odin_ui.py"
    
    assert ui_path.exists(), "start_odin_ui.py does not exist"
    assert ui_path.is_file(), "start_odin_ui.py is not a file"