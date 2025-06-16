#!/usr/bin/env python3
"""
ODIN CLI - Command Line Interface for OSINT Data Intelligence Nexus
Direct CLI access to ODIN vulnerability intelligence platform.
"""

import sys
from pathlib import Path

# Add the current directory to Python path for imports
sys.path.insert(0, str(Path(__file__).parent))

if __name__ == "__main__":
    try:
        from odin.cli import cli_main
        cli_main()
    except ImportError as e:
        print(f"Error importing ODIN modules: {e}")
        print("Please ensure ODIN is properly installed.")
        sys.exit(1)