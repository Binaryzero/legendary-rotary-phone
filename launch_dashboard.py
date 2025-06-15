#!/usr/bin/env python3
"""
CVE Research Toolkit - Streamlit Dashboard Launcher

Launches the enterprise-grade Streamlit dashboard for vulnerability intelligence.
"""

import subprocess
import sys
from pathlib import Path

def main():
    """Launch the Streamlit dashboard."""
    dashboard_path = Path(__file__).parent / "streamlit_app.py"
    
    if not dashboard_path.exists():
        print("Error: Streamlit dashboard file not found")
        sys.exit(1)
    
    print("Launching CVE Research Toolkit Dashboard...")
    print("Enterprise Vulnerability Intelligence Platform")
    print(f"Dashboard will open at: http://localhost:8501")
    print("Press Ctrl+C to stop the server")
    print()
    
    try:
        subprocess.run([
            sys.executable, "-m", "streamlit", "run", 
            str(dashboard_path),
            "--server.address", "localhost",
            "--server.port", "8501",
            "--browser.gatherUsageStats", "false"
        ])
    except KeyboardInterrupt:
        print("\nDashboard stopped")
    except Exception as e:
        print(f"Error launching dashboard: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()