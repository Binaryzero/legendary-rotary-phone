#!/usr/bin/env python3
"""Convenience script to start CVE Research Toolkit Web UI

This script provides an easy way to:
1. Run CVE research and automatically launch the web UI
2. Start the web UI with existing research data
3. Start the web UI with sample data for demonstration
"""

import argparse
import asyncio
from pathlib import Path
import sys
import time

def main():
    parser = argparse.ArgumentParser(
        description="Start CVE Research Toolkit Web UI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Start with sample data
  python3 start_webui.py --demo
  
  # Research CVEs and launch UI
  python3 start_webui.py --research cves.txt
  
  # Start UI with existing data
  python3 start_webui.py --data research_output/research_report_20241214.json
  
  # Start UI on different port
  python3 start_webui.py --demo --port 8090
        """
    )
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--demo', action='store_true', 
                      help='Start with sample/demo data')
    group.add_argument('--research', type=Path, metavar='CVE_FILE',
                      help='Research CVEs from file and launch UI')
    group.add_argument('--data', type=Path, metavar='JSON_FILE',
                      help='Load existing research data')
    group.add_argument('--empty', action='store_true',
                      help='Start with empty data (research from UI)')
    
    parser.add_argument('--host', default='localhost',
                       help='Host to bind to (default: localhost)')
    parser.add_argument('--port', type=int, default=8080,
                       help='Port to bind to (default: 8080)')
    parser.add_argument('--no-browser', action='store_true',
                       help='Do not open browser automatically')
    
    args = parser.parse_args()
    
    if args.demo:
        start_demo_ui(args)
    elif args.research:
        start_with_research(args)
    elif args.data:
        start_with_data(args)
    elif args.empty:
        start_empty_ui(args)

def start_demo_ui(args):
    """Start web UI with demo data."""
    print("Starting CVE Research Toolkit Web UI with demo data...")
    
    from cve_research_ui import CVEResearchUIServer
    
    server = CVEResearchUIServer(args.host, args.port)
    server.load_research_data()  # Loads sample data
    
    try:
        if server.start_server(open_browser=not args.no_browser):
            print("\\nDemo includes sample CVEs showcasing all Web UI features")
            print("To research real CVEs, use: python3 start_webui.py --research cves.txt")
            
            # Keep server running
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        print("\\nShutting down...")
        server.stop_server()

def start_with_research(args):
    """Research CVEs and start web UI."""
    if not args.research.exists():
        print(f"CVE file not found: {args.research}")
        sys.exit(1)
    
    print(f"Researching CVEs from {args.research}...")
    
    try:
        from cve_research_toolkit_fixed import main_research
        
        # Create output directory
        output_dir = Path("research_output")
        output_dir.mkdir(exist_ok=True)
        
        # Research CVEs and export for web UI
        import time
        webui_file = output_dir / f"webui_data_{Path().resolve().name}_{int(time.time())}.json"
        
        print("⚙️  Running CVE research...")
        main_research(
            input_file=str(args.research),
            format=['webui'],
            output_dir=str(output_dir)
        )
        
        # Find the most recent webui export
        webui_files = list(output_dir.glob("*.webui"))
        if not webui_files:
            print("No web UI data file generated")
            sys.exit(1)
        
        latest_file = max(webui_files, key=lambda p: p.stat().st_mtime)
        
        print(f"Research complete! Starting web UI with {latest_file}...")
        
        # Start web UI
        from cve_research_ui import CVEResearchUIServer
        
        server = CVEResearchUIServer(args.host, args.port)
        server.load_research_data(latest_file)
        
        try:
            if server.start_server(open_browser=not args.no_browser):
                # Keep server running
                while True:
                    import time
                    time.sleep(1)
        except KeyboardInterrupt:
            print("\\nShutting down...")
            server.stop_server()
            
    except ImportError:
        print("CVE Research Toolkit not available")
        sys.exit(1)
    except Exception as e:
        print(f"Research failed: {e}")
        sys.exit(1)

def start_with_data(args):
    """Start web UI with existing data file."""
    if not args.data.exists():
        print(f"Data file not found: {args.data}")
        sys.exit(1)
    
    print(f"Starting CVE Research Toolkit Web UI with {args.data}...")
    
    from cve_research_ui import CVEResearchUIServer
    
    server = CVEResearchUIServer(args.host, args.port)
    server.load_research_data(args.data)
    
    try:
        if server.start_server(open_browser=not args.no_browser):
            # Keep server running
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        print("\\nShutting down...")
        server.stop_server()

def start_empty_ui(args):
    """Start web UI with empty data for interactive research."""
    print("Starting CVE Research Toolkit Web UI (empty - ready for research)...")
    
    from cve_research_ui import CVEResearchUIServer
    
    server = CVEResearchUIServer(args.host, args.port)
    server.load_research_data(None)  # Starts with empty data
    
    try:
        if server.start_server(open_browser=not args.no_browser):
            print("\\nEnter CVE IDs in the research panel to start analyzing vulnerabilities")
            print("Export your research results using the export buttons")
            # Keep server running
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        print("\\nShutting down...")
        server.stop_server()

if __name__ == '__main__':
    main()