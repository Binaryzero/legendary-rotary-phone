#!/usr/bin/env python3
"""
Simplified ODIN UI launcher - No API backend needed
Serves static React frontend and executes CLI directly
"""

import subprocess
import sys
import time
import os
import json
from pathlib import Path
from http.server import HTTPServer, SimpleHTTPRequestHandler
import threading
import urllib.parse

class OdinRequestHandler(SimpleHTTPRequestHandler):
    """Custom request handler for ODIN UI"""
    
    def __init__(self, *args, **kwargs):
        # Set the directory to serve from
        self.directory = str(Path("frontend/build").absolute())
        super().__init__(*args, directory=self.directory, **kwargs)
    
    def do_POST(self):
        """Handle CLI execution requests"""
        if self.path == "/api/research":
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))
            
            # Extract CVE IDs from request
            cve_ids = data.get('cve_ids', [])
            if not cve_ids:
                self.send_error(400, "No CVE IDs provided")
                return
            
            # Create temporary input file
            temp_input = Path("temp_cves.txt")
            temp_input.write_text("\n".join(cve_ids))
            
            # Execute CLI
            try:
                result = subprocess.run([
                    sys.executable, "odin_cli.py", 
                    str(temp_input),
                    "--output-dir", "research_output"
                ], capture_output=True, text=True)
                
                if result.returncode == 0:
                    # Find the latest JSON file
                    output_dir = Path("research_output")
                    json_files = sorted(output_dir.glob("research_report_*.json"), 
                                      key=lambda p: p.stat().st_mtime, reverse=True)
                    
                    if json_files:
                        # Read and return the JSON data
                        with open(json_files[0], 'r') as f:
                            json_data = json.load(f)
                        
                        self.send_response(200)
                        self.send_header('Content-Type', 'application/json')
                        self.send_header('Access-Control-Allow-Origin', '*')
                        self.end_headers()
                        self.wfile.write(json.dumps(json_data).encode('utf-8'))
                    else:
                        self.send_error(500, "No output file generated")
                else:
                    self.send_error(500, f"CLI execution failed: {result.stderr}")
                    
            except Exception as e:
                self.send_error(500, f"Error executing CLI: {str(e)}")
            finally:
                # Clean up temp file
                if temp_input.exists():
                    temp_input.unlink()
                    
        elif self.path == "/api/load":
            # Load existing JSON file
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))
            
            file_path = data.get('file_path')
            if not file_path:
                self.send_error(400, "No file path provided")
                return
                
            file_path = Path(file_path)
            if not file_path.exists():
                self.send_error(404, "File not found")
                return
                
            try:
                with open(file_path, 'r') as f:
                    json_data = json.load(f)
                
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps(json_data).encode('utf-8'))
            except Exception as e:
                self.send_error(500, f"Error reading file: {str(e)}")
        else:
            self.send_error(404, "Endpoint not found")
    
    def do_OPTIONS(self):
        """Handle CORS preflight requests"""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

def build_frontend():
    """Build the React frontend"""
    print("Building React frontend...")
    frontend_dir = Path("frontend")
    
    if not frontend_dir.exists():
        print("Frontend directory not found")
        return False
    
    try:
        # Install dependencies if needed
        if not (frontend_dir / "node_modules").exists():
            print("Installing frontend dependencies...")
            subprocess.run(["npm", "install"], cwd=frontend_dir, check=True)
        
        # Build production bundle
        print("Building production bundle...")
        subprocess.run(["npm", "run", "build"], cwd=frontend_dir, check=True)
        print("Frontend built successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Failed to build frontend: {e}")
        return False
    except FileNotFoundError:
        print("npm not found. Please install Node.js")
        return False

def serve_ui(port=3000):
    """Serve the UI and handle CLI requests"""
    build_dir = Path("frontend/build")
    
    if not build_dir.exists():
        print("Frontend build directory not found. Building frontend...")
        if not build_frontend():
            return
    
    # Try to start HTTP server, handle port in use error
    server_address = ('', port)
    try:
        httpd = HTTPServer(server_address, OdinRequestHandler)
    except OSError as e:
        if e.errno == 48:  # Address already in use
            print(f"\nError: Port {port} is already in use.")
            print(f"Try running with a different port: python {sys.argv[0]} --port {port + 1}")
            sys.exit(1)
        else:
            raise
    
    print(f"\nODIN UI running at: http://localhost:{port}")
    print("Press Ctrl+C to stop\n")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        httpd.shutdown()

def main():
    """Main function"""
    print("ODIN (OSINT Data Intelligence Nexus) - Simplified UI")
    print("=" * 60)
    
    # Parse command line arguments
    port = 3002  # Default to 3002 to avoid conflicts with regular React dev server
    data_file = None
    
    for i, arg in enumerate(sys.argv):
        if arg == "--port" and i + 1 < len(sys.argv):
            try:
                port = int(sys.argv[i + 1])
            except ValueError:
                print(f"Invalid port: {sys.argv[i + 1]}")
                sys.exit(1)
        elif arg == "--data-file" and i + 1 < len(sys.argv):
            data_file = sys.argv[i + 1]
        elif arg == "--build":
            # Just build the frontend and exit
            if build_frontend():
                print("Frontend built successfully")
            sys.exit(0)
    
    if data_file:
        print(f"Loading data from: {data_file}")
        # TODO: Implement loading specific data file in the UI
    
    serve_ui(port)

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--help":
        print("Usage:")
        print("  python start_odin_ui_simple.py                  # Start the UI")
        print("  python start_odin_ui_simple.py --port 3001      # Use custom port")
        print("  python start_odin_ui_simple.py --data-file file.json  # Load specific data file")
        print("  python start_odin_ui_simple.py --build          # Build frontend only")
        print("  python start_odin_ui_simple.py --help           # Show this help")
    else:
        main()