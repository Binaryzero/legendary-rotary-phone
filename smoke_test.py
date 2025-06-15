#!/usr/bin/env python3
"""Smoke test for CVE Research Toolkit Streamlit dashboard"""

import subprocess
import sys
import time
import requests
import signal
import os

def test_dashboard_smoke():
    """Smoke test: Can we start the dashboard and get a response?"""
    print("Running smoke test for dashboard...")
    
    # Start the streamlit server
    proc = subprocess.Popen([
        sys.executable, "-m", "streamlit", "run", "streamlit_app.py",
        "--server.headless=true",
        "--server.port=8503",
        "--browser.gatherUsageStats=false"
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    try:
        # Wait for server to start
        print("Waiting for server to start...")
        time.sleep(5)
        
        # Try to connect
        response = requests.get("http://localhost:8503", timeout=10)
        
        if response.status_code == 200:
            print("Dashboard starts and responds to HTTP requests")
            print(f"Response size: {len(response.content)} bytes")
            
            # Check for obvious errors in HTML
            html = response.text
            if "StreamlitDuplicateElementId" in html:
                print("ERROR: Duplicate element ID error in HTML")
                return False
            elif "error" in html.lower():
                print("WARNING: Possible errors in HTML content")
            else:
                print("No obvious errors in HTML response")
                return True
        else:
            print(f"ERROR: Server responded with status {response.status_code}")
            return False
            
    except requests.exceptions.ConnectionError:
        print("ERROR: Could not connect to dashboard server")
        return False
    except Exception as e:
        print(f"ERROR: Smoke test failed: {e}")
        return False
    finally:
        # Clean up: kill the server
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except:
            proc.kill()
        print("Server stopped")

if __name__ == "__main__":
    success = test_dashboard_smoke()
    sys.exit(0 if success else 1)