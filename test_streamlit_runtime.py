#!/usr/bin/env python3
"""
Runtime tests for Streamlit that actually catch real errors.
"""

import subprocess
import sys
import time
import requests
import signal
import os

def test_streamlit_runtime_errors():
    """Test that Streamlit actually runs without Python errors."""
    print("Testing Streamlit for runtime errors...")
    
    proc = subprocess.Popen([
        sys.executable, "-m", "streamlit", "run", "streamlit_app.py",
        "--server.headless=true",
        "--server.port=8506",
        "--browser.gatherUsageStats=false"
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    try:
        # Wait for server to start and check for immediate crashes
        time.sleep(5)
        
        # Check if process crashed during startup
        if proc.poll() is not None:
            stdout, stderr = proc.communicate()
            print(f"FAIL: Process crashed during startup with code {proc.returncode}")
            print(f"STDERR: {stderr}")
            return False
        
        # Check stderr for API errors even if process is running
        try:
            # Read available stderr without blocking
            import select
            import fcntl
            import os
            
            # Make stderr non-blocking
            fd = proc.stderr.fileno()
            fl = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
            
            stderr_content = ""
            try:
                stderr_content = proc.stderr.read()
            except:
                pass  # No data available yet
            
            if stderr_content and ("StreamlitAPIException" in stderr_content or "Traceback" in stderr_content):
                print(f"FAIL: API errors detected in stderr:")
                print(stderr_content)
                return False
                
        except:
            pass  # Skip stderr check if not available
        
        # Additional wait for full startup
        time.sleep(5)
        
        # Try to access the page
        try:
            response = requests.get("http://localhost:8506", timeout=15)
            
            if response.status_code != 200:
                print(f"FAIL: HTTP {response.status_code}")
                return False
            
            html = response.text.lower()
            
            # Check for Python errors that would appear in the page
            error_indicators = [
                "nameerror",
                "attributeerror", 
                "keyerror",
                "typeerror",
                "valueerror",
                "traceback",
                "exception",
                "error occurred",
                "streamlit error",
                "streamlitapiexception",
                "something went wrong",
                "invalid height",
                "must be at least"
            ]
            
            found_errors = []
            for error in error_indicators:
                if error in html:
                    found_errors.append(error)
            
            if found_errors:
                print(f"FAIL: Runtime errors detected in page: {', '.join(found_errors)}")
                # Save the error page for debugging
                with open("error_page.html", "w") as f:
                    f.write(response.text)
                print("Error page saved to error_page.html")
                return False
            
            print("SUCCESS: App runs without runtime errors")
            return True
            
        except requests.exceptions.ConnectionError:
            print("FAIL: Could not connect to app")
            return False
        except Exception as e:
            print(f"FAIL: Request failed: {e}")
            return False
            
    finally:
        # Kill the process
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except:
            proc.kill()

def test_streamlit_no_crashes():
    """Test that app loads without crashing."""
    print("Testing app loads without crashes...")
    
    proc = subprocess.Popen([
        sys.executable, "-m", "streamlit", "run", "streamlit_app.py",
        "--server.headless=true", 
        "--server.port=8507",
        "--browser.gatherUsageStats=false"
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    try:
        time.sleep(10)
        
        if proc.poll() is not None:
            stdout, stderr = proc.communicate()
            print("FAIL: Process crashed during startup")
            if "StreamlitAPIException" in stderr:
                print(f"API Error: {stderr}")
            return False
        
        # Test basic page load
        response = requests.get("http://localhost:8507", timeout=15)
        
        if response.status_code != 200:
            print(f"FAIL: Page load failed with {response.status_code}")
            return False
        
        print("SUCCESS: App loads without crashes")
        return True
        
    except Exception as e:
        print(f"FAIL: Load test failed: {e}")
        return False
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except:
            proc.kill()

def main():
    """Run runtime tests that actually matter."""
    print("Running REAL Streamlit Runtime Tests")
    print("=" * 50)
    
    tests = [
        ("Runtime Error Detection", test_streamlit_runtime_errors),
        ("No Crash Test", test_streamlit_no_crashes),
    ]
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        print(f"\nRunning: {test_name}")
        try:
            if test_func():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"CRASH: {test_name} crashed: {e}")
            failed += 1
    
    print("\n" + "=" * 50)
    print(f"RESULTS: {passed} passed, {failed} failed")
    
    if failed == 0:
        print("ALL RUNTIME TESTS PASSED")
        return True
    else:
        print("RUNTIME TESTS FAILED - APP HAS REAL ISSUES")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)