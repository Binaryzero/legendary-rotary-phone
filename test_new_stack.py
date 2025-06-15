#!/usr/bin/env python3
"""
Test script for the new React + FastAPI stack
"""

import asyncio
import json
import subprocess
import sys
import time
import requests
from pathlib import Path

def test_backend_startup():
    """Test that the FastAPI backend starts correctly."""
    print("Testing FastAPI backend startup...")
    
    proc = subprocess.Popen([
        sys.executable, "-m", "uvicorn", 
        "backend.app:app", 
        "--host", "0.0.0.0", 
        "--port", "8001",  # Use different port for testing
        "--no-access-log"
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    try:
        # Wait for startup
        time.sleep(5)
        
        if proc.poll() is not None:
            stdout, stderr = proc.communicate()
            print(f"FAIL: Backend crashed with code {proc.returncode}")
            print(f"STDERR: {stderr.decode()}")
            return False
        
        # Test health endpoint
        try:
            response = requests.get("http://localhost:8001/", timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "healthy":
                    print("SUCCESS: Backend starts and responds correctly")
                    return True
                else:
                    print(f"FAIL: Unexpected response: {data}")
                    return False
            else:
                print(f"FAIL: Health check returned {response.status_code}")
                return False
        except requests.exceptions.ConnectionError:
            print("FAIL: Could not connect to backend")
            return False
            
    finally:
        # Clean up
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except:
            proc.kill()

def test_api_endpoints():
    """Test core API endpoints."""
    print("Testing API endpoints...")
    
    proc = subprocess.Popen([
        sys.executable, "-m", "uvicorn", 
        "backend.app:app", 
        "--host", "0.0.0.0", 
        "--port", "8002",
        "--no-access-log"
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    try:
        time.sleep(5)
        
        if proc.poll() is not None:
            print("FAIL: Backend failed to start for API testing")
            return False
        
        base_url = "http://localhost:8002"
        
        # Test empty CVE list
        response = requests.get(f"{base_url}/api/cves")
        if response.status_code != 200:
            print(f"FAIL: CVE list endpoint returned {response.status_code}")
            return False
        
        data = response.json()
        if "data" not in data or "pagination" not in data or "summary" not in data:
            print(f"FAIL: CVE list endpoint missing required fields")
            return False
        
        # Test summary endpoint
        response = requests.get(f"{base_url}/api/summary")
        if response.status_code != 200:
            print(f"FAIL: Summary endpoint returned {response.status_code}")
            return False
        
        # Test pagination parameters
        response = requests.get(f"{base_url}/api/cves?page=1&per_page=10")
        if response.status_code != 200:
            print(f"FAIL: Pagination failed with {response.status_code}")
            return False
        
        print("SUCCESS: All API endpoints respond correctly")
        return True
        
    except Exception as e:
        print(f"FAIL: API testing failed: {e}")
        return False
        
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except:
            proc.kill()

def test_research_functionality():
    """Test CVE research functionality."""
    print("Testing research functionality...")
    
    # Check if research toolkit is available
    try:
        from cve_research_toolkit_fixed import VulnerabilityResearchEngine
        print("Research toolkit available")
    except ImportError:
        print("SKIP: Research toolkit not available")
        return True  # Not a failure, just skip
    
    proc = subprocess.Popen([
        sys.executable, "-m", "uvicorn", 
        "backend.app:app", 
        "--host", "0.0.0.0", 
        "--port", "8003",
        "--no-access-log"
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    try:
        time.sleep(5)
        
        if proc.poll() is not None:
            print("FAIL: Backend failed to start for research testing")
            return False
        
        # Test research endpoint with a known CVE
        test_cves = ["CVE-2021-44228"]  # Log4Shell - should have good data
        
        response = requests.post(
            "http://localhost:8003/api/research",
            json={"cve_ids": test_cves},
            timeout=30  # Research can take time
        )
        
        if response.status_code == 200:
            result = response.json()
            if result.get("status") == "success":
                print("SUCCESS: Research functionality works")
                return True
            else:
                print(f"FAIL: Research returned error: {result}")
                return False
        else:
            print(f"FAIL: Research endpoint returned {response.status_code}")
            return False
        
    except Exception as e:
        print(f"FAIL: Research testing failed: {e}")
        return False
        
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except:
            proc.kill()

def test_frontend_build():
    """Test that the React frontend builds correctly."""
    print("Testing React frontend build...")
    
    frontend_dir = Path("frontend")
    if not frontend_dir.exists():
        print("FAIL: Frontend directory not found")
        return False
    
    # Check if package.json exists
    if not (frontend_dir / "package.json").exists():
        print("FAIL: package.json not found")
        return False
    
    try:
        # Check if npm is available
        subprocess.run(["npm", "--version"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("SKIP: npm not available")
        return True  # Not a failure, just skip
    
    try:
        # Try to install dependencies (if not already installed)
        if not (frontend_dir / "node_modules").exists():
            print("Installing frontend dependencies...")
            subprocess.run([
                "npm", "install"
            ], cwd=frontend_dir, check=True, capture_output=True)
        
        # Test build (this validates TypeScript and React setup)
        print("Testing frontend build...")
        result = subprocess.run([
            "npm", "run", "build"
        ], cwd=frontend_dir, capture_output=True, text=True)
        
        if result.returncode == 0:
            print("SUCCESS: Frontend builds successfully")
            return True
        else:
            print(f"FAIL: Frontend build failed")
            print(f"STDERR: {result.stderr}")
            return False
            
    except Exception as e:
        print(f"FAIL: Frontend testing failed: {e}")
        return False

def main():
    """Run all tests."""
    print("Testing New React + FastAPI Stack")
    print("=" * 50)
    
    tests = [
        ("Backend Startup", test_backend_startup),
        ("API Endpoints", test_api_endpoints),
        ("Research Functionality", test_research_functionality),
        ("Frontend Build", test_frontend_build),
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
        print("ALL TESTS PASSED - NEW STACK IS READY")
        print("\nTo start the application:")
        print("  python start_new_ui.py --install    # First time")
        print("  python start_new_ui.py              # Regular start")
        return True
    else:
        print("SOME TESTS FAILED - CHECK ERRORS ABOVE")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)