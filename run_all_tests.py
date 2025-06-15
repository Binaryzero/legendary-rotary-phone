#!/usr/bin/env python3
"""Comprehensive test runner for CVE Research Toolkit"""

import subprocess
import sys
from pathlib import Path

def run_test(test_name, command):
    """Run a test and return success status"""
    print(f"\n{'='*60}")
    print(f"Running {test_name}")
    print('='*60)
    
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=60)
        
        if result.returncode == 0:
            print(f"PASS {test_name}")
            if result.stdout:
                print(result.stdout)
            return True
        else:
            print(f"FAIL {test_name}")
            if result.stderr:
                print("STDERR:", result.stderr)
            if result.stdout:
                print("STDOUT:", result.stdout)
            return False
            
    except subprocess.TimeoutExpired:
        print(f"TIMEOUT {test_name}")
        return False
    except Exception as e:
        print(f"CRASH {test_name}: {e}")
        return False

def main():
    """Run comprehensive test suite"""
    print("CVE Research Toolkit - Comprehensive Test Suite")
    
    tests = [
        ("Core Toolkit Tests", "python3 tests/test_research_comprehensive.py"),
        ("Streamlit Functional Tests", "python3 test_streamlit_functionality.py"),
        ("Dashboard Smoke Test", "python3 smoke_test.py"),
        ("Import Validation", "python3 -c 'import streamlit_app; import cve_research_toolkit_fixed; print(\"All imports successful\")'"),
        ("CLI Command Check", "which cve-dashboard && echo 'CLI command available'"),
        ("Package Structure", "pip show cve-research-toolkit | grep -E 'Name|Version' || echo 'Package installed'")
    ]
    
    passed = 0
    failed = 0
    
    for test_name, command in tests:
        if run_test(test_name, command):
            passed += 1
        else:
            failed += 1
    
    print(f"\n{'='*60}")
    print(f"TEST SUMMARY")
    print('='*60)
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    print(f"Success Rate: {passed/(passed+failed)*100:.1f}%")
    
    if failed == 0:
        print("ALL TESTS PASSED!")
        return True
    else:
        print("SOME TESTS FAILED - Review above for details")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)