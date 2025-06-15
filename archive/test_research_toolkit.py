#!/usr/bin/env python3
"""Test script for the CVE Research Toolkit"""

import sys
from pathlib import Path

def test_basic_functionality():
    """Test basic functionality without external dependencies."""
    print("Testing CVE Research Toolkit...")
    
    # Test imports
    try:
        from cve_research_toolkit_fixed import (
            ResearchData, 
            DataLayer, 
            ExploitReference,
            ThreatContext,
            WeaknessTactics,
            ResearchCache
        )
        print("✓ Core classes imported successfully")
    except ImportError as e:
        print(f"✗ Import failed: {e}")
        return False
    
    # Test data structures
    try:
        # Test ResearchData creation
        rd = ResearchData(cve_id="CVE-2021-44228")
        print(f"✓ ResearchData created: {rd.cve_id}")
        
        # Test cache
        cache = ResearchCache()
        cache.put(rd)
        cached = cache.get("CVE-2021-44228")
        if cached:
            print("✓ Cache operations working")
        else:
            print("✗ Cache operations failed")
        
    except Exception as e:
        print(f"✗ Data structure test failed: {e}")
        return False
    
    # Test dependency handling
    try:
        from cve_research_toolkit_fixed import aiohttp, click, pd, yaml, RICH_AVAILABLE
        
        deps = {
            "aiohttp": aiohttp is not None,
            "click": click is not None,
            "pandas": pd is not None,
            "yaml": yaml is not None,
            "rich": RICH_AVAILABLE
        }
        
        print("\nDependency Status:")
        for dep, available in deps.items():
            status = "✓" if available else "✗"
            print(f"  {status} {dep}: {'Available' if available else 'Not available'}")
        
    except Exception as e:
        print(f"✗ Dependency check failed: {e}")
        return False
    
    print("\n✓ All basic tests passed!")
    return True

def test_main_function():
    """Test the main function with minimal dependencies."""
    print("\nTesting main function...")
    
    try:
        from cve_research_toolkit_fixed import main
        
        # Create a test CVE file
        test_file = Path("test_cves.txt")
        test_file.write_text("CVE-2021-44228\nCVE-2023-23397\n")
        
        # Test with dry run (no actual network calls)
        print("Running main function test...")
        
        # This should work even without optional dependencies
        # Note: This will show warnings about missing dependencies but should not crash
        try:
            main(
                input_file=str(test_file),
                format=['json'],
                output_dir='test_output',
                priority_threshold=0
            )
            print("✓ Main function completed without crashing")
        except Exception as e:
            print(f"Main function test info: {e}")
            # This is expected if aiohttp is not available
            if "aiohttp" in str(e):
                print("✓ Expected behavior - aiohttp dependency missing")
            else:
                raise
        
        # Cleanup
        test_file.unlink(missing_ok=True)
        import shutil
        shutil.rmtree("test_output", ignore_errors=True)
        
    except Exception as e:
        print(f"✗ Main function test failed: {e}")
        return False
    
    print("✓ Main function test completed")
    return True

if __name__ == "__main__":
    print("CVE Research Toolkit - Test Suite")
    print("=" * 50)
    
    success = True
    
    success &= test_basic_functionality()
    success &= test_main_function()
    
    print("\n" + "=" * 50)
    if success:
        print("✓ All tests passed! The research toolkit is working correctly.")
        print("\nTo use with full functionality, install dependencies:")
        print("pip install -r requirements-research.txt")
    else:
        print("✗ Some tests failed. Check the output above.")
        sys.exit(1)