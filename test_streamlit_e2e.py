#!/usr/bin/env python3
"""End-to-end tests for Streamlit dashboard"""

import pytest
from streamlit.testing.v1 import AppTest

def test_streamlit_app_loads():
    """Test that the Streamlit app loads without errors"""
    at = AppTest.from_file("streamlit_app.py")
    at.run()
    
    # Check for any exceptions during load
    assert not at.exception, f"App crashed with exception: {at.exception}"
    
    # Check that title is present
    assert "CVE Research Toolkit" in str(at.title)

def test_main_interface_exists():
    """Test that main interface elements are present"""
    at = AppTest.from_file("streamlit_app.py")
    at.run()
    
    # Check that main interface loads (no tabs in new design)
    assert not at.exception, f"App failed to load: {at.exception}"

def test_research_tab_functionality():
    """Test the research tab interface"""
    at = AppTest.from_file("streamlit_app.py")
    at.run()
    
    # Should have text area for CVE input
    text_areas = at.text_area
    assert len(text_areas) > 0, "No text area found for CVE input"
    
    # Should have research button
    buttons = [b for b in at.button if "Start Research" in str(b)]
    assert len(buttons) > 0, "No Start Research button found"

def test_input_interface():
    """Test input interface functionality"""
    at = AppTest.from_file("streamlit_app.py")
    at.run()
    
    # Check for CVE input interface
    text_areas = at.text_area
    assert len(text_areas) > 0, "No text area found for CVE input"
    
    # Check that no exceptions occurred
    assert not at.exception, f"Input interface failed: {at.exception}"

def test_no_duplicate_element_ids():
    """Test that there are no duplicate element IDs"""
    at = AppTest.from_file("streamlit_app.py")
    at.run()
    
    # This should not raise StreamlitDuplicateElementId
    assert not at.exception, f"Duplicate element ID error: {at.exception}"

if __name__ == "__main__":
    # Run tests directly
    print("Running Streamlit end-to-end tests...")
    
    try:
        test_streamlit_app_loads()
        print("App loads without errors")
    except Exception as e:
        print(f"App load test failed: {e}")
    
    try:
        test_main_interface_exists()
        print("Main interface exists")
    except Exception as e:
        print(f"Main interface test failed: {e}")
    
    try:
        test_research_tab_functionality()
        print("Research tab has required elements")
    except Exception as e:
        print(f"Research tab test failed: {e}")
    
    try:
        test_input_interface()
        print("Input interface works")
    except Exception as e:
        print(f"Input interface test failed: {e}")
        
    try:
        test_no_duplicate_element_ids()
        print("No duplicate element IDs")
    except Exception as e:
        print(f"Duplicate ID test failed: {e}")
    
    print("End-to-end testing complete!")