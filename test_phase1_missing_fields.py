#!/usr/bin/env python3
"""Test Phase 1 missing fields implementation"""

import asyncio
from odin.core.engine import VulnerabilityResearchEngine

async def test_phase1_missing_fields():
    config = {"max_concurrent": 5}
    engine = VulnerabilityResearchEngine(config)
    
    # Test with CVE-2021-34527 (PrintNightmare) - has temporal CVSS
    cve_id = "CVE-2021-34527"
    print(f"Testing Phase 1 missing fields for {cve_id}")
    
    research_data = await engine.research_cve(cve_id)
    
    print("\n=== PHASE 1: CORE CVE ENHANCEMENT ===")
    print(f"CVSS Score: {research_data.cvss_score}")
    print(f"CVSS Version: '{research_data.cvss_version}'")
    print(f"CVSS-BT Score: {research_data.cvss_bt_score}")
    print(f"CVSS-BT Severity: '{research_data.cvss_bt_severity}'")
    print(f"Original Severity: '{research_data.severity}'")
    
    print("\n=== COMPARISON ===")
    print(f"CVE Project CVSS: {research_data.cvss_score} ({research_data.severity})")
    print(f"CVSS-BT Enhanced: {research_data.cvss_bt_score} ({research_data.cvss_bt_severity})")
    
    # Test with another CVE
    print(f"\n{'='*60}")
    cve_id2 = "CVE-2021-44228"
    print(f"Testing {cve_id2}")
    
    research_data2 = await engine.research_cve(cve_id2)
    print(f"CVSS Version: '{research_data2.cvss_version}'")
    print(f"CVSS Score: {research_data2.cvss_score}")
    print(f"CVSS-BT Score: {research_data2.cvss_bt_score}")
    print(f"CVSS-BT Severity: '{research_data2.cvss_bt_severity}'")
    
    # Verify Phase 1 fields are working
    phase1_working = all([
        research_data.cvss_version,  # Should have CVSS version
        research_data.cvss_bt_score > 0,  # Should have CVSS-BT score
        research_data.cvss_bt_severity  # Should have CVSS-BT severity
    ])
    
    print(f"\n Phase 1 Status: {'SUCCESS' if phase1_working else 'NEEDS WORK'}")
    print(f"New fields populated: {3 if phase1_working else 'FAILED'}/3")

if __name__ == "__main__":
    asyncio.run(test_phase1_missing_fields())