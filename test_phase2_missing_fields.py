#!/usr/bin/env python3
"""Test Phase 2 missing fields implementation"""

import asyncio
from odin.core.engine import VulnerabilityResearchEngine

async def test_phase2_missing_fields():
    config = {"max_concurrent": 5}
    engine = VulnerabilityResearchEngine(config)
    
    # Test with CVE-2021-44228 (Log4Shell) - likely to have ADP data and many reference tags
    cve_id = "CVE-2021-44228"
    print(f"Testing Phase 2 missing fields for {cve_id}")
    
    research_data = await engine.research_cve(cve_id)
    
    print("\n=== PHASE 2: INTELLIGENCE ENHANCEMENT ===")
    print(f"Alternative CVSS Scores: {len(research_data.alternative_cvss_scores)}")
    for i, alt_cvss in enumerate(research_data.alternative_cvss_scores[:3]):
        print(f"  {i+1}. {alt_cvss['provider']}: {alt_cvss['score']} (v{alt_cvss['version']})")
    
    print(f"\nReference Tags: {len(research_data.reference_tags)}")
    if research_data.reference_tags:
        print(f"  Tags: {', '.join(research_data.reference_tags[:10])}")  # First 10 tags
    
    print(f"\nExploit Enhancement:")
    print(f"  Total Exploits: {len(research_data.exploits)}")
    verified_exploits = [e for e in research_data.exploits if e.verified]
    print(f"  Verified Exploits: {len(verified_exploits)}")
    
    for i, exploit in enumerate(research_data.exploits[:3]):
        status = " Verified" if exploit.verified else "  Unverified"
        print(f"  {i+1}. {exploit.type} - {status}")
        if exploit.title:
            print(f"      Title: {exploit.title}")
    
    # Test with another CVE that might have ADP data
    print(f"\n{'='*60}")
    cve_id2 = "CVE-2014-6271"
    print(f"Testing {cve_id2}")
    
    research_data2 = await engine.research_cve(cve_id2)
    print(f"Alternative CVSS: {len(research_data2.alternative_cvss_scores)}")
    print(f"Reference Tags: {len(research_data2.reference_tags)}")
    print(f"Verified Exploits: {sum(1 for e in research_data2.exploits if e.verified)}/{len(research_data2.exploits)}")
    
    # Verify Phase 2 fields are working
    phase2_working = any([
        research_data.alternative_cvss_scores,  # Alternative CVSS scores
        research_data.reference_tags,  # Reference tags
        any(e.verified for e in research_data.exploits),  # Verified exploits
        any(e.title for e in research_data.exploits)  # Exploit titles
    ])
    
    print(f"\n Phase 2 Status: {'SUCCESS' if phase2_working else 'NEEDS WORK'}")
    
    # Count new fields populated
    fields_populated = 0
    if research_data.alternative_cvss_scores: fields_populated += 1
    if research_data.reference_tags: fields_populated += 1
    if any(e.verified for e in research_data.exploits): fields_populated += 1
    if any(e.title for e in research_data.exploits): fields_populated += 1
    
    print(f"New fields populated: {fields_populated}/4")

if __name__ == "__main__":
    asyncio.run(test_phase2_missing_fields())