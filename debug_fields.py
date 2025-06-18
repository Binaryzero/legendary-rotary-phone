#!/usr/bin/env python3
"""Debug missing field data"""

import asyncio
from odin.core.engine import VulnerabilityResearchEngine

async def debug_missing_fields():
    config = {"max_concurrent": 5}
    engine = VulnerabilityResearchEngine(config)
    
    # Test with CVE-2021-44228 (Log4Shell)
    cve_id = "CVE-2021-44228"
    print(f"Debugging data extraction for {cve_id}")
    
    # Get research data
    research_data = await engine.research_cve(cve_id)
    
    print("\n=== THREAT CONTEXT DATA ===")
    print(f"KEV Vulnerability Name: '{research_data.threat.kev_vulnerability_name}'")
    print(f"KEV Vendor Project: '{research_data.threat.kev_vendor_project}'")
    print(f"KEV Product: '{research_data.threat.kev_product}'")
    print(f"VEDAS Percentile: {research_data.threat.vedas_percentile}")
    print(f"VEDAS Score Change: {research_data.threat.vedas_score_change}")
    print(f"VEDAS Detail URL: '{research_data.threat.vedas_detail_url}'")
    print(f"VEDAS Date: '{research_data.threat.vedas_date}'")
    print(f"Temporal CVSS Score: {research_data.threat.temporal_score}")
    print(f"Exploit Code Maturity: '{research_data.threat.exploit_code_maturity}'")
    print(f"Remediation Level: '{research_data.threat.remediation_level}'")
    print(f"Report Confidence: '{research_data.threat.report_confidence}'")
    
    print("\n=== ENHANCED PROBLEM TYPE DATA ===")
    print(f"Primary Weakness: '{research_data.enhanced_problem_type.primary_weakness}'")
    print(f"Secondary Weaknesses: {research_data.enhanced_problem_type.secondary_weaknesses}")
    print(f"Vulnerability Categories: {research_data.enhanced_problem_type.vulnerability_categories}")
    print(f"Impact Types: {research_data.enhanced_problem_type.impact_types}")
    print(f"Attack Vectors: {research_data.enhanced_problem_type.attack_vectors}")
    print(f"Enhanced CWE Details: {research_data.enhanced_problem_type.enhanced_cwe_details}")
    
    print("\n=== CONTROL MAPPINGS DATA ===")
    print(f"Applicable Controls Count: {research_data.control_mappings.applicable_controls_count}")
    print(f"Control Categories: {research_data.control_mappings.control_categories}")
    print(f"Top Controls: {research_data.control_mappings.top_controls}")
    
    print("\n=== PRODUCT INTELLIGENCE DATA ===")
    print(f"Vendors: {research_data.product_intelligence.vendors}")
    print(f"Products: {research_data.product_intelligence.products}")
    print(f"Source Repositories: {research_data.product_intelligence.repositories}")

if __name__ == "__main__":
    asyncio.run(debug_missing_fields())