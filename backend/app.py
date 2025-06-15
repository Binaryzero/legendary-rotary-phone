#!/usr/bin/env python3
"""
CVE Research Toolkit - FastAPI Backend
High-performance API for vulnerability data with server-side pagination and filtering.
"""

import asyncio
import json
import logging
import math
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# Import the research toolkit
try:
    from cve_research_toolkit_fixed import VulnerabilityResearchEngine, ResearchData
    TOOLKIT_AVAILABLE = True
except ImportError:
    TOOLKIT_AVAILABLE = False

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# FastAPI app
app = FastAPI(
    title="ODIN API",
    description="OSINT Data Intelligence Nexus - High-performance vulnerability intelligence API with advanced filtering and pagination",
    version="2.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Data models
class CVEResearchRequest(BaseModel):
    cve_ids: List[str]

class PaginationParams(BaseModel):
    page: int = 1
    per_page: int = 25
    search: Optional[str] = None
    severity_filter: Optional[str] = None
    kev_filter: Optional[bool] = None
    exploits_filter: Optional[bool] = None

class CVEResponse(BaseModel):
    data: List[Dict[str, Any]]
    pagination: Dict[str, Any]
    summary: Dict[str, Any]

# In-memory data store (in production, use Redis or database)
research_data: List[Dict[str, Any]] = []

@app.get("/")
async def root():
    """Health check endpoint."""
    return {"status": "healthy", "toolkit_available": TOOLKIT_AVAILABLE}

@app.post("/api/research")
async def research_cves(request: CVEResearchRequest):
    """
    Researches a batch of CVEs using the vulnerability research toolkit and stores the results.
    
    Validates toolkit availability and input, performs asynchronous research on the provided CVE IDs, and structures the results with detailed vulnerability, threat, and product intelligence information. Newly researched CVEs are added to the in-memory data store, avoiding duplicates.
    
    Args:
        request: Contains a list of CVE IDs to research.
    
    Returns:
        A dictionary indicating success, the number of newly researched CVEs, the total stored, and a status message.
    
    Raises:
        HTTPException: If the toolkit is unavailable, no CVE IDs are provided, or research fails.
    """
    global research_data
    
    if not TOOLKIT_AVAILABLE:
        raise HTTPException(status_code=500, detail="Research toolkit not available")
    
    if not request.cve_ids:
        raise HTTPException(status_code=400, detail="No CVE IDs provided")
    
    try:
        logger.info(f"Researching {len(request.cve_ids)} CVEs")
        
        config_data = {}
        engine = VulnerabilityResearchEngine(config_data)
        
        # Research CVEs
        research_results = await engine.research_batch(request.cve_ids)
        
        # Convert to API format
        new_data = []
        for rd in research_results:
            result = {
                "cve_id": rd.cve_id,
                "description": rd.description,
                "cvss_score": rd.cvss_score,
                "cvss_vector": rd.cvss_vector,
                "severity": rd.severity,
                "published_date": rd.published_date.isoformat() if rd.published_date else None,
                "last_modified": rd.last_modified.isoformat() if rd.last_modified else None,
                "references": rd.references,
                "weakness": {
                    "cwe_ids": rd.weakness.cwe_ids,
                    "capec_ids": rd.weakness.capec_ids,
                    "attack_techniques": rd.weakness.attack_techniques,
                    "attack_tactics": rd.weakness.attack_tactics,
                    "kill_chain_phases": rd.weakness.kill_chain_phases
                },
                "threat": {
                    "in_kev": rd.threat.in_kev,
                    "vulncheck_kev": rd.threat.vulncheck_kev,
                    "epss_score": rd.threat.epss_score,
                    "epss_percentile": rd.threat.epss_percentile,
                    "vedas_score": rd.threat.vedas_score,
                    "vedas_percentile": rd.threat.vedas_percentile,
                    "vedas_score_change": rd.threat.vedas_score_change,
                    "vedas_detail_url": rd.threat.vedas_detail_url,
                    "vedas_date": rd.threat.vedas_date,
                    "temporal_score": rd.threat.temporal_score,
                    "exploit_code_maturity": rd.threat.exploit_code_maturity,
                    "remediation_level": rd.threat.remediation_level,
                    "report_confidence": rd.threat.report_confidence,
                    "actively_exploited": rd.threat.actively_exploited,
                    "has_metasploit": rd.threat.has_metasploit,
                    "has_nuclei": rd.threat.has_nuclei,
                    "ransomware_campaign": rd.threat.ransomware_campaign,
                    "kev_vulnerability_name": rd.threat.kev_vulnerability_name,
                    "kev_short_description": rd.threat.kev_short_description,
                    "kev_vendor_project": rd.threat.kev_vendor_project,
                    "kev_product": rd.threat.kev_product
                },
                "exploits": [{"url": exp.url, "source": exp.source, "type": exp.type} for exp in rd.exploits],
                "exploit_maturity": rd.exploit_maturity,
                "cpe_affected": rd.cpe_affected,
                "vendor_advisories": rd.vendor_advisories,
                "patches": rd.patches,
                "enhanced_problem_type": {
                    "primary_weakness": rd.enhanced_problem_type.primary_weakness,
                    "secondary_weaknesses": '; '.join(rd.enhanced_problem_type.secondary_weaknesses),
                    "vulnerability_categories": '; '.join(rd.enhanced_problem_type.vulnerability_categories),
                    "impact_types": '; '.join(rd.enhanced_problem_type.impact_types),
                    "attack_vectors": '; '.join(rd.enhanced_problem_type.attack_vectors),
                    "enhanced_cwe_details": '; '.join(rd.enhanced_problem_type.enhanced_cwe_details)
                },
                "control_mappings": {
                    "applicable_controls_count": str(rd.control_mappings.applicable_controls_count),
                    "control_categories": '; '.join(rd.control_mappings.control_categories),
                    "top_controls": '; '.join(rd.control_mappings.top_controls)
                },
                "product_intelligence": {
                    "vendors": rd.product_intelligence.vendors,
                    "products": rd.product_intelligence.products,
                    "affected_versions": rd.product_intelligence.affected_versions,
                    "platforms": rd.product_intelligence.platforms,
                    "modules": rd.product_intelligence.modules,
                    "repositories": rd.product_intelligence.repositories
                },
                "last_enriched": rd.last_enriched.isoformat() if rd.last_enriched else None
            }
            new_data.append(result)
        
        # Add to existing data (avoid duplicates by CVE ID)
        existing_cves = {item["cve_id"] for item in research_data}
        for item in new_data:
            if item["cve_id"] not in existing_cves:
                research_data.append(item)
        
        logger.info(f"Research complete. Total CVEs in database: {len(research_data)}")
        
        return {
            "status": "success",
            "researched": len(new_data),
            "total": len(research_data),
            "message": f"Successfully researched {len(new_data)} CVEs"
        }
    
    except Exception as e:
        logger.error(f"Research failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Research failed: {str(e)}")

@app.get("/api/cves", response_model=CVEResponse)
async def get_cves(
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(25, ge=1, le=100, description="Items per page"),
    search: Optional[str] = Query(None, description="Search term for CVE ID or description"),
    severity: Optional[str] = Query(None, description="Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)"),
    kev: Optional[bool] = Query(None, description="Filter by CISA KEV status"),
    exploits: Optional[bool] = Query(None, description="Filter by exploit availability")
):
    """Get paginated CVE data with filtering."""
    
    # Apply filters
    filtered_data = research_data.copy()
    
    if search:
        search_lower = search.lower()
        filtered_data = [
            item for item in filtered_data
            if search_lower in item.get('cve_id', '').lower() or
               search_lower in item.get('description', '').lower()
        ]
    
    if severity:
        filtered_data = [
            item for item in filtered_data
            if item.get('severity', '').upper() == severity.upper()
        ]
    
    if kev is not None:
        filtered_data = [
            item for item in filtered_data
            if item.get('threat', {}).get('in_kev', False) == kev
        ]
    
    if exploits is not None:
        if exploits:
            filtered_data = [
                item for item in filtered_data
                if len(item.get('exploits', [])) > 0
            ]
        else:
            filtered_data = [
                item for item in filtered_data
                if len(item.get('exploits', [])) == 0
            ]
    
    # Calculate pagination
    total_items = len(filtered_data)
    total_pages = math.ceil(total_items / per_page) if total_items > 0 else 1
    
    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    
    paginated_data = filtered_data[start_idx:end_idx]
    
    # Generate summary statistics
    summary = {
        "total_cves": len(research_data),
        "filtered_cves": total_items,
        "critical_high": len([d for d in filtered_data if d.get('severity', '').upper() in ['CRITICAL', 'HIGH']]),
        "in_kev": len([d for d in filtered_data if d.get('threat', {}).get('in_kev', False)]),
        "with_exploits": len([d for d in filtered_data if len(d.get('exploits', [])) > 0])
    }
    
    return CVEResponse(
        data=paginated_data,
        pagination={
            "page": page,
            "per_page": per_page,
            "total_items": total_items,
            "total_pages": total_pages,
            "has_next": page < total_pages,
            "has_prev": page > 1
        },
        summary=summary
    )

@app.get("/api/cves/{cve_id}")
async def get_cve_details(cve_id: str):
    """Get detailed information for a specific CVE."""
    
    # Find CVE in data
    cve_data = next((item for item in research_data if item.get('cve_id') == cve_id), None)
    
    if not cve_data:
        raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")
    
    return cve_data

@app.get("/api/summary")
async def get_summary():
    """Get overall summary statistics."""
    
    if not research_data:
        return {
            "total_cves": 0,
            "severity_breakdown": {},
            "kev_count": 0,
            "exploit_count": 0
        }
    
    # Calculate statistics
    severity_counts = {}
    kev_count = 0
    exploit_count = 0
    
    for item in research_data:
        # Severity breakdown
        severity = item.get('severity', 'UNKNOWN').upper()
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # KEV count
        if item.get('threat', {}).get('in_kev', False):
            kev_count += 1
        
        # Exploit count
        if len(item.get('exploits', [])) > 0:
            exploit_count += 1
    
    return {
        "total_cves": len(research_data),
        "severity_breakdown": severity_counts,
        "kev_count": kev_count,
        "exploit_count": exploit_count
    }

@app.get("/api/analytics/severity")
async def get_severity_analytics():
    """Get severity distribution analytics."""
    
    severity_data = []
    severity_counts = {}
    
    for item in research_data:
        severity = item.get('severity', 'UNKNOWN').upper()
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    for severity, count in severity_counts.items():
        severity_data.append({"severity": severity, "count": count})
    
    return {"data": severity_data}

@app.get("/api/analytics/mitre")
async def get_mitre_analytics():
    """Get MITRE framework analytics."""
    
    all_cwes = []
    all_tactics = []
    all_techniques = []
    
    for item in research_data:
        weakness = item.get('weakness', {})
        all_cwes.extend(weakness.get('cwe_ids', []))
        all_tactics.extend(weakness.get('attack_tactics', []))
        all_techniques.extend(weakness.get('attack_techniques', []))
    
    # Count occurrences
    from collections import Counter
    
    cwe_counts = Counter(all_cwes).most_common(10)
    tactic_counts = Counter(all_tactics).most_common()
    technique_counts = Counter(all_techniques).most_common(10)
    
    return {
        "top_cwes": [{"cwe": cwe, "count": count} for cwe, count in cwe_counts],
        "tactics": [{"tactic": tactic, "count": count} for tactic, count in tactic_counts],
        "top_techniques": [{"technique": tech, "count": count} for tech, count in technique_counts]
    }

@app.delete("/api/data")
async def clear_data():
    """
    Removes all stored CVE research data from memory.
    
    Returns:
        A dictionary indicating success and a confirmation message.
    """
    global research_data
    research_data = []
    return {"status": "success", "message": "All data cleared"}

@app.post("/api/load-data")
async def load_data(data: List[Dict[str, Any]]):
    """
    Replaces all stored CVE research data with the provided list.
    
    Validates that each item in the input list is a dictionary containing a 'cve_id' field. On success, clears the existing in-memory data and loads the new data. Returns a success response with the count of loaded CVEs. Raises an HTTP 400 error for invalid input format and HTTP 500 for unexpected errors.
    """
    global research_data
    
    try:
        # Validate the data structure
        for item in data:
            if not isinstance(item, dict) or 'cve_id' not in item:
                raise HTTPException(status_code=400, detail="Invalid data format. Each item must have a 'cve_id' field.")
        
        # Clear existing data and load new data
        research_data = data
        
        logger.info(f"Loaded {len(data)} CVEs from uploaded data")
        
        return {
            "status": "success",
            "loaded": len(data),
            "message": f"Successfully loaded {len(data)} CVEs"
        }
    
    except Exception as e:
        logger.error(f"Data loading failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Data loading failed: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)