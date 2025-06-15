#!/usr/bin/env python3
"""CVE Research Toolkit - Local Web UI Wrapper

Interactive web interface for CVE research data consumption and analysis.
Provides filtering, sorting, search, and detailed drill-down capabilities.
"""

import asyncio
import json
import logging
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse
import webbrowser
import threading
import time

# Import the research toolkit
try:
    from cve_research_toolkit_fixed import (
        VulnerabilityResearchEngine,
        ResearchData,
        console
    )
    TOOLKIT_AVAILABLE = True
except ImportError:
    TOOLKIT_AVAILABLE = False
    print("Warning: CVE Research Toolkit not available. UI will run in demo mode.")

logger = logging.getLogger(__name__)

class CVEResearchUIHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the CVE Research UI."""
    
    def __init__(self, *args, research_data: List[Dict[str, Any]] = None, server_instance=None, **kwargs):
        self.research_data = research_data or []
        self.server_instance = server_instance
        super().__init__(*args, **kwargs)
    
    def do_GET(self):
        """Handle GET requests."""
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        query_params = parse_qs(parsed_path.query)
        
        if path == '/' or path == '/index.html':
            self._serve_main_page()
        elif path == '/api/cves':
            self._serve_cve_data(query_params)
        elif path == '/api/cve':
            cve_id = query_params.get('id', [''])[0]
            self._serve_cve_details(cve_id)
        elif path == '/api/stats':
            self._serve_statistics()
        elif path == '/api/export':
            format_type = query_params.get('format', ['json'])[0]
            self._serve_export(format_type)
        elif path.startswith('/static/'):
            self._serve_static_file(path)
        else:
            self._send_404()
    
    def do_POST(self):
        """Handle POST requests."""
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        
        if path == '/api/research':
            self._handle_research_request()
        else:
            self._send_404()
    
    def _serve_main_page(self):
        """Serve the main HTML page."""
        html = self._generate_html()
        self._send_response(200, html, 'text/html')
    
    def _serve_cve_data(self, query_params: Dict[str, List[str]]):
        """Serve filtered CVE data."""
        # Parse filtering parameters
        search_term = query_params.get('search', [''])[0].lower()
        severity_filter = query_params.get('severity', [''])[0]
        sort_by = query_params.get('sort', ['cvss_score'])[0]
        sort_order = query_params.get('order', ['desc'])[0]
        
        # Get current research data
        current_data = self.server_instance.research_data if self.server_instance else self.research_data
        
        # Filter data
        filtered_data = []
        for cve in current_data:
            # Search filter
            if search_term:
                searchable_text = f"{cve.get('cve_id', '')} {cve.get('description', '')} {' '.join(cve.get('cwe_ids', []))}".lower()
                if search_term not in searchable_text:
                    continue
            
            # Severity filter
            if severity_filter and cve.get('severity', '').upper() != severity_filter.upper():
                continue
                
            filtered_data.append(cve)
        
        # Sort data
        reverse = sort_order == 'desc'
        if sort_by == 'cvss_score':
            filtered_data.sort(key=lambda x: x.get('cvss_score', 0), reverse=reverse)
        elif sort_by == 'published_date':
            filtered_data.sort(key=lambda x: x.get('published_date', ''), reverse=reverse)
        elif sort_by == 'cve_id':
            filtered_data.sort(key=lambda x: x.get('cve_id', ''), reverse=reverse)
        
        self._send_json_response(filtered_data)
    
    def _serve_cve_details(self, cve_id: str):
        """Serve detailed information for a specific CVE."""
        current_data = self.server_instance.research_data if self.server_instance else self.research_data
        for cve in current_data:
            if cve.get('cve_id') == cve_id:
                self._send_json_response(cve)
                return
        self._send_404()
    
    def _serve_statistics(self):
        """Serve summary statistics."""
        current_data = self.server_instance.research_data if self.server_instance else self.research_data
        if not current_data:
            self._send_json_response({})
            return
        
        total_cves = len(current_data)
        severity_counts = {}
        cvss_scores = []
        exploit_count = 0
        kev_count = 0
        
        for cve in current_data:
            # Severity distribution
            severity = cve.get('severity', 'UNKNOWN').upper()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            # CVSS scores
            score = cve.get('cvss_score', 0)
            if score > 0:
                cvss_scores.append(score)
            
            # Exploit availability
            if cve.get('exploits'):
                exploit_count += 1
            
            # CISA KEV
            if cve.get('threat', {}).get('in_kev'):
                kev_count += 1
        
        avg_cvss = sum(cvss_scores) / len(cvss_scores) if cvss_scores else 0
        
        stats = {
            'total_cves': total_cves,
            'severity_distribution': severity_counts,
            'average_cvss': round(avg_cvss, 1),
            'cves_with_exploits': exploit_count,
            'cves_in_kev': kev_count,
            'exploit_percentage': round((exploit_count / total_cves) * 100, 1) if total_cves > 0 else 0,
            'kev_percentage': round((kev_count / total_cves) * 100, 1) if total_cves > 0 else 0
        }
        
        self._send_json_response(stats)
    
    def _handle_research_request(self):
        """Handle new CVE research request."""
        if not TOOLKIT_AVAILABLE:
            self._send_json_response({'error': 'CVE Research Toolkit not available'}, 400)
            return
        
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        
        try:
            request_data = json.loads(post_data.decode('utf-8'))
            cve_ids = request_data.get('cve_ids', [])
            
            if not cve_ids:
                self._send_json_response({'error': 'No CVE IDs provided'}, 400)
                return
            
            # Create a temporary file with CVE IDs
            import tempfile
            import os
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                for cve_id in cve_ids:
                    f.write(f"{cve_id}\n")
                temp_file = f.name
            
            try:
                # Run the research
                from cve_research_toolkit_fixed import VulnerabilityResearchEngine, ResearchReportGenerator
                
                config_data = {}  # Empty config like in main function
                engine = VulnerabilityResearchEngine(config_data)
                research_results = asyncio.run(engine.research_batch(cve_ids))
                
                # Convert to web UI format (same logic as _export_webui_json)
                webui_data = []
                for rd in research_results:
                    webui_record = {
                        'cve_id': rd.cve_id,
                        'description': rd.description,
                        'cvss_score': rd.cvss_score,
                        'severity': rd.severity,
                        'published_date': rd.published_date.isoformat() if rd.published_date else None,
                        'last_modified': rd.last_modified.isoformat() if rd.last_modified else None,
                        
                        'weakness': {
                            'cwe_ids': rd.weakness.cwe_ids,
                            'capec_ids': rd.weakness.capec_ids,
                            'attack_techniques': rd.weakness.attack_techniques,
                            'attack_tactics': rd.weakness.attack_tactics
                        },
                        
                        'threat': {
                            'in_kev': rd.threat.in_kev,
                            'epss_score': rd.threat.epss_score,
                            'epss_percentile': rd.threat.epss_percentile,
                            'actively_exploited': rd.threat.actively_exploited,
                            'has_metasploit': rd.threat.has_metasploit,
                            'has_nuclei': rd.threat.has_nuclei
                        },
                        
                        'exploits': [
                            {
                                'url': exp.url,
                                'source': exp.source,
                                'type': exp.type
                            } for exp in rd.exploits
                        ],
                        
                        'remediation': {
                            'patches': rd.patches,
                            'vendor_advisories': rd.vendor_advisories,
                            'references': rd.references
                        }
                    }
                    webui_data.append(webui_record)
                
                # Update server's research data
                if self.server_instance:
                    self.server_instance.research_data.extend(webui_data)
                    self.research_data = self.server_instance.research_data
                else:
                    self.research_data.extend(webui_data)
                
                # Clean up temp file
                os.unlink(temp_file)
                
                self._send_json_response({
                    'status': 'completed',
                    'cve_ids': cve_ids,
                    'message': f'Successfully researched {len(cve_ids)} CVEs',
                    'data': webui_data
                })
            
            except Exception as e:
                logger.error(f"Research failed: {e}")
                if os.path.exists(temp_file):
                    os.unlink(temp_file)
                self._send_json_response({'error': f'Research failed: {str(e)}'}, 500)
                
        except json.JSONDecodeError:
            self._send_json_response({'error': 'Invalid JSON'}, 400)
        except Exception as e:
            self._send_json_response({'error': str(e)}, 500)
    
    def _serve_export(self, format_type: str):
        """Export research data in various formats."""
        current_data = self.server_instance.research_data if self.server_instance else self.research_data
        if format_type == 'json':
            self._send_json_response(current_data)
        elif format_type == 'csv':
            # Generate CSV
            if not current_data:
                self._send_response(200, '', 'text/csv')
                return
                
            import csv
            import io
            output = io.StringIO()
            
            # Define CSV columns
            fieldnames = ['cve_id', 'description', 'cvss_score', 'severity', 'published_date', 
                         'cwe_ids', 'capec_ids', 'attack_techniques', 'attack_tactics',
                         'in_kev', 'epss_score', 'exploit_count', 'patch_available']
            
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            
            for cve in current_data:
                row = {
                    'cve_id': cve.get('cve_id', ''),
                    'description': cve.get('description', ''),
                    'cvss_score': cve.get('cvss_score', ''),
                    'severity': cve.get('severity', ''),
                    'published_date': cve.get('published_date', ''),
                    'cwe_ids': ', '.join(cve.get('weakness', {}).get('cwe_ids', [])),
                    'capec_ids': ', '.join(cve.get('weakness', {}).get('capec_ids', [])),
                    'attack_techniques': ', '.join(cve.get('weakness', {}).get('attack_techniques', [])),
                    'attack_tactics': ', '.join(cve.get('weakness', {}).get('attack_tactics', [])),
                    'in_kev': 'Yes' if cve.get('threat', {}).get('in_kev') else 'No',
                    'epss_score': cve.get('threat', {}).get('epss_score', ''),
                    'exploit_count': len(cve.get('exploits', [])),
                    'patch_available': 'Yes' if cve.get('remediation', {}).get('patches') else 'No'
                }
                writer.writerow(row)
            
            csv_content = output.getvalue()
            self.send_response(200)
            self.send_header('Content-Type', 'text/csv')
            self.send_header('Content-Disposition', 'attachment; filename="cve_research_export.csv"')
            self.send_header('Content-Length', str(len(csv_content)))
            self.end_headers()
            self.wfile.write(csv_content.encode('utf-8'))
        else:
            self._send_json_response({'error': f'Unsupported format: {format_type}'}, 400)
    
    def _serve_static_file(self, path: str):
        """Serve static files (placeholder for CSS/JS)."""
        # For now, return minimal CSS
        if path.endswith('.css'):
            css = self._generate_css()
            self._send_response(200, css, 'text/css')
        else:
            self._send_404()
    
    def _generate_html(self) -> str:
        """Generate the main HTML page."""
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CVE Research Toolkit - Interactive Analysis</title>
    <link rel="stylesheet" href="/static/styles.css">
    <style>
        {self._generate_css()}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔍 CVE Research Toolkit</h1>
            <p>Interactive Vulnerability Intelligence Analysis</p>
        </header>
        
        <div class="dashboard">
            <div class="stats-panel">
                <h2>Research Overview</h2>
                <div id="stats-container">
                    <div class="stat-card">
                        <div class="stat-value" id="total-cves">-</div>
                        <div class="stat-label">Total CVEs</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value" id="avg-cvss">-</div>
                        <div class="stat-label">Avg CVSS</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value" id="exploits-available">-</div>
                        <div class="stat-label">With Exploits</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value" id="in-kev">-</div>
                        <div class="stat-label">CISA KEV</div>
                    </div>
                </div>
            </div>
            
            <div class="controls-panel">
                <h2>Search & Filter</h2>
                <div class="controls">
                    <input type="text" id="search-input" placeholder="Search CVEs, descriptions, CWEs...">
                    <select id="severity-filter">
                        <option value="">All Severities</option>
                        <option value="CRITICAL">Critical</option>
                        <option value="HIGH">High</option>
                        <option value="MEDIUM">Medium</option>
                        <option value="LOW">Low</option>
                    </select>
                    <select id="sort-select">
                        <option value="cvss_score">Sort by CVSS Score</option>
                        <option value="published_date">Sort by Date</option>
                        <option value="cve_id">Sort by CVE ID</option>
                    </select>
                    <select id="order-select">
                        <option value="desc">Descending</option>
                        <option value="asc">Ascending</option>
                    </select>
                    <div class="export-buttons">
                        <button onclick="exportData('json')">Export JSON</button>
                        <button onclick="exportData('csv')">Export CSV</button>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="content">
            <div class="cve-list-panel">
                <h2>CVE Research Results</h2>
                <div id="cve-list">
                    <div class="loading">Loading CVE data...</div>
                </div>
            </div>
            
            <div class="detail-panel">
                <div id="cve-details">
                    <div class="placeholder">
                        <h3>Select a CVE</h3>
                        <p>Click on a CVE from the list to view detailed analysis including MITRE framework mappings, exploit references, and threat intelligence.</p>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="research-panel">
            <h2>New Research</h2>
            <div class="research-controls">
                <textarea id="cve-input" placeholder="Enter CVE IDs (one per line or comma-separated)&#10;Example:&#10;CVE-2021-44228&#10;CVE-2023-23397"></textarea>
                <button id="research-btn" onclick="startResearch()">Start Research</button>
            </div>
        </div>
    </div>
    
    <script>
        {self._generate_javascript()}
    </script>
</body>
</html>"""

    def _generate_css(self) -> str:
        """Generate CSS styles."""
        return """
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
            min-height: 100vh;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        
        header {
            text-align: center;
            color: white;
            margin-bottom: 30px;
        }
        
        header h1 { font-size: 2.5em; margin-bottom: 10px; }
        header p { font-size: 1.2em; opacity: 0.9; }
        
        .dashboard {
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stats-panel, .controls-panel {
            background: white;
            border-radius: 12px;
            padding: 20px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
        }
        
        .stats-panel h2, .controls-panel h2 {
            margin-bottom: 15px;
            color: #444;
        }
        
        #stats-container {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            gap: 15px;
        }
        
        .stat-card {
            text-align: center;
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
            color: white;
            padding: 15px;
            border-radius: 8px;
        }
        
        .stat-value {
            font-size: 2em;
            font-weight: bold;
            margin-bottom: 5px;
        }
        
        .stat-label {
            font-size: 0.9em;
            opacity: 0.9;
        }
        
        .controls {
            display: grid;
            grid-template-columns: 2fr 1fr 1fr 1fr 1fr;
            gap: 10px;
        }
        
        .export-buttons {
            display: flex;
            gap: 5px;
        }
        
        .export-buttons button {
            padding: 8px 12px;
            font-size: 12px;
            background: #f8f9fa;
            border: 1px solid #ccc;
        }
        
        .export-buttons button:hover {
            background: #e9ecef;
        }
        
        input, select, button {
            padding: 10px;
            border: 2px solid #ddd;
            border-radius: 6px;
            font-size: 14px;
        }
        
        input:focus, select:focus {
            outline: none;
            border-color: #667eea;
        }
        
        .content {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .cve-list-panel, .detail-panel {
            background: white;
            border-radius: 12px;
            padding: 20px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
            max-height: 600px;
            overflow-y: auto;
        }
        
        .cve-item {
            border: 1px solid #eee;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 10px;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        
        .cve-item:hover {
            border-color: #667eea;
            box-shadow: 0 4px 12px rgba(102, 126, 234, 0.15);
        }
        
        .cve-item.selected {
            border-color: #667eea;
            background: #f8f9ff;
        }
        
        .cve-header {
            display: flex;
            justify-content: between;
            align-items: center;
            margin-bottom: 8px;
        }
        
        .cve-id {
            font-weight: bold;
            color: #667eea;
            font-size: 1.1em;
        }
        
        .cvss-badge {
            padding: 4px 8px;
            border-radius: 4px;
            color: white;
            font-size: 0.9em;
            font-weight: bold;
        }
        
        .cvss-critical { background: #dc3545; }
        .cvss-high { background: #fd7e14; }
        .cvss-medium { background: #ffc107; color: #333; }
        .cvss-low { background: #28a745; }
        
        .cve-description {
            color: #666;
            font-size: 0.9em;
            line-height: 1.4;
        }
        
        .research-panel {
            background: white;
            border-radius: 12px;
            padding: 20px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
        }
        
        .research-controls {
            display: grid;
            grid-template-columns: 1fr auto;
            gap: 15px;
            align-items: start;
        }
        
        #cve-input {
            min-height: 100px;
            resize: vertical;
        }
        
        #research-btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 15px 25px;
            border-radius: 8px;
            cursor: pointer;
            font-weight: bold;
            transition: all 0.3s ease;
        }
        
        #research-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 16px rgba(102, 126, 234, 0.3);
        }
        
        .loading {
            text-align: center;
            color: #666;
            font-style: italic;
            padding: 40px;
        }
        
        .placeholder {
            text-align: center;
            color: #666;
            padding: 40px;
        }
        
        .detail-section {
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 1px solid #eee;
        }
        
        .detail-section:last-child {
            border-bottom: none;
        }
        
        .detail-section h4 {
            color: #444;
            margin-bottom: 8px;
        }
        
        .tag {
            display: inline-block;
            background: #f0f0f0;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            margin: 2px;
        }
        
        .tag.cwe { background: #e3f2fd; color: #1976d2; }
        .tag.capec { background: #fff3e0; color: #f57c00; }
        .tag.attack { background: #fce4ec; color: #c2185b; }
        
        @media (max-width: 768px) {
            .dashboard, .content {
                grid-template-columns: 1fr;
            }
            
            .controls {
                grid-template-columns: 1fr;
            }
            
            .research-controls {
                grid-template-columns: 1fr;
            }
        }
        """

    def _generate_javascript(self) -> str:
        """Generate JavaScript functionality."""
        return """
        let currentCVEData = [];
        let selectedCVE = null;
        
        // Load initial data
        async function loadData() {
            try {
                // Load statistics
                const statsResponse = await fetch('/api/stats');
                const stats = await statsResponse.json();
                updateStatistics(stats);
                
                // Load CVE data
                await loadCVEData();
            } catch (error) {
                console.error('Error loading data:', error);
            }
        }
        
        async function loadCVEData() {
            const searchTerm = document.getElementById('search-input').value;
            const severity = document.getElementById('severity-filter').value;
            const sortBy = document.getElementById('sort-select').value;
            const order = document.getElementById('order-select').value;
            
            const params = new URLSearchParams({
                search: searchTerm,
                severity: severity,
                sort: sortBy,
                order: order
            });
            
            try {
                const response = await fetch(`/api/cves?${params}`);
                currentCVEData = await response.json();
                renderCVEList(currentCVEData);
            } catch (error) {
                console.error('Error loading CVE data:', error);
                document.getElementById('cve-list').innerHTML = '<div class="loading">Error loading CVE data</div>';
            }
        }
        
        function updateStatistics(stats) {
            document.getElementById('total-cves').textContent = stats.total_cves || 0;
            document.getElementById('avg-cvss').textContent = stats.average_cvss || 'N/A';
            document.getElementById('exploits-available').textContent = stats.cves_with_exploits || 0;
            document.getElementById('in-kev').textContent = stats.cves_in_kev || 0;
        }
        
        function renderCVEList(cves) {
            const container = document.getElementById('cve-list');
            
            if (cves.length === 0) {
                container.innerHTML = '<div class="loading">No CVEs found matching current filters</div>';
                return;
            }
            
            container.innerHTML = cves.map(cve => `
                <div class="cve-item" onclick="selectCVE('${cve.cve_id}')" data-cve-id="${cve.cve_id}">
                    <div class="cve-header">
                        <span class="cve-id">${cve.cve_id}</span>
                        <span class="cvss-badge cvss-${getSeverityClass(cve.cvss_score)}">${cve.cvss_score || 'N/A'}</span>
                    </div>
                    <div class="cve-description">${truncateText(cve.description || 'No description available', 120)}</div>
                </div>
            `).join('');
        }
        
        function getSeverityClass(score) {
            if (score >= 9.0) return 'critical';
            if (score >= 7.0) return 'high';
            if (score >= 4.0) return 'medium';
            return 'low';
        }
        
        function truncateText(text, maxLength) {
            return text.length > maxLength ? text.substring(0, maxLength) + '...' : text;
        }
        
        async function selectCVE(cveId) {
            // Update visual selection
            document.querySelectorAll('.cve-item').forEach(item => {
                item.classList.remove('selected');
            });
            document.querySelector(`[data-cve-id="${cveId}"]`).classList.add('selected');
            
            // Load detailed data
            try {
                const response = await fetch(`/api/cve?id=${cveId}`);
                const cveDetails = await response.json();
                renderCVEDetails(cveDetails);
                selectedCVE = cveId;
            } catch (error) {
                console.error('Error loading CVE details:', error);
            }
        }
        
        function renderCVEDetails(cve) {
            const container = document.getElementById('cve-details');
            
            container.innerHTML = `
                <h3>${cve.cve_id}</h3>
                
                <div class="detail-section">
                    <h4>Overview</h4>
                    <p><strong>CVSS Score:</strong> ${cve.cvss_score || 'N/A'} (${cve.severity || 'Unknown'})</p>
                    <p><strong>Published:</strong> ${formatDate(cve.published_date)}</p>
                    <p><strong>Description:</strong> ${cve.description || 'No description available'}</p>
                </div>
                
                <div class="detail-section">
                    <h4>MITRE Framework</h4>
                    <p><strong>CWE Classifications:</strong></p>
                    <div>${renderTags(cve.weakness?.cwe_ids || [], 'cwe')}</div>
                    <p><strong>CAPEC Attack Patterns:</strong></p>
                    <div>${renderTags(cve.weakness?.capec_ids || [], 'capec')}</div>
                    <p><strong>ATT&CK Techniques:</strong></p>
                    <div>${renderTags(cve.weakness?.attack_techniques || [], 'attack')}</div>
                    <p><strong>ATT&CK Tactics:</strong></p>
                    <div>${renderTags(cve.weakness?.attack_tactics || [], 'attack')}</div>
                </div>
                
                <div class="detail-section">
                    <h4>Threat Intelligence</h4>
                    <p><strong>CISA KEV:</strong> ${cve.threat?.in_kev ? 'Yes' : 'No'}</p>
                    <p><strong>EPSS Score:</strong> ${cve.threat?.epss_score || 'N/A'}</p>
                    <p><strong>EPSS Percentile:</strong> ${cve.threat?.epss_percentile || 'N/A'}</p>
                    <p><strong>Actively Exploited:</strong> ${cve.threat?.actively_exploited ? 'Yes' : 'No'}</p>
                </div>
                
                <div class="detail-section">
                    <h4>Exploits & References</h4>
                    <p><strong>Exploit Maturity:</strong> ${cve.exploit_maturity || 'Unknown'}</p>
                    <p><strong>Available Exploits:</strong> ${cve.exploits?.length || 0}</p>
                    ${renderExploits(cve.exploits || [])}
                </div>
                
                <div class="detail-section">
                    <h4>Remediation</h4>
                    <p><strong>Vendor Advisories:</strong> ${cve.vendor_advisories?.length || 0}</p>
                    <p><strong>Available Patches:</strong> ${cve.patches?.length || 0}</p>
                </div>
            `;
        }
        
        function renderTags(items, className = '') {
            if (!items || items.length === 0) return '<span class="tag">None available</span>';
            return items.map(item => `<span class="tag ${className}">${item}</span>`).join('');
        }
        
        function renderExploits(exploits) {
            if (!exploits || exploits.length === 0) return '<p>No exploits found</p>';
            return `<ul>${exploits.map(exploit => 
                `<li><a href="${exploit.url}" target="_blank">${exploit.type} (${exploit.source})</a></li>`
            ).join('')}</ul>`;
        }
        
        function formatDate(dateString) {
            if (!dateString) return 'Unknown';
            try {
                return new Date(dateString).toLocaleDateString();
            } catch {
                return dateString;
            }
        }
        
        async function startResearch() {
            const input = document.getElementById('cve-input').value.trim();
            if (!input) {
                alert('Please enter CVE IDs');
                return;
            }
            
            // Parse CVE IDs
            const cveIds = input.split(/[\\n,]/).map(id => id.trim()).filter(id => id);
            
            if (cveIds.length === 0) {
                alert('Please enter valid CVE IDs');
                return;
            }
            
            try {
                const response = await fetch('/api/research', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ cve_ids: cveIds })
                });
                
                const result = await response.json();
                
                if (response.ok) {
                    alert(`Research completed for ${result.cve_ids.length} CVEs!`);
                    // Refresh the page to show new data
                    window.location.reload();
                } else {
                    alert(`Error: ${result.error}`);
                }
            } catch (error) {
                console.error('Research request failed:', error);
                alert('Failed to start research. Please try again.');
            }
        }
        
        // Event listeners
        document.getElementById('search-input').addEventListener('input', 
            debounce(loadCVEData, 300)
        );
        
        document.getElementById('severity-filter').addEventListener('change', loadCVEData);
        document.getElementById('sort-select').addEventListener('change', loadCVEData);
        document.getElementById('order-select').addEventListener('change', loadCVEData);
        
        function debounce(func, wait) {
            let timeout;
            return function executedFunction(...args) {
                const later = () => {
                    clearTimeout(timeout);
                    func(...args);
                };
                clearTimeout(timeout);
                timeout = setTimeout(later, wait);
            };
        }
        
        function exportData(format) {
            const url = `/api/export?format=${format}`;
            const link = document.createElement('a');
            link.href = url;
            link.download = `cve_research_export.${format}`;
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        }
        
        // Initialize
        loadData();
        """

    def _send_response(self, status_code: int, content: str, content_type: str = 'text/html'):
        """Send HTTP response."""
        self.send_response(status_code)
        self.send_header('Content-type', f'{content_type}; charset=utf-8')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
        self.wfile.write(content.encode('utf-8'))
    
    def _send_json_response(self, data: Any, status_code: int = 200):
        """Send JSON response."""
        json_content = json.dumps(data, indent=2, default=str)
        self._send_response(status_code, json_content, 'application/json')
    
    def _send_404(self):
        """Send 404 response."""
        self._send_response(404, '404 Not Found', 'text/plain')
    
    def log_message(self, format, *args):
        """Override to reduce logging noise."""
        pass


class CVEResearchUIServer:
    """Local web server for CVE Research UI."""
    
    def __init__(self, host: str = 'localhost', port: int = 8080):
        self.host = host
        self.port = port
        self.research_data: List[Dict[str, Any]] = []
        self.server: Optional[HTTPServer] = None
        self.server_thread: Optional[threading.Thread] = None
    
    def load_research_data(self, data_file: Optional[Path] = None):
        """Load research data from file or generate sample data."""
        if data_file and data_file.exists():
            try:
                with open(data_file, 'r') as f:
                    if data_file.suffix.lower() in ['.json', '.webui']:
                        self.research_data = json.load(f)
                        print(f"Loaded {len(self.research_data)} CVEs from {data_file}")
                    else:
                        print(f"Unsupported file format: {data_file.suffix}")
            except Exception as e:
                print(f"Error loading data file {data_file}: {e}")
                self._generate_sample_data()
        else:
            # Start with empty data - user can research CVEs from the UI
            self.research_data = []
            print("Started with empty data - use the research panel to analyze CVEs")
    
    def _generate_sample_data(self):
        """Generate sample CVE data for demonstration."""
        self.research_data = [
            {
                'cve_id': 'CVE-2021-44228',
                'description': 'Apache Log4j2 remote code execution vulnerability',
                'cvss_score': 10.0,
                'severity': 'CRITICAL',
                'published_date': '2021-12-09',
                'weakness': {
                    'cwe_ids': ['CWE-502'],
                    'capec_ids': ['CAPEC-586'],
                    'attack_techniques': ['T1203'],
                    'attack_tactics': ['TA0002']
                },
                'threat': {
                    'in_kev': True,
                    'epss_score': 0.97,
                    'epss_percentile': 99.5,
                    'actively_exploited': True
                },
                'exploits': [
                    {'url': 'https://github.com/kozmer/log4j-shell-poc', 'source': 'github', 'type': 'poc'}
                ],
                'exploit_maturity': 'weaponized',
                'vendor_advisories': ['https://logging.apache.org/log4j/2.x/security.html'],
                'patches': ['https://github.com/apache/logging-log4j2/pull/608']
            },
            {
                'cve_id': 'CVE-2023-23397',
                'description': 'Microsoft Outlook privilege escalation vulnerability',
                'cvss_score': 9.8,
                'severity': 'CRITICAL',
                'published_date': '2023-03-14',
                'weakness': {
                    'cwe_ids': ['CWE-269'],
                    'capec_ids': ['CAPEC-122'],
                    'attack_techniques': ['T1068'],
                    'attack_tactics': ['TA0004']
                },
                'threat': {
                    'in_kev': True,
                    'epss_score': 0.12,
                    'epss_percentile': 85.2,
                    'actively_exploited': True
                },
                'exploits': [],
                'exploit_maturity': 'unproven',
                'vendor_advisories': ['https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-23397'],
                'patches': []
            }
        ]
        print(f"Generated {len(self.research_data)} sample CVEs for demonstration")
    
    def start_server(self, open_browser: bool = True):
        """Start the web server."""
        def create_handler(*args, **kwargs):
            return CVEResearchUIHandler(*args, research_data=self.research_data, server_instance=self, **kwargs)
        
        try:
            self.server = HTTPServer((self.host, self.port), create_handler)
            
            def run_server():
                print(f"CVE Research UI Server starting at http://{self.host}:{self.port}")
                self.server.serve_forever()
            
            self.server_thread = threading.Thread(target=run_server, daemon=True)
            self.server_thread.start()
            
            # Give server time to start
            time.sleep(1)
            
            if open_browser:
                webbrowser.open(f"http://{self.host}:{self.port}")
            
            print(f"🌐 CVE Research UI available at: http://{self.host}:{self.port}")
            print("Press Ctrl+C to stop the server")
            
        except OSError as e:
            if e.errno == 48:  # Address already in use
                print(f"Port {self.port} is already in use. Try a different port.")
            else:
                print(f"Failed to start server: {e}")
            return False
        
        return True
    
    def stop_server(self):
        """Stop the web server."""
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            print("Server stopped")


def main():
    """Main entry point for the web UI."""
    import argparse
    
    parser = argparse.ArgumentParser(description="CVE Research Toolkit - Web UI")
    parser.add_argument('--host', default='localhost', help='Host to bind to (default: localhost)')
    parser.add_argument('--port', type=int, default=8080, help='Port to bind to (default: 8080)')
    parser.add_argument('--data-file', type=Path, help='JSON file with research data to load')
    parser.add_argument('--no-browser', action='store_true', help='Do not open browser automatically')
    
    args = parser.parse_args()
    
    # Create and configure server
    server = CVEResearchUIServer(args.host, args.port)
    server.load_research_data(args.data_file)
    
    try:
        if server.start_server(open_browser=not args.no_browser):
            # Keep main thread alive
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        print("\\nShutting down...")
        server.stop_server()


if __name__ == '__main__':
    main()