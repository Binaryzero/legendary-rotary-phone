# CVE Research Toolkit - Web UI Guide

## Overview

The CVE Research Toolkit now includes a comprehensive **local web interface** that transforms static vulnerability research data into an interactive, searchable, and filterable analysis platform.

## Key Features

### 🎯 **Interactive Dashboard**
- Real-time statistics overview (Total CVEs, Average CVSS, Exploits Available, CISA KEV count)
- Visual severity distribution and threat intelligence metrics
- Comprehensive research summary at a glance

### 🔍 **Advanced Search & Filtering**
- **Global Search**: Search across CVE IDs, descriptions, and CWE classifications
- **Severity Filtering**: Filter by Critical, High, Medium, Low severity levels
- **Flexible Sorting**: Sort by CVSS score, publication date, or CVE ID
- **Real-time Updates**: Instant filtering with debounced search (300ms delay)

### 📊 **Detailed CVE Analysis**
- **MITRE Framework Integration**: Complete CWE, CAPEC, and ATT&CK mappings with visual tags
- **Threat Intelligence**: CISA KEV status, EPSS scores/percentiles, active exploitation indicators
- **Exploit References**: Direct links to PoCs, Exploit-DB entries, and security advisories
- **Remediation Information**: Vendor advisories, patches, and mitigation guidance

### 🎨 **Modern User Experience**
- **Responsive Design**: CSS Grid layout optimized for desktop and mobile
- **Visual Hierarchy**: Color-coded severity badges and framework tags
- **Professional Styling**: Gradient backgrounds, smooth transitions, and modern typography
- **Intuitive Navigation**: Click-to-expand details with visual selection feedback

## Quick Start

### Option 1: Demo Mode (Instant Start)
```bash
python3 start_webui.py --demo
```
- Launches immediately with sample CVE data
- Perfect for exploring UI features and capabilities
- No network dependencies or research time required

### Option 2: Research & Launch (Complete Workflow)
```bash
python3 start_webui.py --research cves.txt
```
- Automatically researches CVEs from your input file
- Exports data in web-optimized format
- Launches UI with fresh research results

### Option 3: Existing Data (Use Previous Research)
```bash
python3 start_webui.py --data research_output/research_report_20241214.json
```
- Load previously generated research data
- Supports any JSON export from the main toolkit
- Instant startup with comprehensive data

## Manual Export & Launch

For advanced workflows, you can separate research and UI phases:

```bash
# Step 1: Research CVEs with web UI export
python3 cve_research_toolkit_fixed.py --format webui cves.txt

# Step 2: Launch UI with generated data
python3 cve_research_ui.py --data-file research_output/webui_data_*.json
```

## Web Interface Walkthrough

### Dashboard Overview
- **Statistics Panel**: Key metrics and threat intelligence summary
- **Search Controls**: Global search, severity filter, and sorting options
- **CVE List**: Scrollable list with CVSS badges and truncated descriptions
- **Detail Panel**: Comprehensive analysis of selected CVE

### MITRE Framework Display
The UI provides complete visual representation of MITRE framework mappings:
- **CWE Tags**: Blue-coded weakness classifications
- **CAPEC Tags**: Orange-coded attack pattern identifiers  
- **ATT&CK Techniques**: Pink-coded technique identifiers (T-codes)
- **ATT&CK Tactics**: Pink-coded tactic identifiers (TA-codes)

### Threat Intelligence Integration
- **CISA KEV Status**: Clear Yes/No indication for Known Exploited Vulnerabilities
- **EPSS Scoring**: Exploitation probability with percentile ranking
- **Active Exploitation**: Real-world threat activity indicators
- **Tool Availability**: Metasploit and Nuclei module presence

## Configuration Options

### Server Settings
```bash
# Custom host and port
python3 start_webui.py --demo --host 0.0.0.0 --port 8090

# Disable auto-browser opening
python3 start_webui.py --demo --no-browser
```

### Data Sources
The web UI consumes data from:
- **Main Toolkit JSON Export**: Standard research data export
- **Web UI Optimized Export**: Streamlined format for faster loading
- **Manual JSON Files**: Any compatible CVE research data

## Technical Architecture

### Frontend
- **Pure HTML/CSS/JavaScript**: No external frameworks or dependencies
- **Responsive CSS Grid**: Modern layout with mobile support
- **Vanilla JavaScript**: ES6+ features with browser compatibility
- **REST API Integration**: Asynchronous data fetching with error handling

### Backend
- **Python HTTP Server**: Built-in `http.server` with custom request handler
- **RESTful Endpoints**: JSON API for data retrieval and filtering
- **In-Memory Processing**: Fast search and filtering without database overhead
- **Cross-Origin Support**: CORS headers for development flexibility

### Security
- **Local-Only Access**: Binds to localhost by default for security
- **No Persistent Storage**: All data handling in memory during session
- **Input Validation**: Sanitized search parameters and data filtering

## Browser Compatibility

**Tested Browsers:**
- Chrome 90+ ✅
- Firefox 88+ ✅  
- Safari 14+ ✅
- Edge 90+ ✅

**Required Features:**
- ES6 JavaScript support
- CSS Grid layout
- Fetch API for AJAX requests

## Integration Examples

### Automated Workflow
```bash
#!/bin/bash
# Daily CVE research with web UI
python3 cve_research_toolkit_fixed.py --format webui daily_cves.txt
python3 start_webui.py --data research_output/webui_*.json --no-browser
echo "CVE analysis available at http://localhost:8080"
```

### Custom Analysis
```bash
# Research specific high-severity CVEs
echo "CVE-2021-44228\nCVE-2023-23397" > critical_cves.txt
python3 start_webui.py --research critical_cves.txt
```

## Performance Notes

- **Initial Load**: Sub-second startup with cached sample data
- **Data Processing**: Real-time filtering for datasets up to 1000+ CVEs
- **Memory Usage**: Approximately 50-100MB for typical research sessions
- **Network**: No external dependencies once research data is generated

## Troubleshooting

### Port Already in Use
```bash
# Try different port
python3 start_webui.py --demo --port 8081
```

### Large Dataset Performance
For datasets with 500+ CVEs, consider:
- Using severity filters to reduce initial display
- Implementing pagination (future enhancement)
- Splitting data into focused analysis sessions

### Browser Not Opening
```bash
# Manual browser launch
python3 start_webui.py --demo --no-browser
# Then open: http://localhost:8080
```

## Future Enhancements

Planned improvements for the web UI:
- **Export Functionality**: Download filtered results as CSV/JSON
- **Advanced Visualizations**: CVSS distribution charts and timeline views
- **Collaboration Features**: Shared analysis sessions and annotations
- **Plugin Integration**: Custom analysis modules and data sources

---

**Ready to explore?** Start with `python3 start_webui.py --demo` and experience interactive CVE analysis!