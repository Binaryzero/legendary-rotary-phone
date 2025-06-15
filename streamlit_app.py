#!/usr/bin/env python3
"""
CVE Research Toolkit - Enterprise Streamlit Dashboard

Professional vulnerability intelligence platform with advanced analytics,
real-time research capabilities, and enterprise-grade visualizations.
"""

import asyncio
import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots

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
    st.error("CVE Research Toolkit not available. Please install the package.")

# Configure page
st.set_page_config(
    page_title="CVE Research Toolkit",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        'Get Help': 'https://github.com/Binaryzero/legendary-rotary-phone',
        'Report a bug': 'https://github.com/Binaryzero/legendary-rotary-phone/issues',
        'About': "Enterprise-grade vulnerability intelligence platform"
    }
)

# Clean, professional styling
st.markdown("""
<style>
    /* Clean layout with proper spacing */
    .main > div {
        padding-top: 1rem;
        max-width: 1200px;
        margin: 0 auto;
    }
    
    /* Consistent text sizing */
    .stTextInput input, .stTextArea textarea, .stSelectbox select {
        font-size: 16px !important;
    }
    
    /* Professional button styling */
    .stButton > button {
        font-size: 16px !important;
        font-weight: 500;
        height: 2.5rem;
        border-radius: 6px;
    }
    
    /* Clear section headers */
    .stSubheader {
        color: #1f2937;
        border-bottom: 2px solid #e5e7eb;
        padding-bottom: 0.5rem;
        margin-bottom: 1rem;
    }
    
    /* Expander styling */
    .streamlit-expanderHeader {
        background-color: #f9fafb;
        border: 1px solid #e5e7eb;
        border-radius: 6px;
        font-size: 16px !important;
        font-weight: 500;
    }
    
    /* Improved dataframes */
    .stDataFrame {
        border: 1px solid #e5e7eb;
        border-radius: 6px;
    }
    
    /* Clean metrics */
    .stMetric {
        background: white;
        border: 1px solid #e5e7eb;
        border-radius: 8px;
        padding: 1rem;
    }
    
    .stMetric > div {
        text-align: center;
    }
    
    /* Alert styling */
    .stAlert {
        border-radius: 6px;
        border: none;
    }
    
    /* File uploader spacing */
    .stFileUploader {
        margin-top: 1rem;
        margin-bottom: 1rem;
    }
    
    /* Better spacing for results */
    .element-container {
        margin-bottom: 0.5rem;
    }
</style>
""", unsafe_allow_html=True)

# Session state initialization
if 'research_data' not in st.session_state:
    st.session_state.research_data = []
if 'research_history' not in st.session_state:
    st.session_state.research_history = []


def create_executive_summary(data: List[Dict[str, Any]]) -> None:
    """Create executive summary dashboard."""
    if not data:
        st.warning("No data available for analysis")
        return
    
    # Key metrics
    col1, col2, col3, col4 = st.columns(4)
    
    total_cves = len(data)
    critical_high = len([d for d in data if d.get('severity', '').upper() in ['CRITICAL', 'HIGH']])
    in_kev = len([d for d in data if d.get('threat', {}).get('in_kev', False)])
    with_exploits = len([d for d in data if d.get('exploits', [])])
    
    with col1:
        st.markdown(f"""
        <div class="metric-container">
            <h3>Total CVEs</h3>
            <h2>{total_cves}</h2>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown(f"""
        <div class="metric-container">
            <h3>Critical/High</h3>
            <h2>{critical_high}</h2>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown(f"""
        <div class="metric-container">
            <h3>CISA KEV</h3>
            <h2>{in_kev}</h2>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        st.markdown(f"""
        <div class="metric-container">
            <h3>With Exploits</h3>
            <h2>{with_exploits}</h2>
        </div>
        """, unsafe_allow_html=True)

def create_threat_landscape_charts(data: List[Dict[str, Any]]) -> None:
    """Create comprehensive threat landscape visualizations."""
    if not data:
        return
    
    df = pd.DataFrame(data)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Severity Distribution")
        severity_counts = df['severity'].value_counts()
        
        fig = px.pie(
            values=severity_counts.values,
            names=severity_counts.index,
            color_discrete_map={
                'CRITICAL': '#dc2626',
                'HIGH': '#ea580c',
                'MEDIUM': '#d97706',
                'LOW': '#0891b2'
            },
            title="CVE Severity Breakdown"
        )
        fig.update_layout(
            font_size=14,
            title_font_size=16,
            showlegend=True
        )
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.subheader("CVSS Score Distribution")
        fig = px.histogram(
            df,
            x='cvss_score',
            nbins=20,
            title="CVSS Score Distribution",
            color_discrete_sequence=['#3b82f6']
        )
        fig.update_layout(
            xaxis_title="CVSS Score",
            yaxis_title="Number of CVEs",
            font_size=14,
            title_font_size=16
        )
        st.plotly_chart(fig, use_container_width=True)

def create_mitre_analysis(data: List[Dict[str, Any]]) -> None:
    """Create MITRE framework analysis visualizations."""
    if not data:
        return
    
    st.subheader("MITRE Framework Analysis")
    
    # Extract MITRE data
    all_cwes = []
    all_tactics = []
    all_techniques = []
    
    for item in data:
        weakness = item.get('weakness', {})
        all_cwes.extend(weakness.get('cwe_ids', []))
        all_tactics.extend(weakness.get('attack_tactics', []))
        all_techniques.extend(weakness.get('attack_techniques', []))
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if all_cwes:
            cwe_counts = pd.Series(all_cwes).value_counts().head(10)
            fig = px.bar(
                x=cwe_counts.values,
                y=cwe_counts.index,
                orientation='h',
                title="Top CWE Weaknesses",
                color_discrete_sequence=['#8b5cf6']
            )
            fig.update_layout(yaxis={'categoryorder': 'total ascending'})
            st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        if all_tactics:
            tactic_counts = pd.Series(all_tactics).value_counts()
            fig = px.bar(
                x=tactic_counts.index,
                y=tactic_counts.values,
                title="ATT&CK Tactics",
                color_discrete_sequence=['#ef4444']
            )
            fig.update_xaxes(tickangle=45)
            st.plotly_chart(fig, use_container_width=True)
    
    with col3:
        if all_techniques:
            technique_counts = pd.Series(all_techniques).value_counts().head(10)
            fig = px.bar(
                x=technique_counts.index,
                y=technique_counts.values,
                title="Top ATT&CK Techniques",
                color_discrete_sequence=['#f59e0b']
            )
            fig.update_xaxes(tickangle=45)
            st.plotly_chart(fig, use_container_width=True)

def create_threat_intelligence_view(data: List[Dict[str, Any]]) -> None:
    """Create threat intelligence focused view."""
    if not data:
        return
    
    st.subheader("Threat Intelligence Overview")
    
    # EPSS scores analysis
    epss_data = [item.get('threat', {}).get('epss_score', 0) for item in data if item.get('threat', {}).get('epss_score')]
    
    if epss_data:
        col1, col2 = st.columns(2)
        
        with col1:
            fig = px.scatter(
                x=range(len(epss_data)),
                y=epss_data,
                title="EPSS Exploitation Probability",
                labels={'x': 'CVE Index', 'y': 'EPSS Score'},
                color=epss_data,
                color_continuous_scale='Reds'
            )
            fig.add_hline(y=0.7, line_dash="dash", annotation_text="High Risk Threshold")
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # KEV status
            kev_data = [item.get('threat', {}).get('in_kev', False) for item in data]
            kev_counts = pd.Series(kev_data).value_counts()
            
            fig = px.pie(
                values=kev_counts.values,
                names=['Not in KEV', 'In CISA KEV'] if False in kev_counts.index else ['In CISA KEV'],
                title="CISA KEV Status",
                color_discrete_map={
                    'In CISA KEV': '#dc2626',
                    'Not in KEV': '#6b7280'
                }
            )
            st.plotly_chart(fig, use_container_width=True)

def create_detailed_cve_table(data: List[Dict[str, Any]], search_term: str = "", severity_filter: str = "All") -> None:
    """Create detailed CVE analysis table with filtering."""
    if not data:
        return
    
    st.subheader("Detailed CVE Analysis")
    
    # Apply filters
    filtered_data = data
    
    if search_term:
        filtered_data = [
            item for item in filtered_data
            if search_term.lower() in item.get('cve_id', '').lower() or
               search_term.lower() in item.get('description', '').lower()
        ]
    
    if severity_filter != "All":
        filtered_data = [
            item for item in filtered_data
            if item.get('severity', '').upper() == severity_filter.upper()
        ]
    
    for item in filtered_data:
        with st.expander(f"**{item.get('cve_id', 'Unknown')}** - {item.get('severity', 'Unknown')} Severity"):
            col1, col2 = st.columns([2, 1])
            
            with col1:
                st.write(f"**Description:** {item.get('description', 'Not available')}")
                st.write(f"**CVSS Score:** {item.get('cvss_score', 'N/A')}")
                
                # MITRE framework data
                weakness = item.get('weakness', {})
                if weakness.get('cwe_ids'):
                    cwe_tags = " ".join([f'<span class="mitre-tag">{cwe}</span>' for cwe in weakness['cwe_ids']])
                    st.markdown(f"**CWE IDs:** {cwe_tags}", unsafe_allow_html=True)
                
                if weakness.get('attack_techniques'):
                    tech_tags = " ".join([f'<span class="mitre-tag">{tech}</span>' for tech in weakness['attack_techniques']])
                    st.markdown(f"**ATT&CK Techniques:** {tech_tags}", unsafe_allow_html=True)
            
            with col2:
                threat = item.get('threat', {})
                
                if threat.get('in_kev'):
                    st.markdown('<span class="threat-indicator">CISA KEV</span>', unsafe_allow_html=True)
                
                if threat.get('actively_exploited'):
                    st.markdown('<span class="threat-indicator">Active Exploitation</span>', unsafe_allow_html=True)
                
                if threat.get('epss_score'):
                    st.write(f"**EPSS Score:** {threat['epss_score']:.3f}")
                
                exploits = item.get('exploits', [])
                if exploits:
                    st.write(f"**Exploits Found:** {len(exploits)}")

async def research_cves(cve_list: List[str]) -> List[Dict[str, Any]]:
    """Research CVEs using the toolkit."""
    if not TOOLKIT_AVAILABLE:
        st.error("Research toolkit not available")
        return []
    
    try:
        config_data = {}
        engine = VulnerabilityResearchEngine(config_data)
        
        with st.spinner(f"Researching {len(cve_list)} CVEs..."):
            research_results = await engine.research_batch(cve_list)
        
        # Convert ResearchData objects to dictionaries
        results = []
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
                    "epss_score": rd.threat.epss_score,
                    "epss_percentile": rd.threat.epss_percentile,
                    "actively_exploited": rd.threat.actively_exploited,
                    "has_metasploit": rd.threat.has_metasploit,
                    "has_nuclei": rd.threat.has_nuclei
                },
                "exploits": [{"url": exp.url, "source": exp.source, "type": exp.type} for exp in rd.exploits],
                "exploit_maturity": rd.exploit_maturity,
                "cpe_affected": rd.cpe_affected,
                "vendor_advisories": rd.vendor_advisories,
                "patches": rd.patches,
                "last_enriched": rd.last_enriched.isoformat() if rd.last_enriched else None
            }
            results.append(result)
        
        return results
    
    except Exception as e:
        st.error(f"Research failed: {str(e)}")
        return []

def export_data(data: List[Dict[str, Any]], format_type: str) -> None:
    """Export data in specified format."""
    if not data:
        st.warning("No data to export")
        return
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    if format_type == "JSON":
        json_data = json.dumps(data, indent=2)
        st.download_button(
            label="Download JSON",
            data=json_data,
            file_name=f"cve_research_{timestamp}.json",
            mime="application/json"
        )
    
    elif format_type == "CSV":
        df = pd.json_normalize(data)
        csv_data = df.to_csv(index=False)
        st.download_button(
            label="Download CSV",
            data=csv_data,
            file_name=f"cve_research_{timestamp}.csv",
            mime="text/csv"
        )

def main():
    """Main Streamlit application."""
    st.title("CVE Research Toolkit")
    
    if not TOOLKIT_AVAILABLE:
        st.error("CVE Research Toolkit not available. Please install the package.")
        return
    
    # Initialize variables
    uploaded_file = None
    search = ""
    
    # Show input only when no results exist
    if not st.session_state.research_data:
        col1, col2 = st.columns([3, 1])
        with col1:
            cve_input = st.text_area(
                "Enter CVE IDs:",
                placeholder="CVE-2023-44487, CVE-2021-44228, CVE-2023-23397",
                height=100
            )
        with col2:
            st.write("")  # Add spacing to align with text area
            uploaded_file = st.file_uploader("Upload file:", type=['txt', 'csv'])
            research_button = st.button("Research", type="primary", use_container_width=True)
    else:
        # Compact input when results exist
        col1, col2, col3, col4 = st.columns([2, 1, 1, 1])
        with col1:
            cve_input = st.text_input("Add more CVEs:", placeholder="CVE-2024-1234")
        with col2:
            research_button = st.button("Research")
        with col3:
            search = st.text_input("Search:")
        with col4:
            if st.button("Export CSV"):
                export_data(st.session_state.research_data, "CSV")
        
    # Process input when button clicked
    if research_button:
        cve_list = []
        
        if cve_input:
            text = cve_input.replace(',', '\n')
            new_cves = [item.strip() for item in text.split('\n') if item.strip().startswith('CVE-')]
            if new_cves:
                results = asyncio.run(research_cves(new_cves))
                if results:
                    # Add to existing results or create new
                    if st.session_state.research_data:
                        st.session_state.research_data.extend(results)
                    else:
                        st.session_state.research_data = results
                    st.rerun()
        elif uploaded_file:
            content = uploaded_file.read().decode('utf-8')
            content = content.replace(',', '\n')
            cve_list = [item.strip() for item in content.split('\n') if item.strip().startswith('CVE-')]
            if cve_list:
                results = asyncio.run(research_cves(cve_list))
                if results:
                    st.session_state.research_data = results
                    st.rerun()
        
    # Show results summary table
    if st.session_state.research_data:
        # Apply search filter
        filtered_data = st.session_state.research_data
        if search:
            filtered_data = [
                item for item in filtered_data
                if search.lower() in item.get('cve_id', '').lower() or
                   search.lower() in item.get('description', '').lower()
            ]
        
        st.markdown("---")
        
        # Dashboard view - summary table with drill-down
        import pandas as pd
        
        # Create summary table
        summary_data = []
        for item in filtered_data:
            threat = item.get('threat', {})
            exploits = item.get('exploits', [])
            patches = item.get('patches', [])
            
            priority = "HIGH" if (threat.get('in_kev') or threat.get('actively_exploited') or len(exploits) > 10) else "MEDIUM" if len(exploits) > 0 else "LOW"
            
            summary_data.append({
                'CVE': item.get('cve_id', 'Unknown'),
                'Severity': item.get('severity', 'Unknown'),
                'CVSS': item.get('cvss_score', 'N/A'),
                'Priority': priority,
                'KEV': 'Yes' if threat.get('in_kev') else 'No',
                'Exploits': len(exploits),
                'Patches': len(patches),
                'EPSS': f"{threat.get('epss_score', 0):.2f}" if threat.get('epss_score') else 'N/A'
            })
        
        if summary_data:
            df = pd.DataFrame(summary_data)
            
            st.subheader("CVE Summary Dashboard")
            st.dataframe(df, use_container_width=True, hide_index=True)
            
            # CVE selector for detailed view
            st.subheader("Detailed Analysis")
            cve_options = [item.get('cve_id', 'Unknown') for item in filtered_data]
            
            if len(cve_options) == 1:
                selected_cve = cve_options[0]
                st.info(f"Showing details for {selected_cve}")
            else:
                selected_cve = st.selectbox("Select CVE for detailed analysis:", cve_options)
            
            # Show detailed view for selected CVE
            selected_item = next((item for item in filtered_data if item.get('cve_id') == selected_cve), None)
            
            if selected_item:
                # Key metrics in columns
                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    threat = selected_item.get('threat', {})
                    kev_status = "Yes" if threat.get('in_kev') else "No"
                    st.metric("CISA KEV", kev_status)
                with col2:
                    exploits = selected_item.get('exploits', [])
                    st.metric("Known Exploits", len(exploits))
                with col3:
                    patches = selected_item.get('patches', [])
                    st.metric("Available Patches", len(patches))
                with col4:
                    epss = threat.get('epss_score', 0)
                    st.metric("EPSS Score", f"{epss:.3f}" if epss else "N/A")
                
                # Tabbed detailed view
                tab1, tab2, tab3, tab4 = st.tabs(["Overview", "Exploits", "Remediation", "Technical"])
                
                with tab1:
                    st.write(f"**Description:** {selected_item.get('description', 'No description')}")
                    st.write(f"**Published:** {selected_item.get('published_date', 'N/A')}")
                    
                    weakness = selected_item.get('weakness', {})
                    if weakness.get('cwe_ids'):
                        st.write(f"**CWE:** {', '.join(weakness['cwe_ids'])}")
                    if weakness.get('attack_techniques'):
                        st.write(f"**MITRE ATT&CK:** {', '.join(weakness['attack_techniques'])}")
                
                with tab2:
                    if exploits:
                        exploit_df = pd.DataFrame([{
                            'Type': e.get('type', 'Unknown'),
                            'Source': e.get('source', 'Unknown'),
                            'URL': e.get('url', 'No URL')
                        } for e in exploits])
                        st.dataframe(exploit_df, use_container_width=True)
                    else:
                        st.info("No known exploits")
                
                with tab3:
                    if patches:
                        st.markdown("**Available Patches:**")
                        for i, patch in enumerate(patches, 1):
                            st.write(f"{i}. {patch}")
                    
                    vendor_advisories = selected_item.get('vendor_advisories', [])
                    if vendor_advisories:
                        st.markdown("**Vendor Advisories:**")
                        for i, advisory in enumerate(vendor_advisories, 1):
                            st.write(f"{i}. {advisory}")
                    
                    if not patches and not vendor_advisories:
                        st.info("No remediation information available")
                
                with tab4:
                    if weakness.get('capec_ids'):
                        st.write(f"**CAPEC IDs:** {', '.join(weakness['capec_ids'])}")
                    if weakness.get('attack_tactics'):
                        st.write(f"**ATT&CK Tactics:** {', '.join(weakness['attack_tactics'])}")
                    if selected_item.get('cvss_vector'):
                        st.write(f"**CVSS Vector:** {selected_item.get('cvss_vector')}")
                    
                    cpe_affected = selected_item.get('cpe_affected', [])
                    if cpe_affected:
                        st.markdown(f"**Affected Products ({len(cpe_affected)}):**")
                        for cpe in cpe_affected:
                            st.write(cpe)
                    
                    references = selected_item.get('references', [])
                    if references:
                        st.markdown(f"**References ({len(references)}):**")
                        for ref in references:
                            st.write(ref)
        else:
            st.info("No CVEs match search criteria")
    else:
        st.info("Enter CVE IDs above to start research")
    

if __name__ == "__main__":
    main()