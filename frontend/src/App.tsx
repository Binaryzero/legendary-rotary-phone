import React, { useState, useEffect, useCallback } from 'react';
import { AgGridReact } from 'ag-grid-react';
import { ColDef } from 'ag-grid-community';
import axios from 'axios';
import 'ag-grid-community/styles/ag-grid.css';
import 'ag-grid-community/styles/ag-theme-alpine.css';
import './App.css';

interface CVEData {
  cve_id: string;
  description: string;
  cvss_score: number | null;
  cvss_vector?: string;
  severity: string;
  published_date: string | null;
  last_modified?: string;
  threat: {
    in_kev: boolean;
    vulncheck_kev: boolean;
    epss_score: number | null;
    epss_percentile: number | null;
    vedas_score: number | null;
    vedas_percentile: number | null;
    vedas_score_change: number | null;
    vedas_detail_url: string;
    vedas_date: string | null;
    temporal_score: number | null;
    exploit_code_maturity: string;
    remediation_level: string;
    report_confidence: string;
    actively_exploited: boolean;
    has_metasploit: boolean;
    has_nuclei: boolean;
    ransomware_campaign: boolean;
    kev_vulnerability_name: string;
    kev_short_description: string;
    kev_vendor_project: string;
    kev_product: string;
  };
  exploits: Array<{ url: string; source: string; type: string }>;
  patches: string[];
  weakness: {
    cwe_ids: string[];
    capec_ids: string[];
    attack_techniques: string[];
    attack_tactics: string[];
    kill_chain_phases: string[];
  };
  enhanced_problem_type: {
    primary_weakness: string;
    secondary_weaknesses: string;
    vulnerability_categories: string;
    impact_types: string;
    attack_vectors: string;
    enhanced_cwe_details: string;
  };
  control_mappings: {
    applicable_controls_count: string;
    control_categories: string;
    top_controls: string;
  };
  product_intelligence: {
    vendors: string[];
    products: string[];
    affected_versions: string[];
    platforms: string[];
    modules: string[];
    repositories: string[];
  };
  exploit_maturity?: string;
  cpe_affected?: string;
  vendor_advisories?: string[];
  references?: string[];
  last_enriched?: string;
}

interface ApiResponse {
  data: CVEData[];
  pagination: {
    page: number;
    per_page: number;
    total_items: number;
    total_pages: number;
    has_next: boolean;
    has_prev: boolean;
  };
  summary: {
    total_cves: number;
    filtered_cves: number;
    critical_high: number;
    in_kev: number;
    with_exploits: number;
  };
}

const App: React.FC = () => {
  const [rowData, setRowData] = useState<CVEData[]>([]);
  const [loading, setLoading] = useState(false);
  const [pagination, setPagination] = useState({
    page: 1,
    per_page: 25,
    total_items: 0,
    total_pages: 0
  });
  const [summary, setSummary] = useState({
    total_cves: 0,
    filtered_cves: 0,
    critical_high: 0,
    in_kev: 0,
    with_exploits: 0
  });
  const [filters, setFilters] = useState({
    search: '',
    severity: '',
    kev: '',
    exploits: ''
  });
  const [researchInput, setResearchInput] = useState('');
  const [selectedCve, setSelectedCve] = useState<CVEData | null>(null);
  const [selectedCveIndex, setSelectedCveIndex] = useState<number>(-1);
  const [pendingNavigation, setPendingNavigation] = useState<'first' | 'last' | null>(null);
  const [uploadType, setUploadType] = useState<'json' | 'cve-list'>('cve-list');
  const [expandedSections, setExpandedSections] = useState<Record<string, boolean>>({
    overview: true,
    threat: true,
    exploits: false,
    patches: false,
    enhanced_problem_type: false,
    mitre: false,
    controls: false,
    references: false,
    technical: false
  });

  const columnDefs: ColDef[] = [
    {
      field: 'cve_id',
      headerName: 'CVE ID',
      width: 200,
      pinned: 'left',
      cellRenderer: (params: any) => (
        <button 
          className="cve-link"
          onClick={() => {
            const index = rowData.findIndex(item => item.cve_id === params.data.cve_id);
            setSelectedCve(params.data);
            setSelectedCveIndex(index);
          }}
          style={{
            background: 'none',
            border: 'none',
            color: 'var(--accent-blue)',
            cursor: 'pointer',
            textDecoration: 'underline',
            fontSize: '1.3rem',
            fontWeight: '600'
          }}
        >
          {params.value}
        </button>
      )
    },
    {
      field: 'severity',
      headerName: 'Severity',
      width: 180,
      cellRenderer: (params: any) => (
        <span className={`severity-badge ${params.value?.toLowerCase()}`} style={{
          fontSize: '1.2rem',
          padding: '0.4rem 0.8rem'
        }}>
          {params.value}
        </span>
      )
    },
    {
      field: 'cvss_score',
      headerName: 'CVSS Score',
      width: 160,
      type: 'numericColumn',
      cellRenderer: (params: any) => (
        <span style={{ fontWeight: '600', fontSize: '1.3rem' }}>
          {params.value || 'N/A'}
        </span>
      )
    },
    {
      field: 'threat.in_kev',
      headerName: 'CISA KEV',
      width: 160,
      cellRenderer: (params: any) => (
        <div style={{ 
          display: 'flex', 
          alignItems: 'center', 
          gap: '8px',
          justifyContent: 'center'
        }}>
          <span style={{ 
            fontWeight: '700',
            color: params.value ? '#ff6b6b' : '#666',
            fontSize: '1.6rem'
          }}>
            {params.value ? '●' : '○'}
          </span>
          <span style={{ 
            fontSize: '1.2rem',
            fontWeight: '600',
            color: params.value ? '#ff6b6b' : '#666'
          }}>
            {params.value ? 'YES' : 'NO'}
          </span>
        </div>
      )
    },
    {
      field: 'threat.vedas_score',
      headerName: 'VEDAS Score',
      width: 160,
      type: 'numericColumn',
      cellRenderer: (params: any) => (
        <span style={{ fontWeight: '600', fontSize: '1.3rem' }}>
          {params.value ? params.value.toFixed(4) : 'N/A'}
        </span>
      )
    },
    {
      field: 'threat.vedas_percentile',
      headerName: 'VEDAS %ile',
      width: 160,
      type: 'numericColumn',
      cellRenderer: (params: any) => (
        <span style={{ fontWeight: '600', fontSize: '1.3rem' }}>
          {params.value ? (params.value * 100).toFixed(1) + '%' : 'N/A'}
        </span>
      )
    },
    {
      field: 'threat.temporal_score',
      headerName: 'Temporal CVSS',
      width: 160,
      type: 'numericColumn',
      cellRenderer: (params: any) => (
        <span style={{ fontWeight: '600', fontSize: '1.3rem' }}>
          {params.value ? params.value.toFixed(1) : 'N/A'}
        </span>
      )
    },
    {
      field: 'product_intelligence.vendors',
      headerName: 'Vendors',
      width: 180,
      cellRenderer: (params: any) => (
        <span style={{ fontSize: '1.2rem' }}>
          {params.value && params.value.length > 0 ? params.value.slice(0, 2).join(', ') + (params.value.length > 2 ? '...' : '') : 'N/A'}
        </span>
      )
    },
    {
      field: 'description',
      headerName: 'Description',
      flex: 1,
      minWidth: 500,
      wrapText: true,
      autoHeight: true,
      cellRenderer: (params: any) => (
        <div style={{ 
          fontSize: '1.3rem',
          lineHeight: '1.6',
          padding: '4px 0',
          wordWrap: 'break-word',
          whiteSpace: 'normal'
        }}>
          {params.value}
        </div>
      )
    }
  ];

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams({
        page: pagination.page.toString(),
        per_page: pagination.per_page.toString(),
        ...(filters.search && { search: filters.search }),
        ...(filters.severity && { severity: filters.severity }),
        ...(filters.kev && { kev: filters.kev }),
        ...(filters.exploits && { exploits: filters.exploits })
      });

      const response = await axios.get<ApiResponse>(`/api/cves?${params}`);
      
      setRowData(response.data.data);
      setPagination(response.data.pagination);
      setSummary(response.data.summary);
    } catch (error) {
      console.error('Failed to fetch data:', error);
    } finally {
      setLoading(false);
    }
  }, [pagination.page, pagination.per_page, filters]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  // Handle navigation after page change
  useEffect(() => {
    if (pendingNavigation && rowData.length > 0) {
      if (pendingNavigation === 'first') {
        setSelectedCve(rowData[0]);
        setSelectedCveIndex(0);
      } else if (pendingNavigation === 'last') {
        const lastIndex = rowData.length - 1;
        setSelectedCve(rowData[lastIndex]);
        setSelectedCveIndex(lastIndex);
      }
      setPendingNavigation(null);
    }
  }, [rowData, pendingNavigation]);

  const handleResearch = async () => {
    if (!researchInput.trim()) return;

    setLoading(true);
    try {
      const cveIds = researchInput
        .split(/[,\n]/)
        .map(id => id.trim())
        .filter(id => id.startsWith('CVE-'));

      await axios.post('/api/research', { cve_ids: cveIds });
      
      setResearchInput('');
      setPagination(prev => ({ ...prev, page: 1 }));
      fetchData();
    } catch (error) {
      console.error('Research failed:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleFilterChange = (key: string, value: string) => {
    setFilters(prev => ({ ...prev, [key]: value }));
    setPagination(prev => ({ ...prev, page: 1 }));
  };

  const navigateRecord = (direction: 'prev' | 'next') => {
    if (selectedCveIndex === -1) return;
    
    if (direction === 'prev') {
      if (selectedCveIndex > 0) {
        // Navigate within current page
        setSelectedCve(rowData[selectedCveIndex - 1]);
        setSelectedCveIndex(selectedCveIndex - 1);
      } else if (pagination.page > 1) {
        // Navigate to previous page and select last item
        setPendingNavigation('last');
        setPagination(prev => ({ ...prev, page: prev.page - 1 }));
      }
    } else {
      if (selectedCveIndex < rowData.length - 1) {
        // Navigate within current page
        setSelectedCve(rowData[selectedCveIndex + 1]);
        setSelectedCveIndex(selectedCveIndex + 1);
      } else if (pagination.page < pagination.total_pages) {
        // Navigate to next page and select first item
        setPendingNavigation('first');
        setPagination(prev => ({ ...prev, page: prev.page + 1 }));
      }
    }
  };

  const toggleSection = (section: string) => {
    setExpandedSections(prev => ({
      ...prev,
      [section]: !prev[section]
    }));
  };

  const closeModal = () => {
    setSelectedCve(null);
    setSelectedCveIndex(-1);
  };

  const clearData = async () => {
    try {
      await axios.delete('/api/data');
      fetchData();
    } catch (error) {
      console.error('Failed to clear data:', error);
    }
  };

  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    try {
      setLoading(true);
      const fileContent = await file.text();

      if (uploadType === 'json') {
        // Load JSON data file directly into the UI
        try {
          const jsonData = JSON.parse(fileContent);
          
          // Check if it's the right format (array of CVE data or research data)
          let dataToLoad = [];
          if (Array.isArray(jsonData)) {
            dataToLoad = jsonData;
          } else if (jsonData.data && Array.isArray(jsonData.data)) {
            dataToLoad = jsonData.data;
          } else {
            throw new Error('Invalid JSON format. Expected array of CVE data or API response format.');
          }

          // Use the backend API to load the data
          await axios.post('/api/load-data', dataToLoad);
          
          // Refresh the UI with the loaded data
          await fetchData();
        } catch (parseError) {
          alert('Error parsing JSON file: ' + (parseError as Error).message);
          setLoading(false);
          return;
        }
      } else {
        // Process CVE list file and research them
        const cveIds = fileContent
          .split(/[\n,\s]+/)
          .map(id => id.trim())
          .filter(id => id.match(/^CVE-\d{4}-\d+$/i))
          .map(id => id.toUpperCase());

        if (cveIds.length === 0) {
          alert('No valid CVE IDs found in the file. Expected format: CVE-YYYY-NNNN');
          setLoading(false);
          return;
        }

        // Research the CVEs
        const response = await axios.post('/api/research', { cve_ids: cveIds });
        console.log('Research response:', response.data);
        
        // Refresh data after research
        await fetchData();
      }
      
      // Clear the file input
      event.target.value = '';
      
    } catch (error) {
      console.error('File upload failed:', error);
      alert('File upload failed: ' + (error as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const exportData = () => {
    if (rowData.length === 0) {
      alert('No data to export. Research some CVEs first.');
      return;
    }

    const exportData = {
      timestamp: new Date().toISOString(),
      summary: summary,
      data: rowData
    };

    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `odin-research-data-${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="app">
      <header className="app-header">
        <h1>ODIN</h1>
        <div style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', fontWeight: '500', marginTop: '0.25rem' }}>
          OSINT Data Intelligence Nexus
        </div>
        <div className="header-stats">
          <span>Total: {summary.total_cves}</span>
          <span>Critical/High: {summary.critical_high}</span>
          <span>CISA KEV: {summary.in_kev}</span>
          <span>With Exploits: {summary.with_exploits}</span>
        </div>
      </header>

      <div className="controls">
        <div className="research-section">
          <textarea
            value={researchInput}
            onChange={(e) => setResearchInput(e.target.value)}
            placeholder="Enter CVE IDs (e.g., CVE-2023-44487, CVE-2021-44228)"
            rows={2}
          />
          <button onClick={handleResearch} disabled={loading}>
            {loading ? 'Researching...' : 'Research CVEs'}
          </button>
        </div>

        <div className="research-section" style={{ borderTop: '1px solid var(--border-color)', paddingTop: '1rem', marginTop: '1rem' }}>
          <div style={{ 
            display: 'flex', 
            alignItems: 'center', 
            gap: '1rem', 
            marginBottom: '1rem',
            flexWrap: 'wrap'
          }}>
            <div style={{ 
              display: 'flex', 
              alignItems: 'center', 
              gap: '0.5rem',
              background: 'var(--bg-tertiary)',
              padding: '0.5rem 1rem',
              borderRadius: '6px',
              border: '1px solid var(--border-color)'
            }}>
              <span style={{ color: 'var(--text-primary)', fontWeight: '600', fontSize: '1rem' }}>Upload:</span>
              <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }}>
                <input
                  type="radio"
                  name="uploadType"
                  value="cve-list"
                  checked={uploadType === 'cve-list'}
                  onChange={(e) => setUploadType(e.target.value as 'json' | 'cve-list')}
                  style={{ marginRight: '0.25rem' }}
                />
                <span style={{ color: 'var(--text-secondary)', fontSize: '1rem' }}>CVE List (.txt)</span>
              </label>
              <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }}>
                <input
                  type="radio"
                  name="uploadType"
                  value="json"
                  checked={uploadType === 'json'}
                  onChange={(e) => setUploadType(e.target.value as 'json' | 'cve-list')}
                  style={{ marginRight: '0.25rem' }}
                />
                <span style={{ color: 'var(--text-secondary)', fontSize: '1rem' }}>JSON Data (.json)</span>
              </label>
            </div>
            
            <div style={{ 
              display: 'flex', 
              alignItems: 'center', 
              gap: '1rem'
            }}>
              <input
                type="file"
                accept={uploadType === 'json' ? '.json' : '.txt,.csv'}
                onChange={handleFileUpload}
                disabled={loading}
                style={{ display: 'none' }}
                id="file-upload"
              />
              <label 
                htmlFor="file-upload"
                style={{
                  padding: '0.75rem 1.5rem',
                  background: loading ? 'var(--text-muted)' : 'var(--brand-secondary)',
                  color: 'white',
                  border: 'none',
                  borderRadius: '6px',
                  cursor: loading ? 'not-allowed' : 'pointer',
                  fontSize: '1.3rem',
                  fontWeight: '600',
                  transition: 'background-color 0.2s ease'
                }}
              >
                {loading ? 'Processing...' : `Upload ${uploadType === 'json' ? 'JSON File' : 'CVE List'}`}
              </label>
              
              <div style={{ 
                color: 'var(--text-muted)', 
                fontSize: '1.2rem',
                maxWidth: '300px',
                lineHeight: '1.4'
              }}>
                {uploadType === 'json' 
                  ? 'Load pre-generated ODIN research data'
                  : 'Upload text file with CVE IDs (one per line or comma-separated)'
                }
              </div>
            </div>
          </div>
        </div>

        <div className="filters">
          <input
            type="text"
            placeholder="Search CVE ID or description..."
            value={filters.search}
            onChange={(e) => handleFilterChange('search', e.target.value)}
          />
          
          <select
            value={filters.severity}
            onChange={(e) => handleFilterChange('severity', e.target.value)}
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>

          <select
            value={filters.kev}
            onChange={(e) => handleFilterChange('kev', e.target.value)}
          >
            <option value="">All KEV Status</option>
            <option value="true">In CISA KEV</option>
            <option value="false">Not in KEV</option>
          </select>

          <select
            value={filters.exploits}
            onChange={(e) => handleFilterChange('exploits', e.target.value)}
          >
            <option value="">All Exploit Status</option>
            <option value="true">Has Exploits</option>
            <option value="false">No Exploits</option>
          </select>

          <button 
            onClick={exportData}
            style={{
              padding: '0.75rem 1rem',
              background: 'var(--brand-accent)',
              color: 'var(--bg-primary)',
              border: 'none',
              borderRadius: '6px',
              fontWeight: '600',
              cursor: 'pointer',
              fontSize: '1.3rem',
              transition: 'background-color 0.2s ease'
            }}
            onMouseOver={(e) => e.currentTarget.style.background = 'var(--brand-accent-hover)'}
            onMouseOut={(e) => e.currentTarget.style.background = 'var(--brand-accent)'}
          >
            Export JSON
          </button>

          <button onClick={clearData} className="clear-btn">
            Clear All Data
          </button>
        </div>
      </div>

      <div className="main-content">
        <div className="data-grid">
          <div className="ag-theme-alpine" style={{ height: 'calc(100vh - 280px)', width: '100%' }}>
            <AgGridReact
              rowData={rowData}
              columnDefs={columnDefs}
              suppressRowHoverHighlight={false}
              suppressColumnVirtualisation={false}
              enableCellTextSelection={true}
              domLayout="normal"
              headerHeight={60}
              rowHeight={75}
              defaultColDef={{
                sortable: true,
                filter: false,
                resizable: true,
                suppressSizeToFit: false
              }}
              pagination={false}
              onGridReady={(params) => {
                params.api.sizeColumnsToFit();
              }}
              onGridSizeChanged={(params) => {
                params.api.sizeColumnsToFit();
              }}
            />
          </div>

          <div className="pagination">
            <button
              onClick={() => setPagination(prev => ({ ...prev, page: prev.page - 1 }))}
              disabled={pagination.page <= 1}
            >
              Previous
            </button>
            
            <span>
              Page {pagination.page} of {pagination.total_pages} 
              ({pagination.total_items} items)
            </span>
            
            <button
              onClick={() => setPagination(prev => ({ ...prev, page: prev.page + 1 }))}
              disabled={pagination.page >= pagination.total_pages}
            >
              Next
            </button>

            <select
              value={pagination.per_page}
              onChange={(e) => setPagination(prev => ({ 
                ...prev, 
                per_page: parseInt(e.target.value),
                page: 1 
              }))}
            >
              <option value={10}>10 per page</option>
              <option value={25}>25 per page</option>
              <option value={50}>50 per page</option>
              <option value={100}>100 per page</option>
            </select>
          </div>
        </div>
      </div>

      {/* Modal Dialog */}
      {selectedCve && (
        <div className="modal-overlay" onClick={closeModal}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <div className="modal-title">
                <h2>{selectedCve.cve_id}</h2>
                <span className="modal-index">
                  {(pagination.page - 1) * pagination.per_page + selectedCveIndex + 1} of {pagination.total_items}
                </span>
              </div>
              
              <div className="modal-controls">
                <button
                  onClick={() => navigateRecord('prev')}
                  disabled={selectedCveIndex <= 0 && pagination.page <= 1}
                  className="nav-button"
                >
                  ← Previous
                </button>
                
                <button
                  onClick={() => navigateRecord('next')}
                  disabled={selectedCveIndex >= rowData.length - 1 && pagination.page >= pagination.total_pages}
                  className="nav-button"
                >
                  Next →
                </button>
                
                <button onClick={closeModal} className="close-button">
                  ×
                </button>
              </div>
            </div>
            
            <div className="modal-body">
              {/* Top Summary Section */}
              <div className="modal-summary">
                <div className="summary-main">
                  <div className="summary-title">
                    <h3>{selectedCve.cve_id}</h3>
                    <span className={`severity-badge ${selectedCve.severity?.toLowerCase()}`}>
                      {selectedCve.severity}
                    </span>
                  </div>
                  <div className="summary-description">
                    {selectedCve.description}
                  </div>
                </div>
                
                <div className="summary-metrics">
                  <div className="metric-card">
                    <div className="metric-label">CVSS Score</div>
                    <div className="metric-value">{selectedCve.cvss_score || 'N/A'}</div>
                  </div>
                  <div className="metric-card">
                    <div className="metric-label">EPSS Score</div>
                    <div className="metric-value">{selectedCve.threat.epss_score?.toFixed(3) || 'N/A'}</div>
                  </div>
                  <div className="metric-card">
                    <div className="metric-label">VEDAS Score</div>
                    <div className="metric-value">{selectedCve.threat.vedas_score?.toFixed(3) || 'N/A'}</div>
                  </div>
                  <div className="metric-card">
                    <div className="metric-label">CISA KEV</div>
                    <div className={`metric-value ${selectedCve.threat.in_kev ? 'kev-yes' : ''}`}>
                      {selectedCve.threat.in_kev ? 'Yes' : 'No'}
                    </div>
                  </div>
                  <div className="metric-card">
                    <div className="metric-label">Published</div>
                    <div className="metric-value" style={{fontSize: '0.9rem'}}>
                      {selectedCve.published_date ? new Date(selectedCve.published_date).toLocaleDateString() : 'N/A'}
                    </div>
                  </div>
                </div>
              </div>

              <div className="modal-content-sections">
                {/* Basic Information */}
                <div className="collapsible-section">
                  <button 
                    className="section-header"
                    onClick={() => toggleSection('overview')}
                  >
                    <span>Additional Details</span>
                    <span className={`expand-caret ${expandedSections.overview ? 'expanded' : ''}`}>
                      ▶
                    </span>
                  </button>
                  {expandedSections.overview && (
                    <div className="section-content">
                      <div className="field-row">
                        <strong>CVSS Vector</strong>
                        <span>{selectedCve.cvss_vector || 'N/A'}</span>
                      </div>
                      <div className="field-row">
                        <strong>Last Modified</strong>
                        <span>{selectedCve.last_modified ? new Date(selectedCve.last_modified).toLocaleDateString() : 'N/A'}</span>
                      </div>
                      <div className="field-row">
                        <strong>Active Exploitation</strong>
                        <span>{selectedCve.threat.actively_exploited ? 'Yes' : 'No'}</span>
                      </div>
                      <div className="field-row">
                        <strong>EPSS Percentile</strong>
                        <span>{selectedCve.threat.epss_percentile ? `${(selectedCve.threat.epss_percentile * 100).toFixed(1)}%` : 'N/A'}</span>
                      </div>
                      <div className="field-row">
                        <strong>VEDAS Percentile</strong>
                        <span>{selectedCve.threat.vedas_percentile ? `${(selectedCve.threat.vedas_percentile * 100).toFixed(1)}%` : 'N/A'}</span>
                      </div>
                      <div className="field-row">
                        <strong>VEDAS Score Change</strong>
                        <span style={{ 
                          color: selectedCve.threat.vedas_score_change && selectedCve.threat.vedas_score_change > 0 ? '#ef4444' : 
                                 selectedCve.threat.vedas_score_change && selectedCve.threat.vedas_score_change < 0 ? '#10b981' : 'inherit'
                        }}>
                          {selectedCve.threat.vedas_score_change ? 
                            (selectedCve.threat.vedas_score_change > 0 ? '+' : '') + selectedCve.threat.vedas_score_change.toFixed(4) : 'N/A'}
                        </span>
                      </div>
                      {selectedCve.threat.vedas_detail_url && (
                        <div className="field-row">
                          <strong>VEDAS Details</strong>
                          <a href={selectedCve.threat.vedas_detail_url} target="_blank" rel="noopener noreferrer" 
                             style={{ color: 'var(--accent-blue)', textDecoration: 'underline' }}>
                            View Detailed Analysis
                          </a>
                        </div>
                      )}
                      {selectedCve.threat.temporal_score && (
                        <div className="field-row">
                          <strong>Temporal CVSS Score</strong>
                          <span style={{ fontWeight: '600' }}>
                            {selectedCve.threat.temporal_score.toFixed(1)}
                          </span>
                        </div>
                      )}
                      {selectedCve.threat.exploit_code_maturity && (
                        <div className="field-row">
                          <strong>Exploit Code Maturity</strong>
                          <span style={{ 
                            textTransform: 'capitalize',
                            fontWeight: '600',
                            color: selectedCve.threat.exploit_code_maturity.toLowerCase() === 'high' ? '#ef4444' : 
                                   selectedCve.threat.exploit_code_maturity.toLowerCase() === 'functional' ? '#f59e0b' :
                                   selectedCve.threat.exploit_code_maturity.toLowerCase() === 'proof-of-concept' ? '#10b981' : 'inherit'
                          }}>
                            {selectedCve.threat.exploit_code_maturity}
                          </span>
                        </div>
                      )}
                      {selectedCve.threat.remediation_level && (
                        <div className="field-row">
                          <strong>Remediation Level</strong>
                          <span>{selectedCve.threat.remediation_level}</span>
                        </div>
                      )}
                      {selectedCve.threat.report_confidence && (
                        <div className="field-row">
                          <strong>Report Confidence</strong>
                          <span>{selectedCve.threat.report_confidence}</span>
                        </div>
                      )}
                      <div className="field-row">
                        <strong>Exploit Maturity</strong>
                        <span style={{ 
                          textTransform: 'capitalize',
                          fontWeight: '600',
                          color: selectedCve.exploit_maturity === 'weaponized' ? '#ef4444' : 
                                 selectedCve.exploit_maturity === 'functional' ? '#f59e0b' :
                                 selectedCve.exploit_maturity === 'poc' ? '#10b981' : 'inherit'
                        }}>
                          {selectedCve.exploit_maturity || 'Unproven'}
                        </span>
                      </div>
                      <div className="field-row">
                        <strong>Has Metasploit Module</strong>
                        <span style={{ 
                          color: selectedCve.threat.has_metasploit ? '#ef4444' : 'inherit',
                          fontWeight: selectedCve.threat.has_metasploit ? '600' : 'normal'
                        }}>
                          {selectedCve.threat.has_metasploit ? 'Yes' : 'No'}
                        </span>
                      </div>
                      <div className="field-row">
                        <strong>Has Nuclei Template</strong>
                        <span style={{ 
                          color: selectedCve.threat.has_nuclei ? '#f59e0b' : 'inherit',
                          fontWeight: selectedCve.threat.has_nuclei ? '600' : 'normal'
                        }}>
                          {selectedCve.threat.has_nuclei ? 'Yes' : 'No'}
                        </span>
                      </div>
                      <div className="field-row">
                        <strong>CPE Affected</strong>
                        <span>{selectedCve.cpe_affected || 'N/A'}</span>
                      </div>
                      <div className="field-row">
                        <strong>Last Enriched</strong>
                        <span>{selectedCve.last_enriched ? new Date(selectedCve.last_enriched).toLocaleString() : 'N/A'}</span>
                      </div>
                      {selectedCve.threat.in_kev && (
                        <>
                          <div className="field-row">
                            <strong>KEV Vulnerability Name</strong>
                            <span>{selectedCve.threat.kev_vulnerability_name || 'N/A'}</span>
                          </div>
                          <div className="field-row">
                            <strong>KEV Description</strong>
                            <span>{selectedCve.threat.kev_short_description || 'N/A'}</span>
                          </div>
                          <div className="field-row">
                            <strong>KEV Vendor/Project</strong>
                            <span>{selectedCve.threat.kev_vendor_project || 'N/A'}</span>
                          </div>
                          <div className="field-row">
                            <strong>KEV Product</strong>
                            <span>{selectedCve.threat.kev_product || 'N/A'}</span>
                          </div>
                        </>
                      )}
                      <div className="field-row">
                        <strong>Ransomware Campaign</strong>
                        <span style={{ 
                          color: selectedCve.threat.ransomware_campaign ? '#ff6b6b' : 'inherit',
                          fontWeight: selectedCve.threat.ransomware_campaign ? '600' : 'normal'
                        }}>
                          {selectedCve.threat.ransomware_campaign ? 'Yes' : 'No'}
                        </span>
                      </div>
                    </div>
                  )}
                </div>

                {/* Exploits Section */}
                <div className="collapsible-section">
                  <button 
                    className="section-header"
                    onClick={() => toggleSection('exploits')}
                  >
                    <span>Exploits ({selectedCve.exploits?.length || 0})</span>
                    <span className={`expand-caret ${expandedSections.exploits ? 'expanded' : ''}`}>
                      ▶
                    </span>
                  </button>
                  {expandedSections.exploits && (
                    <div className="section-content">
                      {selectedCve.exploits?.length > 0 ? (
                        <>
                          <div style={{ marginBottom: '1rem', padding: '1rem', background: 'var(--bg-tertiary)', borderRadius: '6px', border: '1px solid var(--border-color)' }}>
                            <strong style={{ color: 'var(--brand-secondary)', fontSize: '1.1rem' }}>Total Exploits: {selectedCve.exploits.length}</strong>
                          </div>
                          <div style={{ maxHeight: '500px', overflowY: 'auto', border: '1px solid var(--border-color)', borderRadius: '6px' }}>
                            <table className="exploits-table" style={{ margin: 0 }}>
                              <thead style={{ position: 'sticky', top: 0, zIndex: 1 }}>
                                <tr>
                                  <th>Type</th>
                                  <th>Source</th>
                                  <th>URL</th>
                                </tr>
                              </thead>
                              <tbody>
                                {selectedCve.exploits.map((exploit, idx) => (
                                  <tr key={idx}>
                                    <td>
                                      <span className="exploit-type">{exploit.type}</span>
                                    </td>
                                    <td style={{ fontSize: '1rem' }}>{exploit.source}</td>
                                    <td className="exploit-url-cell">
                                      <a href={exploit.url} target="_blank" rel="noopener noreferrer" title={exploit.url} style={{ fontSize: '1rem' }}>
                                        {exploit.url}
                                      </a>
                                    </td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        </>
                      ) : (
                        <p style={{ fontSize: '1.1rem', color: 'var(--text-secondary)', textAlign: 'center', padding: '2rem' }}>No known exploits for this CVE</p>
                      )}
                    </div>
                  )}
                </div>

                {/* Patches Section */}
                <div className="collapsible-section">
                  <button 
                    className="section-header"
                    onClick={() => toggleSection('patches')}
                  >
                    <span>Patches & Remediation ({selectedCve.patches?.length || 0})</span>
                    <span className={`expand-caret ${expandedSections.patches ? 'expanded' : ''}`}>
                      ▶
                    </span>
                  </button>
                  {expandedSections.patches && (
                    <div className="section-content">
                      {selectedCve.patches?.length > 0 ? (
                        <div className="patches-grid">
                          {selectedCve.patches.map((patch, idx) => (
                            <div key={idx} className="patch-item">
                              {patch}
                            </div>
                          ))}
                        </div>
                      ) : (
                        <p>No patches available</p>
                      )}
                    </div>
                  )}
                </div>

                {/* Enhanced Problem Type Section */}
                <div className="collapsible-section">
                  <button 
                    className="section-header"
                    onClick={() => toggleSection('enhanced_problem_type')}
                  >
                    <span>Enhanced Problem Type Analysis</span>
                    <span className={`expand-caret ${expandedSections.enhanced_problem_type ? 'expanded' : ''}`}>
                      ▶
                    </span>
                  </button>
                  {expandedSections.enhanced_problem_type && (
                    <div className="section-content">
                      <div className="field-row">
                        <strong>Primary Weakness</strong>
                        <span>{selectedCve.enhanced_problem_type?.primary_weakness || 'N/A'}</span>
                      </div>
                      <div className="field-row">
                        <strong>Secondary Weaknesses</strong>
                        <span>{selectedCve.enhanced_problem_type?.secondary_weaknesses || 'N/A'}</span>
                      </div>
                      <div className="field-row">
                        <strong>Vulnerability Categories</strong>
                        <span>{selectedCve.enhanced_problem_type?.vulnerability_categories || 'N/A'}</span>
                      </div>
                      <div className="field-row">
                        <strong>Impact Types</strong>
                        <span>{selectedCve.enhanced_problem_type?.impact_types || 'N/A'}</span>
                      </div>
                      <div className="field-row">
                        <strong>Attack Vectors</strong>
                        <span>{selectedCve.enhanced_problem_type?.attack_vectors || 'N/A'}</span>
                      </div>
                      <div className="field-row">
                        <strong>Enhanced CWE Details</strong>
                        <span>{selectedCve.enhanced_problem_type?.enhanced_cwe_details || 'N/A'}</span>
                      </div>
                    </div>
                  )}
                </div>

                {/* MITRE Framework Section */}
                <div className="collapsible-section">
                  <button 
                    className="section-header"
                    onClick={() => toggleSection('mitre')}
                  >
                    <span>MITRE Framework</span>
                    <span className={`expand-caret ${expandedSections.mitre ? 'expanded' : ''}`}>
                      ▶
                    </span>
                  </button>
                  {expandedSections.mitre && (
                    <div className="section-content">
                      <div className="field-row">
                        <strong>CWE IDs</strong>
                        <span>{selectedCve.weakness?.cwe_ids?.join(', ') || 'None'}</span>
                      </div>
                      <div className="field-row">
                        <strong>CAPEC IDs</strong>
                        <span>{selectedCve.weakness?.capec_ids?.join(', ') || 'None'}</span>
                      </div>
                      <div className="field-row">
                        <strong>ATT&CK Techniques</strong>
                        <span>{selectedCve.weakness?.attack_techniques?.join(', ') || 'None'}</span>
                      </div>
                      <div className="field-row">
                        <strong>ATT&CK Tactics</strong>
                        <span>{selectedCve.weakness?.attack_tactics?.join(', ') || 'None'}</span>
                      </div>
                      <div className="field-row">
                        <strong>Kill Chain Phases</strong>
                        <span>{selectedCve.weakness?.kill_chain_phases?.join(', ') || 'None'}</span>
                      </div>
                    </div>
                  )}
                </div>

                {/* NIST Control Mapping Section */}
                <div className="collapsible-section">
                  <button 
                    className="section-header"
                    onClick={() => toggleSection('controls')}
                  >
                    <span>NIST 800-53 Control Mapping ({selectedCve.control_mappings?.applicable_controls_count || '0'} controls)</span>
                    <span className={`expand-caret ${expandedSections.controls ? 'expanded' : ''}`}>
                      ▶
                    </span>
                  </button>
                  {expandedSections.controls && (
                    <div className="section-content">
                      <div className="field-row">
                        <strong>Applicable Controls Count</strong>
                        <span>{selectedCve.control_mappings?.applicable_controls_count || '0'}</span>
                      </div>
                      <div className="field-row">
                        <strong>Control Categories</strong>
                        <span>{selectedCve.control_mappings?.control_categories || 'N/A'}</span>
                      </div>
                      <div className="field-row">
                        <strong>Top Recommended Controls</strong>
                        <span>{selectedCve.control_mappings?.top_controls || 'N/A'}</span>
                      </div>
                    </div>
                  )}
                </div>

                {/* Product Intelligence Section */}
                <div className="collapsible-section">
                  <button 
                    className="section-header"
                    onClick={() => toggleSection('product_intelligence')}
                  >
                    <span>Product Intelligence</span>
                    <span className={`expand-caret ${expandedSections.product_intelligence ? 'expanded' : ''}`}>
                      ▶
                    </span>
                  </button>
                  {expandedSections.product_intelligence && (
                    <div className="section-content">
                      {selectedCve.product_intelligence?.vendors?.length > 0 && (
                        <div className="field-row">
                          <strong>Affected Vendors</strong>
                          <div className="tag-list">
                            {selectedCve.product_intelligence.vendors.map((vendor, index) => (
                              <span key={index} className="tag vendor-tag">{vendor}</span>
                            ))}
                          </div>
                        </div>
                      )}
                      {selectedCve.product_intelligence?.products?.length > 0 && (
                        <div className="field-row">
                          <strong>Affected Products</strong>
                          <div className="tag-list">
                            {selectedCve.product_intelligence.products.map((product, index) => (
                              <span key={index} className="tag product-tag">{product}</span>
                            ))}
                          </div>
                        </div>
                      )}
                      {selectedCve.product_intelligence?.affected_versions?.length > 0 && (
                        <div className="field-row">
                          <strong>Affected Versions</strong>
                          <div className="tag-list">
                            {selectedCve.product_intelligence.affected_versions.map((version, index) => (
                              <span key={index} className="tag version-tag">{version}</span>
                            ))}
                          </div>
                        </div>
                      )}
                      {selectedCve.product_intelligence?.platforms?.length > 0 && (
                        <div className="field-row">
                          <strong>Platforms</strong>
                          <div className="tag-list">
                            {selectedCve.product_intelligence.platforms.map((platform, index) => (
                              <span key={index} className="tag platform-tag">{platform}</span>
                            ))}
                          </div>
                        </div>
                      )}
                      {selectedCve.product_intelligence?.modules?.length > 0 && (
                        <div className="field-row">
                          <strong>Modules</strong>
                          <div className="tag-list">
                            {selectedCve.product_intelligence.modules.map((module, index) => (
                              <span key={index} className="tag module-tag">{module}</span>
                            ))}
                          </div>
                        </div>
                      )}
                      {selectedCve.product_intelligence?.repositories?.length > 0 && (
                        <div className="field-row">
                          <strong>Repositories</strong>
                          <div className="tag-list">
                            {selectedCve.product_intelligence.repositories.map((repo, index) => (
                              <a key={index} href={repo} target="_blank" rel="noopener noreferrer" 
                                 className="tag repo-tag" style={{ textDecoration: 'none' }}>
                                {repo}
                              </a>
                            ))}
                          </div>
                        </div>
                      )}
                      {(!selectedCve.product_intelligence?.vendors?.length && 
                        !selectedCve.product_intelligence?.products?.length &&
                        !selectedCve.product_intelligence?.affected_versions?.length &&
                        !selectedCve.product_intelligence?.platforms?.length &&
                        !selectedCve.product_intelligence?.modules?.length &&
                        !selectedCve.product_intelligence?.repositories?.length) && (
                        <p style={{ color: 'var(--text-secondary)', textAlign: 'center', padding: '1rem' }}>
                          No detailed product intelligence available
                        </p>
                      )}
                    </div>
                  )}
                </div>

                {/* References & Advisories Section */}
                <div className="collapsible-section">
                  <button 
                    className="section-header"
                    onClick={() => toggleSection('references')}
                  >
                    <span>References & Advisories</span>
                    <span className={`expand-caret ${expandedSections.references ? 'expanded' : ''}`}>
                      ▶
                    </span>
                  </button>
                  {expandedSections.references && (
                    <div className="section-content">
                      {selectedCve.vendor_advisories && selectedCve.vendor_advisories.length > 0 && (
                        <div className="field-row">
                          <strong>Vendor Advisories</strong>
                          <div>
                            {selectedCve.vendor_advisories.map((advisory, index) => (
                              <div key={index} style={{ marginBottom: '0.5rem' }}>
                                <a 
                                  href={advisory} 
                                  target="_blank" 
                                  rel="noopener noreferrer"
                                  style={{ color: 'var(--brand-secondary)', textDecoration: 'none' }}
                                >
                                  {advisory}
                                </a>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                      {selectedCve.references && selectedCve.references.length > 0 && (
                        <div className="field-row">
                          <strong>Additional References</strong>
                          <div>
                            <div style={{ maxHeight: '300px', overflowY: 'auto', border: '1px solid var(--border-color)', borderRadius: '6px', padding: '1rem' }}>
                              {selectedCve.references.map((ref, index) => (
                                <div key={index} style={{ marginBottom: '0.75rem', paddingBottom: '0.75rem', borderBottom: index < (selectedCve.references?.length || 0) - 1 ? '1px solid var(--border-color)' : 'none' }}>
                                  <a 
                                    href={ref} 
                                    target="_blank" 
                                    rel="noopener noreferrer"
                                    style={{ 
                                      color: 'var(--brand-secondary)', 
                                      textDecoration: 'none',
                                      fontSize: '1.3rem',
                                      lineHeight: '1.5',
                                      wordBreak: 'break-all'
                                    }}
                                  >
                                    {ref}
                                  </a>
                                </div>
                              ))}
                              <div style={{ 
                                color: 'var(--text-muted)', 
                                fontSize: '1.2rem', 
                                fontStyle: 'italic',
                                marginTop: '1rem',
                                textAlign: 'center',
                                padding: '0.5rem'
                              }}>
                                Total: {selectedCve.references?.length || 0} references
                              </div>
                            </div>
                          </div>
                        </div>
                      )}
                      {(!selectedCve.vendor_advisories || selectedCve.vendor_advisories.length === 0) && 
                       (!selectedCve.references || selectedCve.references.length === 0) && (
                        <div className="field-row">
                          <strong>Status</strong>
                          <span>No additional references available</span>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default App;