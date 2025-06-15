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
    epss_score: number | null;
    actively_exploited: boolean;
  };
  exploits: Array<{ url: string; source: string; type: string }>;
  patches: string[];
  weakness: {
    cwe_ids: string[];
    attack_techniques: string[];
  };
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
  const [expandedSections, setExpandedSections] = useState<Record<string, boolean>>({
    overview: true,
    threat: true,
    exploits: false,
    patches: false,
    mitre: false,
    technical: false
  });

  const columnDefs: ColDef[] = [
    {
      field: 'cve_id',
      headerName: 'CVE ID',
      width: 150,
      pinned: 'left',
      cellRenderer: (params: any) => (
        <button 
          className="cve-link"
          onClick={() => {
            const index = rowData.findIndex(item => item.cve_id === params.data.cve_id);
            setSelectedCve(params.data);
            setSelectedCveIndex(index);
          }}
        >
          {params.value}
        </button>
      )
    },
    {
      field: 'severity',
      headerName: 'Severity',
      width: 120,
      cellRenderer: (params: any) => (
        <span className={`severity-badge ${params.value?.toLowerCase()}`}>
          {params.value}
        </span>
      )
    },
    {
      field: 'cvss_score',
      headerName: 'CVSS',
      width: 90,
      type: 'numericColumn'
    },
    {
      field: 'threat.in_kev',
      headerName: 'CISA KEV',
      width: 110,
      cellRenderer: (params: any) => params.value ? 'Yes' : 'No'
    },
    {
      field: 'exploits',
      headerName: 'Exploits',
      width: 100,
      valueGetter: (params: any) => params.data.exploits?.length || 0
    },
    {
      field: 'patches',
      headerName: 'Patches',
      width: 100,
      valueGetter: (params: any) => params.data.patches?.length || 0
    },
    {
      field: 'threat.epss_score',
      headerName: 'EPSS',
      width: 100,
      type: 'numericColumn',
      valueFormatter: (params: any) => 
        params.value ? params.value.toFixed(3) : 'N/A'
    },
    {
      field: 'description',
      headerName: 'Description',
      flex: 1,
      minWidth: 300,
      cellRenderer: (params: any) => (
        <div className="description-cell" title={params.value}>
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

  return (
    <div className="app">
      <header className="app-header">
        <h1>CVE Research Toolkit</h1>
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

          <button onClick={clearData} className="clear-btn">
            Clear All Data
          </button>
        </div>
      </div>

      <div className="main-content">
        <div className="data-grid">
          <div className="ag-theme-alpine" style={{ height: '600px', width: '100%' }}>
            <AgGridReact
              rowData={rowData}
              columnDefs={columnDefs}
              suppressRowHoverHighlight={false}
              suppressColumnVirtualisation={false}
              enableCellTextSelection={true}
              defaultColDef={{
                sortable: true,
                filter: false,
                resizable: true
              }}
              pagination={false}
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
                        <table className="exploits-table">
                          <thead>
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
                                <td>{exploit.source}</td>
                                <td className="exploit-url-cell">
                                  <a href={exploit.url} target="_blank" rel="noopener noreferrer" title={exploit.url}>
                                    {exploit.url}
                                  </a>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      ) : (
                        <p>No known exploits</p>
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
                        <strong>ATT&CK Techniques</strong>
                        <span>{selectedCve.weakness?.attack_techniques?.join(', ') || 'None'}</span>
                      </div>
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