import { useState, useEffect, useCallback, useMemo } from 'react';

export interface CVEData {
  cve_id: string;
  description: string;
  cvss_score: number | null;
  cvss_vector?: string;
  severity: string;
  cvss_version: string;
  cvss_bt_score: number;
  cvss_bt_severity: string;
  published_date: string | null;
  last_modified?: string;
  threat: {
    in_kev: boolean;
    vulncheck_kev: boolean;
    epss_score: number | null;
    actively_exploited: boolean;
    has_metasploit: boolean;
    has_nuclei: boolean;
    has_exploitdb: boolean;
    has_poc_github: boolean;
    ransomware_campaign: boolean;
    kev_vulnerability_name: string;
    kev_short_description: string;
    kev_vendor_project: string;
    kev_product: string;
    kev_required_action: string;
    kev_known_ransomware: string;
    kev_notes: string;
  };
  exploits: Array<{ 
    url: string; 
    source: string; 
    type: string;
    verified: boolean;
    title: string;
    date_found?: string;
  }>;
  patches: string[];
  weakness: {
    cwe_ids: string[];
    capec_ids: string[];
    attack_techniques: string[];
    attack_tactics: string[];
    kill_chain_phases: string[];
    cwe_details: string[];
    capec_details: string[];
    technique_details: string[];
    tactic_details: string[];
    enhanced_technique_descriptions: string[];
    enhanced_tactic_descriptions: string[];
    enhanced_capec_descriptions: string[];
    alternative_cwe_mappings: string[];
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
  };
  alternative_cvss_scores: Array<{
    score: number;
    vector: string;
    version: string;
    source: string;
  }>;
  reference_tags: string[];
  mitigations: string[];
  fix_versions: string[];
  exploit_maturity?: string;
  cpe_affected?: string;
  vendor_advisories?: string[];
  references?: string[];
  last_enriched?: string;
}

export interface Filters {
  search: string;
  severity: string;
  kev: string;
  exploits: string;
}

export interface Pagination {
  page: number;
  per_page: number;
  total_items: number;
  total_pages: number;
}

export const useCVEDataSimple = () => {
  const [allData, setAllData] = useState<CVEData[]>([]);
  const [loading, setLoading] = useState(false);
  const [pagination, setPagination] = useState<Pagination>({
    page: 1,
    per_page: 25,
    total_items: 0,
    total_pages: 0
  });
  const [filters, setFilters] = useState<Filters>({
    search: '',
    severity: '',
    kev: '',
    exploits: ''
  });

  // Filter data based on current filters
  const filteredData = useMemo(() => {
    let result = [...allData];

    // Search filter
    if (filters.search) {
      const searchLower = filters.search.toLowerCase();
      result = result.filter(cve => 
        cve.cve_id.toLowerCase().includes(searchLower) ||
        cve.description.toLowerCase().includes(searchLower)
      );
    }

    // Severity filter
    if (filters.severity) {
      result = result.filter(cve => cve.severity === filters.severity);
    }

    // KEV filter
    if (filters.kev === 'yes') {
      result = result.filter(cve => cve.threat.in_kev);
    } else if (filters.kev === 'no') {
      result = result.filter(cve => !cve.threat.in_kev);
    }

    // Exploits filter
    if (filters.exploits === 'yes') {
      result = result.filter(cve => cve.exploits.length > 0);
    } else if (filters.exploits === 'no') {
      result = result.filter(cve => cve.exploits.length === 0);
    }

    return result;
  }, [allData, filters]);

  // Calculate summary
  const summary = useMemo(() => ({
    total_cves: allData.length,
    filtered_cves: filteredData.length,
    critical_high: filteredData.filter(cve => 
      cve.severity === 'CRITICAL' || cve.severity === 'HIGH'
    ).length,
    in_kev: filteredData.filter(cve => cve.threat.in_kev).length,
    with_exploits: filteredData.filter(cve => cve.exploits.length > 0).length
  }), [allData, filteredData]);

  // Paginate filtered data
  const rowData = useMemo(() => {
    const start = (pagination.page - 1) * pagination.per_page;
    const end = start + pagination.per_page;
    return filteredData.slice(start, end);
  }, [filteredData, pagination.page, pagination.per_page]);

  // Update pagination when filtered data changes
  useEffect(() => {
    const totalPages = Math.ceil(filteredData.length / pagination.per_page);
    setPagination(prev => ({
      ...prev,
      total_items: filteredData.length,
      total_pages: totalPages,
      page: Math.min(prev.page, Math.max(1, totalPages))
    }));
  }, [filteredData.length, pagination.per_page]);

  const researchCVEs = useCallback(async (cveIds: string[]) => {
    setLoading(true);
    try {
      const response = await fetch('/api/research', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ cve_ids: cveIds })
      });

      if (!response.ok) {
        throw new Error(`Research failed: ${response.statusText}`);
      }

      const result = await response.json();
      
      // Extract CVE data from the ODIN JSON format
      if (result.data) {
        setAllData(result.data);
      }
      
      setPagination(prev => ({ ...prev, page: 1 }));
    } catch (error) {
      console.error('Research failed:', error);
      throw error;
    } finally {
      setLoading(false);
    }
  }, []);

  const clearData = useCallback(() => {
    setAllData([]);
    setPagination(prev => ({ ...prev, page: 1 }));
  }, []);

  const loadData = useCallback(async (data: any) => {
    try {
      setLoading(true);
      
      // Handle different data formats
      if (Array.isArray(data)) {
        // Direct array of CVE data
        setAllData(data);
      } else if (data.data && Array.isArray(data.data)) {
        // ODIN JSON export format
        setAllData(data.data);
      } else if (data.cves && Array.isArray(data.cves)) {
        // Legacy export format
        setAllData(data.cves);
      } else {
        throw new Error('Unrecognized data format');
      }
      
      setPagination(prev => ({ ...prev, page: 1 }));
    } catch (error) {
      console.error('Failed to load data:', error);
      throw error;
    } finally {
      setLoading(false);
    }
  }, []);

  const loadFromFile = useCallback(async (filePath: string) => {
    setLoading(true);
    try {
      const response = await fetch('/api/load', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ file_path: filePath })
      });

      if (!response.ok) {
        throw new Error(`Failed to load file: ${response.statusText}`);
      }

      const data = await response.json();
      await loadData(data);
    } catch (error) {
      console.error('Failed to load file:', error);
      throw error;
    } finally {
      setLoading(false);
    }
  }, [loadData]);

  const handleFilterChange = useCallback((key: keyof Filters, value: string) => {
    setFilters(prev => ({ ...prev, [key]: value }));
    setPagination(prev => ({ ...prev, page: 1 }));
  }, []);

  const handlePaginationChange = useCallback((changes: Partial<Pagination>) => {
    setPagination(prev => ({ ...prev, ...changes }));
  }, []);

  const exportData = useCallback(() => {
    if (allData.length === 0) {
      alert('No data to export. Research some CVEs first.');
      return;
    }

    const exportData = {
      timestamp: new Date().toISOString(),
      summary: {
        total_cves: allData.length,
        critical_high: allData.filter(cve => 
          cve.severity === 'CRITICAL' || cve.severity === 'HIGH'
        ).length,
        in_kev: allData.filter(cve => cve.threat.in_kev).length,
        with_exploits: allData.filter(cve => cve.exploits.length > 0).length
      },
      cves: allData
    };

    const blob = new Blob([JSON.stringify(exportData, null, 2)], { 
      type: 'application/json' 
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `odin-export-${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, [allData]);

  return {
    // Data
    rowData,
    loading,
    pagination,
    summary,
    filters,
    
    // Actions
    researchCVEs,
    clearData,
    loadData,
    loadFromFile,
    exportData,
    handleFilterChange,
    handlePaginationChange,
    refetch: () => {} // No-op for compatibility
  };
};