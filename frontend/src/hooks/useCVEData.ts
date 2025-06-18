import { useState, useEffect, useCallback } from 'react';
import axios from 'axios';

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

export interface ApiResponse {
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

export const useCVEData = () => {
  const [rowData, setRowData] = useState<CVEData[]>([]);
  const [loading, setLoading] = useState(false);
  const [pagination, setPagination] = useState<Pagination>({
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
  const [filters, setFilters] = useState<Filters>({
    search: '',
    severity: '',
    kev: '',
    exploits: ''
  });

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
      setPagination(prev => ({
        ...prev,
        total_items: response.data.pagination.total_items,
        total_pages: response.data.pagination.total_pages
      }));
      setSummary(response.data.summary);
    } catch (error) {
      console.error('Failed to fetch data:', error);
      setRowData([]);
    } finally {
      setLoading(false);
    }
  }, [pagination.page, pagination.per_page, filters.search, filters.severity, filters.kev, filters.exploits]);

  const researchCVEs = useCallback(async (cveIds: string[]) => {
    setLoading(true);
    try {
      await axios.post('/api/research', { cve_ids: cveIds });
      setPagination(prev => ({ ...prev, page: 1 }));
      await fetchData();
    } catch (error) {
      console.error('Research failed:', error);
      throw error;
    } finally {
      setLoading(false);
    }
  }, [fetchData]);

  const clearData = useCallback(async () => {
    try {
      await axios.delete('/api/data');
      await fetchData();
    } catch (error) {
      console.error('Failed to clear data:', error);
      throw error;
    }
  }, [fetchData]);

  const loadData = useCallback(async (data: CVEData[]) => {
    try {
      setLoading(true);
      await axios.post('/api/load-data', data);
      await fetchData();
    } catch (error) {
      console.error('Failed to load data:', error);
      throw error;
    } finally {
      setLoading(false);
    }
  }, [fetchData]);

  const handleFilterChange = useCallback((key: keyof Filters, value: string) => {
    setFilters(prev => ({ ...prev, [key]: value }));
    setPagination(prev => ({ ...prev, page: 1 }));
  }, []);

  const handlePaginationChange = useCallback((changes: Partial<Pagination>) => {
    setPagination(prev => ({ ...prev, ...changes }));
  }, []);

  const exportData = useCallback(() => {
    if (rowData.length === 0) {
      alert('No data to export. Research some CVEs first.');
      return;
    }

    const exportData = {
      timestamp: new Date().toISOString(),
      summary,
      cves: rowData
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
  }, [rowData, summary]);

  // Fetch data when pagination or filters change
  useEffect(() => {
    fetchData();
  }, [fetchData]);

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
    exportData,
    handleFilterChange,
    handlePaginationChange,
    refetch: fetchData
  };
};