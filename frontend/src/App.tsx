import React, { useCallback } from 'react';
import { useCVEData } from './hooks/useCVEData';
import { useModalNavigation } from './hooks/useModalNavigation';
import CVETable from './components/CVETable/CVETable';
import FilterBar from './components/Filters/FilterBar';
import ResearchInput from './components/Research/ResearchInput';
import Pagination from './components/Pagination/Pagination';
import CVEModal from './components/CVEModal/CVEModal';
import './App.css';

const App: React.FC = () => {
  const {
    rowData,
    loading,
    pagination,
    summary,
    filters,
    researchCVEs,
    clearData,
    loadData,
    exportData,
    handleFilterChange,
    handlePaginationChange
  } = useCVEData();

  const {
    selectedCve,
    selectedCveIndex,
    expandedSections,
    openModal,
    closeModal,
    navigateRecord,
    toggleSection,
    canNavigatePrev,
    canNavigateNext
  } = useModalNavigation(
    rowData,
    pagination,
    (page: number) => handlePaginationChange({ page })
  );

  const handleResearch = useCallback(async (cveIds: string[]) => {
    try {
      await researchCVEs(cveIds);
    } catch (error) {
      console.error('Research failed:', error);
      throw error;
    }
  }, [researchCVEs]);

  const handleFileUpload = useCallback(async (file: File, type: 'json' | 'cve-list') => {
    const fileContent = await file.text();

    if (type === 'json') {
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

        await loadData(dataToLoad);
      } catch (parseError) {
        throw new Error('Error parsing JSON file: ' + (parseError as Error).message);
      }
    } else {
      // Process CVE list file and research them
      const cveIds = fileContent
        .split(/[\n,\s]+/)
        .map(id => id.trim())
        .filter(id => id.match(/^CVE-\d{4}-\d+$/i))
        .map(id => id.toUpperCase());

      if (cveIds.length === 0) {
        throw new Error('No valid CVE IDs found in the file. Expected format: CVE-YYYY-NNNN');
      }

      await researchCVEs(cveIds);
    }
  }, [loadData, researchCVEs]);

  const handleClearData = useCallback(async () => {
    if (window.confirm('Are you sure you want to clear all data? This action cannot be undone.')) {
      try {
        await clearData();
      } catch (error) {
        console.error('Failed to clear data:', error);
        alert('Failed to clear data. Please try again.');
      }
    }
  }, [clearData]);

  return (
    <div className="app">
      {/* Header */}
      <header className="app-header">
        <h1>ODIN</h1>
        <div className="header-stats">
          <span>Total: {summary.total_cves.toLocaleString()}</span>
          <span>Critical/High: {summary.critical_high.toLocaleString()}</span>
          <span>KEV: {summary.in_kev.toLocaleString()}</span>
          <span>With Exploits: {summary.with_exploits.toLocaleString()}</span>
        </div>
      </header>

      {/* Controls */}
      <div className="controls">
        <ResearchInput
          onResearch={handleResearch}
          onFileUpload={handleFileUpload}
          isLoading={loading}
        />
        
        <FilterBar
          filters={filters}
          onFilterChange={handleFilterChange}
          onExport={exportData}
          onClearData={handleClearData}
          isLoading={loading}
        />
      </div>

      {/* Main Content */}
      <div className="main-content">
        <div className="data-grid">
          <CVETable
            rowData={rowData}
            loading={loading}
            onCVESelect={openModal}
          />
          
          <Pagination
            pagination={pagination}
            onPageChange={(page) => handlePaginationChange({ page })}
            onPerPageChange={(per_page) => handlePaginationChange({ per_page, page: 1 })}
            isLoading={loading}
          />
        </div>
      </div>

      {/* Modal Dialog */}
      {selectedCve && (
        <CVEModal
          cve={selectedCve}
          index={selectedCveIndex}
          totalItems={pagination.total_items}
          currentPage={pagination.page}
          perPage={pagination.per_page}
          expandedSections={expandedSections}
          canNavigatePrev={canNavigatePrev}
          canNavigateNext={canNavigateNext}
          onClose={closeModal}
          onNavigate={navigateRecord}
          onToggleSection={toggleSection}
        />
      )}
    </div>
  );
};

export default App;