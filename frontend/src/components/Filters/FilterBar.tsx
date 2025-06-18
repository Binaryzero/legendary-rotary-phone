import React, { memo } from 'react';
import { Filters } from '../../hooks/useCVEData';
import './FilterBar.css';

interface FilterBarProps {
  filters: Filters;
  onFilterChange: (key: keyof Filters, value: string) => void;
  onExport: () => void;
  onClearData: () => void;
  isLoading?: boolean;
}

const FilterBar: React.FC<FilterBarProps> = memo(({ 
  filters, 
  onFilterChange, 
  onExport, 
  onClearData,
  isLoading = false 
}) => {
  return (
    <div className="filter-bar">
      <div className="filter-group">
        <input
          type="text"
          placeholder="Search CVE ID or description..."
          value={filters.search}
          onChange={(e) => onFilterChange('search', e.target.value)}
          className="search-input"
          disabled={isLoading}
        />
        
        <select
          value={filters.severity}
          onChange={(e) => onFilterChange('severity', e.target.value)}
          className="filter-select"
          disabled={isLoading}
        >
          <option value="">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>

        <select
          value={filters.kev}
          onChange={(e) => onFilterChange('kev', e.target.value)}
          className="filter-select"
          disabled={isLoading}
        >
          <option value="">All KEV Status</option>
          <option value="true">In CISA KEV</option>
          <option value="false">Not in KEV</option>
        </select>

        <select
          value={filters.exploits}
          onChange={(e) => onFilterChange('exploits', e.target.value)}
          className="filter-select"
          disabled={isLoading}
        >
          <option value="">All Exploit Status</option>
          <option value="true">Has Exploits</option>
          <option value="false">No Exploits</option>
        </select>
      </div>

      <div className="action-group">
        <button 
          onClick={onExport}
          className="export-btn"
          disabled={isLoading}
        >
          Export JSON
        </button>

        <button 
          onClick={onClearData} 
          className="clear-btn"
          disabled={isLoading}
        >
          Clear All Data
        </button>
      </div>
    </div>
  );
});

FilterBar.displayName = 'FilterBar';

export default FilterBar;