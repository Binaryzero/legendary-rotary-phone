import { useState, useCallback, useEffect } from 'react';
import { CVEData, Pagination } from './useCVEData';

export const useModalNavigation = (
  rowData: CVEData[],
  pagination: Pagination,
  onPageChange: (page: number) => void
) => {
  const [selectedCve, setSelectedCve] = useState<CVEData | null>(null);
  const [selectedCveIndex, setSelectedCveIndex] = useState<number>(-1);
  const [pendingNavigation, setPendingNavigation] = useState<'first' | 'last' | null>(null);
  const [expandedSections, setExpandedSections] = useState<Record<string, boolean>>({
    overview: true,
    threat: true,
    alternative_cvss: false,
    exploits: false,
    patches: false,
    enhanced_problem_type: false,
    mitre: false,
    controls: false,
    product_intelligence: false,
    references: false,
    technical: false
  });

  // Handle pending navigation when data loads
  useEffect(() => {
    if (pendingNavigation && rowData.length > 0) {
      if (pendingNavigation === 'first') {
        setSelectedCve(rowData[0]);
        setSelectedCveIndex(0);
      } else if (pendingNavigation === 'last') {
        setSelectedCve(rowData[rowData.length - 1]);
        setSelectedCveIndex(rowData.length - 1);
      }
      setPendingNavigation(null);
    }
  }, [rowData, pendingNavigation]);

  const openModal = useCallback((cve: CVEData, index?: number) => {
    setSelectedCve(cve);
    if (index !== undefined) {
      setSelectedCveIndex(index);
    } else {
      const foundIndex = rowData.findIndex(item => item.cve_id === cve.cve_id);
      setSelectedCveIndex(foundIndex);
    }
  }, [rowData]);

  const closeModal = useCallback(() => {
    setSelectedCve(null);
    setSelectedCveIndex(-1);
  }, []);

  const navigateRecord = useCallback((direction: 'prev' | 'next') => {
    if (selectedCveIndex === -1) return;
    
    if (direction === 'prev') {
      if (selectedCveIndex > 0) {
        // Navigate within current page
        setSelectedCve(rowData[selectedCveIndex - 1]);
        setSelectedCveIndex(selectedCveIndex - 1);
      } else if (pagination.page > 1) {
        // Navigate to previous page and select last item
        setPendingNavigation('last');
        onPageChange(pagination.page - 1);
      }
    } else {
      if (selectedCveIndex < rowData.length - 1) {
        // Navigate within current page
        setSelectedCve(rowData[selectedCveIndex + 1]);
        setSelectedCveIndex(selectedCveIndex + 1);
      } else if (pagination.page < pagination.total_pages) {
        // Navigate to next page and select first item
        setPendingNavigation('first');
        onPageChange(pagination.page + 1);
      }
    }
  }, [selectedCveIndex, rowData, pagination, onPageChange]);

  const toggleSection = useCallback((section: string) => {
    setExpandedSections(prev => ({
      ...prev,
      [section]: !prev[section]
    }));
  }, []);

  const canNavigatePrev = selectedCveIndex > 0 || pagination.page > 1;
  const canNavigateNext = selectedCveIndex < rowData.length - 1 || pagination.page < pagination.total_pages;

  return {
    selectedCve,
    selectedCveIndex,
    expandedSections,
    openModal,
    closeModal,
    navigateRecord,
    toggleSection,
    canNavigatePrev,
    canNavigateNext
  };
};