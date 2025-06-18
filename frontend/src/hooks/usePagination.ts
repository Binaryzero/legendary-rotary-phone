import { useState, useCallback } from 'react';

export interface PaginationState {
  page: number;
  per_page: number;
  total_items: number;
  total_pages: number;
}

export const usePagination = (initialPerPage: number = 25) => {
  const [pagination, setPagination] = useState<PaginationState>({
    page: 1,
    per_page: initialPerPage,
    total_items: 0,
    total_pages: 0
  });

  const updatePagination = useCallback((updates: Partial<PaginationState>) => {
    setPagination(prev => ({ ...prev, ...updates }));
  }, []);

  const goToPage = useCallback((page: number) => {
    setPagination(prev => ({ ...prev, page }));
  }, []);

  const changePerPage = useCallback((per_page: number) => {
    setPagination(prev => ({ 
      ...prev, 
      per_page,
      page: 1 // Reset to first page when changing page size
    }));
  }, []);

  const nextPage = useCallback(() => {
    setPagination(prev => ({
      ...prev,
      page: Math.min(prev.page + 1, prev.total_pages)
    }));
  }, []);

  const prevPage = useCallback(() => {
    setPagination(prev => ({
      ...prev,
      page: Math.max(prev.page - 1, 1)
    }));
  }, []);

  const resetToFirstPage = useCallback(() => {
    setPagination(prev => ({ ...prev, page: 1 }));
  }, []);

  return {
    pagination,
    updatePagination,
    goToPage,
    changePerPage,
    nextPage,
    prevPage,
    resetToFirstPage,
    hasNext: pagination.page < pagination.total_pages,
    hasPrev: pagination.page > 1
  };
};