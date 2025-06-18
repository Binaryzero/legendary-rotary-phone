import React, { memo } from 'react';
import { Pagination as PaginationState } from '../../hooks/useCVEData';
import './Pagination.css';

interface PaginationProps {
  pagination: PaginationState;
  onPageChange: (page: number) => void;
  onPerPageChange: (perPage: number) => void;
  isLoading?: boolean;
}

const Pagination: React.FC<PaginationProps> = memo(({ 
  pagination, 
  onPageChange, 
  onPerPageChange,
  isLoading = false 
}) => {
  const { page, per_page, total_items, total_pages } = pagination;

  const handlePrevious = () => {
    if (page > 1 && !isLoading) {
      onPageChange(page - 1);
    }
  };

  const handleNext = () => {
    if (page < total_pages && !isLoading) {
      onPageChange(page + 1);
    }
  };

  const handlePerPageChange = (event: React.ChangeEvent<HTMLSelectElement>) => {
    if (!isLoading) {
      onPerPageChange(parseInt(event.target.value));
    }
  };

  const generatePageNumbers = () => {
    const pages = [];
    const maxVisiblePages = 5;
    
    if (total_pages <= maxVisiblePages) {
      // Show all pages if total is small
      for (let i = 1; i <= total_pages; i++) {
        pages.push(i);
      }
    } else {
      // Smart pagination with ellipsis
      const startPage = Math.max(1, page - 2);
      const endPage = Math.min(total_pages, page + 2);
      
      if (startPage > 1) {
        pages.push(1);
        if (startPage > 2) pages.push('...');
      }
      
      for (let i = startPage; i <= endPage; i++) {
        pages.push(i);
      }
      
      if (endPage < total_pages) {
        if (endPage < total_pages - 1) pages.push('...');
        pages.push(total_pages);
      }
    }
    
    return pages;
  };

  if (total_items === 0) {
    return (
      <div className="pagination-container">
        <div className="pagination-info">
          <span>No data to display</span>
        </div>
      </div>
    );
  }

  const startItem = (page - 1) * per_page + 1;
  const endItem = Math.min(page * per_page, total_items);

  return (
    <div className="pagination-container">
      <div className="pagination-info">
        <span>
          Showing {startItem.toLocaleString()} to {endItem.toLocaleString()} of {total_items.toLocaleString()} items
        </span>
      </div>

      <div className="pagination-controls">
        <button
          onClick={handlePrevious}
          disabled={page <= 1 || isLoading}
          className="pagination-btn pagination-prev"
          aria-label="Previous page"
        >
          ← Previous
        </button>

        <div className="page-numbers">
          {generatePageNumbers().map((pageNum, index) => (
            <React.Fragment key={index}>
              {pageNum === '...' ? (
                <span className="pagination-ellipsis">...</span>
              ) : (
                <button
                  onClick={() => onPageChange(pageNum as number)}
                  disabled={isLoading}
                  className={`pagination-btn page-number ${
                    pageNum === page ? 'active' : ''
                  }`}
                  aria-label={`Page ${pageNum}`}
                >
                  {pageNum}
                </button>
              )}
            </React.Fragment>
          ))}
        </div>

        <button
          onClick={handleNext}
          disabled={page >= total_pages || isLoading}
          className="pagination-btn pagination-next"
          aria-label="Next page"
        >
          Next →
        </button>
      </div>

      <div className="pagination-size">
        <select
          value={per_page}
          onChange={handlePerPageChange}
          disabled={isLoading}
          className="per-page-select"
          aria-label="Items per page"
        >
          <option value={10}>10 per page</option>
          <option value={25}>25 per page</option>
          <option value={50}>50 per page</option>
          <option value={100}>100 per page</option>
        </select>
      </div>
    </div>
  );
});

Pagination.displayName = 'Pagination';

export default Pagination;