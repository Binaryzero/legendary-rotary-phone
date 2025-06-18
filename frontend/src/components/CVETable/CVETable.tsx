import React, { memo } from 'react';
import { AgGridReact } from 'ag-grid-react';
import { ColDef } from 'ag-grid-community';
import { CVEData } from '../../hooks/useCVEData';
import 'ag-grid-community/styles/ag-grid.css';
import 'ag-grid-community/styles/ag-theme-alpine.css';
import './CVETable.css';

interface CVETableProps {
  rowData: CVEData[];
  loading: boolean;
  onCVESelect: (cve: CVEData, index: number) => void;
}

const CVETable: React.FC<CVETableProps> = memo(({ rowData, loading, onCVESelect }) => {
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
            onCVESelect(params.data, index);
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
      field: 'cvss_version',
      headerName: 'CVSS Version',
      width: 140,
      cellRenderer: (params: any) => (
        <span style={{ fontSize: '1.1rem', fontWeight: '500' }}>
          {params.value || 'N/A'}
        </span>
      )
    },
    {
      field: 'cvss_bt_score',
      headerName: 'CVSS-BT',
      width: 120,
      type: 'numericColumn',
      cellRenderer: (params: any) => (
        <span style={{ fontWeight: '600', fontSize: '1.2rem', color: 'var(--accent-blue)' }}>
          {params.value > 0 ? params.value.toFixed(1) : '-'}
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
      field: 'exploits',
      headerName: 'Exploits',
      width: 120,
      cellRenderer: (params: any) => {
        const exploitCount = params.value?.length || 0;
        const hasVerified = params.value?.some((exp: any) => exp.verified) || false;
        
        return (
          <div style={{ 
            display: 'flex', 
            alignItems: 'center', 
            gap: '6px',
            justifyContent: 'center'
          }}>
            <span style={{ 
              fontSize: '1.2rem',
              fontWeight: '600',
              color: exploitCount > 0 ? '#ff6b6b' : '#666'
            }}>
              {exploitCount}
            </span>
            {hasVerified && (
              <span style={{ 
                fontSize: '0.9rem',
                color: '#10B981',
                fontWeight: '600'
              }}>
                ✓
              </span>
            )}
          </div>
        );
      }
    },
    {
      field: 'product_intelligence.vendors',
      headerName: 'Vendors',
      width: 180,
      cellRenderer: (params: any) => (
        <span style={{ fontSize: '1.2rem' }}>
          {params.value && params.value.length > 0 ? 
            params.value.slice(0, 2).join(', ') + (params.value.length > 2 ? '...' : '') : 
            'N/A'
          }
        </span>
      )
    },
    {
      field: 'description',
      headerName: 'Description',
      flex: 1,
      minWidth: 300,
      cellRenderer: (params: any) => (
        <div style={{ 
          fontSize: '1.1rem',
          lineHeight: '1.3',
          padding: '0.5rem 0',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
          display: '-webkit-box',
          WebkitLineClamp: 2,
          WebkitBoxOrient: 'vertical'
        }}>
          {params.value}
        </div>
      )
    }
  ];

  if (loading) {
    return (
      <div className="table-loading">
        <div className="loading-spinner"></div>
        <p>Loading CVE data...</p>
      </div>
    );
  }

  return (
    <div className="cve-table-container">
      <div className="ag-theme-alpine" style={{ height: '100%', width: '100%' }}>
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
    </div>
  );
});

CVETable.displayName = 'CVETable';

export default CVETable;