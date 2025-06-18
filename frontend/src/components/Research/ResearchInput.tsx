import React, { useState, memo, useRef } from 'react';
import './ResearchInput.css';

interface ResearchInputProps {
  onResearch: (cveIds: string[]) => Promise<void>;
  onFileUpload: (file: File, type: 'json' | 'cve-list') => Promise<void>;
  isLoading?: boolean;
}

const ResearchInput: React.FC<ResearchInputProps> = memo(({ 
  onResearch, 
  onFileUpload,
  isLoading = false 
}) => {
  const [researchInput, setResearchInput] = useState('');
  const [uploadType, setUploadType] = useState<'json' | 'cve-list'>('cve-list');
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleResearch = async () => {
    if (!researchInput.trim() || isLoading) return;

    const cveIds = researchInput
      .split(/[,\n]/)
      .map(id => id.trim())
      .filter(id => id.startsWith('CVE-'))
      .filter(Boolean);

    if (cveIds.length === 0) {
      alert('Please enter valid CVE IDs (format: CVE-YYYY-NNNN)');
      return;
    }

    try {
      await onResearch(cveIds);
      setResearchInput('');
    } catch (error) {
      console.error('Research failed:', error);
      alert('Research failed. Please try again.');
    }
  };

  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file || isLoading) return;

    try {
      await onFileUpload(file, uploadType);
      // Clear the file input
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
    } catch (error) {
      console.error('File upload failed:', error);
      alert('File upload failed: ' + (error as Error).message);
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
      handleResearch();
    }
  };

  return (
    <div className="research-input">
      <div className="research-section">
        <div className="input-group">
          <textarea
            placeholder="Enter CVE IDs (comma or newline separated)&#10;Example: CVE-2021-44228, CVE-2021-45046"
            value={researchInput}
            onChange={(e) => setResearchInput(e.target.value)}
            onKeyDown={handleKeyPress}
            disabled={isLoading}
            className="cve-input"
            rows={3}
          />
          <button 
            onClick={handleResearch}
            disabled={!researchInput.trim() || isLoading}
            className="research-btn"
          >
            {isLoading ? 'Researching...' : 'Research CVEs'}
          </button>
        </div>
        
        <div className="input-help">
          <span>💡 Tip: Use Ctrl+Enter to research quickly</span>
        </div>
      </div>

      <div className="file-upload-section">
        <div className="upload-controls">
          <div className="upload-type-selector">
            <label className="radio-label">
              <input
                type="radio"
                value="cve-list"
                checked={uploadType === 'cve-list'}
                onChange={(e) => setUploadType(e.target.value as 'cve-list')}
                disabled={isLoading}
              />
              CVE List File
            </label>
            <label className="radio-label">
              <input
                type="radio"
                value="json"
                checked={uploadType === 'json'}
                onChange={(e) => setUploadType(e.target.value as 'json')}
                disabled={isLoading}
              />
              JSON Data File
            </label>
          </div>
          
          <div className="file-input-wrapper">
            <input
              ref={fileInputRef}
              type="file"
              accept={uploadType === 'json' ? '.json' : '.txt,.csv'}
              onChange={handleFileUpload}
              disabled={isLoading}
              className="file-input"
              id="file-upload"
            />
            <label htmlFor="file-upload" className="file-input-label">
              {isLoading ? 'Processing...' : 'Choose File'}
            </label>
          </div>
        </div>
        
        <div className="upload-help">
          {uploadType === 'cve-list' ? (
            <span>📁 Upload a text/CSV file with CVE IDs to research them automatically</span>
          ) : (
            <span>📊 Upload a JSON file with existing CVE data to load directly</span>
          )}
        </div>
      </div>
    </div>
  );
});

ResearchInput.displayName = 'ResearchInput';

export default ResearchInput;