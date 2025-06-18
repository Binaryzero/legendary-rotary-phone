import React, { memo } from 'react';
import { CVEData } from '../../hooks/useCVEData';
import './CVEModal.css';

interface CVEModalProps {
  cve: CVEData;
  index: number;
  totalItems: number;
  currentPage: number;
  perPage: number;
  expandedSections: Record<string, boolean>;
  canNavigatePrev: boolean;
  canNavigateNext: boolean;
  onClose: () => void;
  onNavigate: (direction: 'prev' | 'next') => void;
  onToggleSection: (section: string) => void;
}

const CVEModal: React.FC<CVEModalProps> = memo(({
  cve,
  index,
  totalItems,
  currentPage,
  perPage,
  expandedSections,
  canNavigatePrev,
  canNavigateNext,
  onClose,
  onNavigate,
  onToggleSection
}) => {
  const currentItemNumber = (currentPage - 1) * perPage + index + 1;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <div className="modal-title">
            <h2>{cve.cve_id}</h2>
            <span className="modal-index">
              {currentItemNumber} of {totalItems}
            </span>
          </div>
          
          <div className="modal-controls">
            <button
              onClick={() => onNavigate('prev')}
              disabled={!canNavigatePrev}
              className="nav-button"
            >
              ← Previous
            </button>
            
            <button
              onClick={() => onNavigate('next')}
              disabled={!canNavigateNext}
              className="nav-button"
            >
              Next →
            </button>
            
            <button onClick={onClose} className="close-button">
              ×
            </button>
          </div>
        </div>
        
        <div className="modal-body">
          {/* Top Summary Section */}
          <div className="modal-summary">
            <div className="summary-main">
              <div className="summary-title">
                <h3>{cve.cve_id}</h3>
                <span className={`severity-badge ${cve.severity?.toLowerCase()}`}>
                  {cve.severity}
                </span>
              </div>
              <div className="summary-description">
                {cve.description}
              </div>
            </div>
            
            <div className="summary-metrics">
              <div className="metric-card">
                <div className="metric-label">CVSS Score</div>
                <div className="metric-value">{cve.cvss_score || 'N/A'}</div>
              </div>
              <div className="metric-card">
                <div className="metric-label">CVSS Version</div>
                <div className="metric-value">{cve.cvss_version || 'N/A'}</div>
              </div>
              {cve.cvss_bt_score > 0 && (
                <div className="metric-card">
                  <div className="metric-label">CVSS-BT Score</div>
                  <div className="metric-value">{cve.cvss_bt_score.toFixed(1)}</div>
                </div>
              )}
              <div className="metric-card">
                <div className="metric-label">EPSS Score</div>
                <div className="metric-value">{cve.threat.epss_score?.toFixed(3) || 'N/A'}</div>
              </div>
              <div className="metric-card">
                <div className="metric-label">CISA KEV</div>
                <div className={`metric-value ${cve.threat.in_kev ? 'kev-yes' : ''}`}>
                  {cve.threat.in_kev ? 'Yes' : 'No'}
                </div>
              </div>
            </div>
          </div>

          {/* Overview Section */}
          <div className="collapsible-section">
            <button 
              className="section-header"
              onClick={() => onToggleSection('overview')}
            >
              <span>Overview & Classification</span>
              <span className={`expand-caret ${expandedSections.overview ? 'expanded' : ''}`}>
                ▶
              </span>
            </button>
            {expandedSections.overview && (
              <div className="section-content">
                <div className="field-row">
                  <strong>CVE Vector</strong>
                  <span style={{fontFamily: 'monospace', fontSize: '0.9rem'}}>{cve.cvss_vector || 'N/A'}</span>
                </div>
                {cve.exploit_maturity && (
                  <div className="field-row">
                    <strong>Exploit Maturity</strong>
                    <span>{cve.exploit_maturity}</span>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Threat Intelligence Section */}
          <div className="collapsible-section">
            <button 
              className="section-header"
              onClick={() => onToggleSection('threat')}
            >
              <span>Threat Intelligence & Risk Context</span>
              <span className={`expand-caret ${expandedSections.threat ? 'expanded' : ''}`}>
                ▶
              </span>
            </button>
            {expandedSections.threat && (
              <div className="section-content">
                <div className="threat-grid">
                  <div className="threat-item">
                    <strong>CISA KEV Status</strong>
                    <span className={cve.threat.in_kev ? 'status-critical' : 'status-normal'}>
                      {cve.threat.in_kev ? 'Listed in KEV' : 'Not in KEV'}
                    </span>
                  </div>
                  
                  
                  <div className="threat-item">
                    <strong>Actively Exploited</strong>
                    <span className={cve.threat.actively_exploited ? 'status-critical' : 'status-normal'}>
                      {cve.threat.actively_exploited ? 'Yes' : 'No'}
                    </span>
                  </div>
                  
                  <div className="threat-item">
                    <strong>Ransomware Campaign</strong>
                    <span className={cve.threat.ransomware_campaign ? 'status-critical' : 'status-normal'}>
                      {cve.threat.ransomware_campaign ? 'Yes' : 'No'}
                    </span>
                  </div>

                  <div className="threat-item">
                    <strong>Has Metasploit</strong>
                    <span className={cve.threat.has_metasploit ? 'status-warning' : 'status-normal'}>
                      {cve.threat.has_metasploit ? 'Yes' : 'No'}
                    </span>
                  </div>

                  <div className="threat-item">
                    <strong>Has Nuclei</strong>
                    <span className={cve.threat.has_nuclei ? 'status-warning' : 'status-normal'}>
                      {cve.threat.has_nuclei ? 'Yes' : 'No'}
                    </span>
                  </div>
                </div>

                {/* KEV Details */}
                {cve.threat.in_kev && (
                  <div className="kev-details">
                    <h4>CISA KEV Details</h4>
                    <div className="field-row">
                      <strong>Vulnerability Name</strong>
                      <span>{cve.threat.kev_vulnerability_name || 'N/A'}</span>
                    </div>
                    <div className="field-row">
                      <strong>Short Description</strong>
                      <span>{cve.threat.kev_short_description || 'N/A'}</span>
                    </div>
                    <div className="field-row">
                      <strong>Vendor/Project</strong>
                      <span>{cve.threat.kev_vendor_project || 'N/A'}</span>
                    </div>
                    <div className="field-row">
                      <strong>Product</strong>
                      <span>{cve.threat.kev_product || 'N/A'}</span>
                    </div>
                    <div className="field-row">
                      <strong>Required Action</strong>
                      <span>{cve.threat.kev_required_action || 'N/A'}</span>
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Alternative CVSS Scores Section */}
          {cve.alternative_cvss_scores && cve.alternative_cvss_scores.length > 0 && (
            <div className="collapsible-section">
              <button 
                className="section-header"
                onClick={() => onToggleSection('alternative_cvss')}
              >
                <span>Alternative CVSS Scores ({cve.alternative_cvss_scores.length})</span>
                <span className={`expand-caret ${expandedSections.alternative_cvss ? 'expanded' : ''}`}>
                  ▶
                </span>
              </button>
              {expandedSections.alternative_cvss && (
                <div className="section-content">
                  <div className="cvss-grid">
                    {cve.alternative_cvss_scores.map((cvss, idx) => (
                      <div key={idx} className="cvss-item">
                        <div className="cvss-score">{cvss.score}</div>
                        <div className="cvss-details">
                          <div>Version: {cvss.version}</div>
                          <div>Source: {cvss.source}</div>
                          <div style={{fontFamily: 'monospace', fontSize: '0.8rem'}}>{cvss.vector}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Exploits Section */}
          <div className="collapsible-section">
            <button 
              className="section-header"
              onClick={() => onToggleSection('exploits')}
            >
              <span>Known Exploits ({cve.exploits?.length || 0})</span>
              <span className={`expand-caret ${expandedSections.exploits ? 'expanded' : ''}`}>
                ▶
              </span>
            </button>
            {expandedSections.exploits && (
              <div className="section-content">
                {cve.exploits?.length > 0 ? (
                  <>
                    <div className="exploits-summary">
                      <span>Total: {cve.exploits.length}</span>
                      <span>Verified: {cve.exploits.filter(exp => exp.verified).length}</span>
                      <span>Sources: {Array.from(new Set(cve.exploits.map(exp => exp.source))).length}</span>
                    </div>
                    <div className="exploits-table-container">
                      <table className="exploits-table">
                        <thead>
                          <tr>
                            <th>Source</th>
                            <th>Type</th>
                            <th>Title</th>
                            <th>Verified</th>
                            <th>URL</th>
                          </tr>
                        </thead>
                        <tbody>
                          {cve.exploits.map((exploit, idx) => (
                            <tr key={idx}>
                              <td>
                                <span className={`source-badge ${exploit.source.toLowerCase()}`}>
                                  {exploit.source}
                                </span>
                              </td>
                              <td>
                                <span className="exploit-type">{exploit.type}</span>
                              </td>
                              <td>
                                <span className="exploit-title">{exploit.title || 'N/A'}</span>
                              </td>
                              <td>
                                <span className={`verification-status ${exploit.verified ? 'verified' : 'unverified'}`}>
                                  {exploit.verified ? '✓ Verified' : '○ Unverified'}
                                </span>
                              </td>
                              <td>
                                <a 
                                  href={exploit.url} 
                                  target="_blank" 
                                  rel="noopener noreferrer"
                                  className="exploit-link"
                                >
                                  View
                                </a>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </>
                ) : (
                  <p style={{ fontSize: '1.1rem', color: 'var(--text-secondary)', textAlign: 'center', padding: '2rem' }}>
                    No known exploits for this CVE
                  </p>
                )}
              </div>
            )}
          </div>

          {/* Patches Section */}
          <div className="collapsible-section">
            <button 
              className="section-header"
              onClick={() => onToggleSection('patches')}
            >
              <span>Patches & Remediation ({cve.patches?.length || 0})</span>
              <span className={`expand-caret ${expandedSections.patches ? 'expanded' : ''}`}>
                ▶
              </span>
            </button>
            {expandedSections.patches && (
              <div className="section-content">
                {cve.patches?.length > 0 ? (
                  <div className="patches-grid">
                    {cve.patches.map((patch, idx) => (
                      <div key={idx} className="patch-item">
                        <a href={patch} target="_blank" rel="noopener noreferrer" className="patch-link">
                          {patch}
                        </a>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p style={{ textAlign: 'center', color: 'var(--text-secondary)', padding: '2rem' }}>
                    No patches available
                  </p>
                )}
              </div>
            )}
          </div>

          {/* Enhanced Problem Type Section - Only show if has meaningful data */}
          {cve.enhanced_problem_type && (
            cve.enhanced_problem_type.primary_weakness || 
            cve.enhanced_problem_type.secondary_weaknesses || 
            cve.enhanced_problem_type.vulnerability_categories ||
            cve.enhanced_problem_type.impact_types ||
            cve.enhanced_problem_type.attack_vectors ||
            cve.enhanced_problem_type.enhanced_cwe_details
          ) && (
            <div className="collapsible-section">
              <button 
                className="section-header"
                onClick={() => onToggleSection('enhanced_problem_type')}
              >
                <span>Enhanced Problem Type Analysis</span>
                <span className={`expand-caret ${expandedSections.enhanced_problem_type ? 'expanded' : ''}`}>
                  ▶
                </span>
              </button>
              {expandedSections.enhanced_problem_type && (
                <div className="section-content">
                  {cve.enhanced_problem_type.primary_weakness && (
                    <div className="field-row">
                      <strong>Primary Weakness</strong>
                      <span>{cve.enhanced_problem_type.primary_weakness}</span>
                    </div>
                  )}
                  {cve.enhanced_problem_type.secondary_weaknesses && (
                    <div className="field-row">
                      <strong>Secondary Weaknesses</strong>
                      <span>{cve.enhanced_problem_type.secondary_weaknesses}</span>
                    </div>
                  )}
                  {cve.enhanced_problem_type.vulnerability_categories && (
                    <div className="field-row">
                      <strong>Vulnerability Categories</strong>
                      <span>{cve.enhanced_problem_type.vulnerability_categories}</span>
                    </div>
                  )}
                  {cve.enhanced_problem_type.impact_types && (
                    <div className="field-row">
                      <strong>Impact Types</strong>
                      <span>{cve.enhanced_problem_type.impact_types}</span>
                    </div>
                  )}
                  {cve.enhanced_problem_type.attack_vectors && (
                    <div className="field-row">
                      <strong>Attack Vectors</strong>
                      <span>{cve.enhanced_problem_type.attack_vectors}</span>
                    </div>
                  )}
                  {cve.enhanced_problem_type.enhanced_cwe_details && (
                    <div className="field-row">
                      <strong>Enhanced CWE Details</strong>
                      <span>{cve.enhanced_problem_type.enhanced_cwe_details}</span>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* MITRE Framework Section */}
          <div className="collapsible-section">
            <button 
              className="section-header"
              onClick={() => onToggleSection('mitre')}
            >
              <span>MITRE Framework</span>
              <span className={`expand-caret ${expandedSections.mitre ? 'expanded' : ''}`}>
                ▶
              </span>
            </button>
            {expandedSections.mitre && (
              <div className="section-content">
                <div className="mitre-grid">
                  <div className="mitre-section">
                    <h4>Common Weakness Enumeration (CWE)</h4>
                    <div className="field-row">
                      <strong>CWE IDs</strong>
                      <span>{cve.weakness?.cwe_ids?.join(', ') || 'None'}</span>
                    </div>
                    {cve.weakness?.cwe_details && cve.weakness.cwe_details.length > 0 && (
                      <div className="field-row">
                        <strong>CWE Details</strong>
                        <div className="details-list">
                          {cve.weakness.cwe_details.map((detail, idx) => (
                            <div key={idx} className="detail-item">{detail}</div>
                          ))}
                        </div>
                      </div>
                    )}
                    {cve.weakness?.alternative_cwe_mappings && cve.weakness.alternative_cwe_mappings.length > 0 && (
                      <div className="field-row">
                        <strong>Alternative CWE Mappings</strong>
                        <span>{cve.weakness.alternative_cwe_mappings.join(', ')}</span>
                      </div>
                    )}
                  </div>

                  <div className="mitre-section">
                    <h4>ATT&CK Techniques & Tactics</h4>
                    <div className="field-row">
                      <strong>Attack Techniques</strong>
                      <span>{cve.weakness?.attack_techniques?.join(', ') || 'None'}</span>
                    </div>
                    <div className="field-row">
                      <strong>Attack Tactics</strong>
                      <span>{cve.weakness?.attack_tactics?.join(', ') || 'None'}</span>
                    </div>
                    <div className="field-row">
                      <strong>Kill Chain Phases</strong>
                      <span>{cve.weakness?.kill_chain_phases?.join(', ') || 'None'}</span>
                    </div>
                    {cve.weakness?.enhanced_technique_descriptions && cve.weakness.enhanced_technique_descriptions.length > 0 && (
                      <div className="field-row">
                        <strong>Enhanced Technique Descriptions</strong>
                        <div className="details-list">
                          {cve.weakness.enhanced_technique_descriptions.map((desc, idx) => (
                            <div key={idx} className="detail-item">{desc}</div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>

                  <div className="mitre-section">
                    <h4>Common Attack Pattern Enumeration (CAPEC)</h4>
                    <div className="field-row">
                      <strong>CAPEC IDs</strong>
                      <span>{cve.weakness?.capec_ids?.join(', ') || 'None'}</span>
                    </div>
                    {cve.weakness?.enhanced_capec_descriptions && cve.weakness.enhanced_capec_descriptions.length > 0 && (
                      <div className="field-row">
                        <strong>Enhanced CAPEC Descriptions</strong>
                        <div className="details-list">
                          {cve.weakness.enhanced_capec_descriptions.map((desc, idx) => (
                            <div key={idx} className="detail-item">{desc}</div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Control Mappings Section - Only show if has meaningful data */}
          {cve.control_mappings && (
            cve.control_mappings.applicable_controls_count || 
            cve.control_mappings.control_categories || 
            cve.control_mappings.top_controls
          ) && (
            <div className="collapsible-section">
              <button 
                className="section-header"
                onClick={() => onToggleSection('controls')}
              >
                <span>Security Control Mappings</span>
                <span className={`expand-caret ${expandedSections.controls ? 'expanded' : ''}`}>
                  ▶
                </span>
              </button>
              {expandedSections.controls && (
                <div className="section-content">
                  {cve.control_mappings.applicable_controls_count && (
                    <div className="field-row">
                      <strong>Applicable Controls Count</strong>
                      <span>{cve.control_mappings.applicable_controls_count}</span>
                    </div>
                  )}
                  {cve.control_mappings.control_categories && (
                    <div className="field-row">
                      <strong>Control Categories</strong>
                      <span>{cve.control_mappings.control_categories}</span>
                    </div>
                  )}
                  {cve.control_mappings.top_controls && (
                    <div className="field-row">
                      <strong>Top Controls</strong>
                      <span>{cve.control_mappings.top_controls}</span>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* Product Intelligence Section - Only show if has meaningful data */}
          {cve.product_intelligence && (
            (cve.product_intelligence.vendors && cve.product_intelligence.vendors.length > 0) ||
            (cve.product_intelligence.products && cve.product_intelligence.products.length > 0) ||
            (cve.product_intelligence.platforms && cve.product_intelligence.platforms.length > 0) ||
            (cve.product_intelligence.affected_versions && cve.product_intelligence.affected_versions.length > 0) ||
            (cve.product_intelligence.modules && cve.product_intelligence.modules.length > 0)
          ) && (
            <div className="collapsible-section">
              <button 
                className="section-header"
                onClick={() => onToggleSection('product_intelligence')}
              >
                <span>Product Intelligence</span>
                <span className={`expand-caret ${expandedSections.product_intelligence ? 'expanded' : ''}`}>
                  ▶
                </span>
              </button>
              {expandedSections.product_intelligence && (
                <div className="section-content">
                  <div className="product-grid">
                    <div className="product-section">
                      <h4>Affected Products</h4>
                      {cve.product_intelligence.vendors && cve.product_intelligence.vendors.length > 0 && (
                        <div className="field-row">
                          <strong>Vendors</strong>
                          <div className="tag-list">
                            {cve.product_intelligence.vendors.map((vendor, idx) => (
                              <span key={idx} className="tag vendor-tag">{vendor}</span>
                            ))}
                          </div>
                        </div>
                      )}
                      {cve.product_intelligence.products && cve.product_intelligence.products.length > 0 && (
                        <div className="field-row">
                          <strong>Products</strong>
                          <div className="tag-list">
                            {cve.product_intelligence.products.map((product, idx) => (
                              <span key={idx} className="tag product-tag">{product}</span>
                            ))}
                          </div>
                        </div>
                      )}
                      {cve.product_intelligence.platforms && cve.product_intelligence.platforms.length > 0 && (
                        <div className="field-row">
                          <strong>Platforms</strong>
                          <div className="tag-list">
                            {cve.product_intelligence.platforms.map((platform, idx) => (
                              <span key={idx} className="tag platform-tag">{platform}</span>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>

                    <div className="product-section">
                      <h4>Version Information</h4>
                      {cve.product_intelligence.affected_versions && cve.product_intelligence.affected_versions.length > 0 && (
                        <div className="field-row">
                          <strong>Affected Versions</strong>
                          <div className="version-list">
                            {cve.product_intelligence.affected_versions.map((version, idx) => (
                              <span key={idx} className="version-item">{version}</span>
                            ))}
                          </div>
                        </div>
                      )}
                      {cve.product_intelligence.modules && cve.product_intelligence.modules.length > 0 && (
                        <div className="field-row">
                          <strong>Modules</strong>
                          <div className="tag-list">
                            {cve.product_intelligence.modules.map((module, idx) => (
                              <span key={idx} className="tag module-tag">{module}</span>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* References Section */}
          <div className="collapsible-section">
            <button 
              className="section-header"
              onClick={() => onToggleSection('references')}
            >
              <span>References & Mitigations ({(cve.references?.length || 0) + (cve.mitigations?.length || 0)})</span>
              <span className={`expand-caret ${expandedSections.references ? 'expanded' : ''}`}>
                ▶
              </span>
            </button>
            {expandedSections.references && (
              <div className="section-content">
                {cve.reference_tags && cve.reference_tags.length > 0 && (
                  <div className="field-row">
                    <strong>Reference Tags</strong>
                    <div className="tag-list">
                      {cve.reference_tags.map((tag, idx) => (
                        <span key={idx} className="tag reference-tag">{tag}</span>
                      ))}
                    </div>
                  </div>
                )}

                {cve.references && cve.references.length > 0 && (
                  <div className="references-section">
                    <h4>External References ({cve.references.length})</h4>
                    <div className="references-list">
                      {cve.references.map((ref, idx) => (
                        <div key={idx} className="reference-item">
                          <a href={ref} target="_blank" rel="noopener noreferrer" className="reference-link">
                            {ref}
                          </a>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {cve.mitigations && cve.mitigations.length > 0 && (
                  <div className="mitigations-section">
                    <h4>Mitigations ({cve.mitigations.length})</h4>
                    <div className="mitigations-list">
                      {cve.mitigations.map((mitigation, idx) => (
                        <div key={idx} className="mitigation-item">
                          {mitigation}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {cve.fix_versions && cve.fix_versions.length > 0 && (
                  <div className="fix-versions-section">
                    <h4>Fix Versions ({cve.fix_versions.length})</h4>
                    <div className="fix-versions-list">
                      {cve.fix_versions.map((version, idx) => (
                        <span key={idx} className="fix-version-item">{version}</span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Technical Details Section */}
          <div className="collapsible-section">
            <button 
              className="section-header"
              onClick={() => onToggleSection('technical')}
            >
              <span>Technical Details</span>
              <span className={`expand-caret ${expandedSections.technical ? 'expanded' : ''}`}>
                ▶
              </span>
            </button>
            {expandedSections.technical && (
              <div className="section-content">
                <div className="field-row">
                  <strong>CPE Affected</strong>
                  <span style={{fontFamily: 'monospace', fontSize: '0.9rem', wordBreak: 'break-all'}}>
                    {cve.cpe_affected || 'N/A'}
                  </span>
                </div>
                <div className="field-row">
                  <strong>CVSS Vector</strong>
                  <span style={{fontFamily: 'monospace', fontSize: '0.9rem', wordBreak: 'break-all'}}>
                    {cve.cvss_vector || 'N/A'}
                  </span>
                </div>
                {cve.cvss_bt_severity && (
                  <div className="field-row">
                    <strong>CVSS-BT Severity</strong>
                    <span>{cve.cvss_bt_severity}</span>
                  </div>
                )}
                
                {cve.vendor_advisories && cve.vendor_advisories.length > 0 && (
                  <div className="field-row">
                    <strong>Vendor Advisories ({cve.vendor_advisories.length})</strong>
                    <div className="advisories-list">
                      {cve.vendor_advisories.map((advisory, idx) => (
                        <div key={idx} className="advisory-item">
                          <a href={advisory} target="_blank" rel="noopener noreferrer" className="advisory-link">
                            {advisory}
                          </a>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
});

CVEModal.displayName = 'CVEModal';

export default CVEModal;