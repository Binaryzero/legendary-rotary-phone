# ODIN Data Dictionary

## **ODIN (OSINT Data Intelligence Nexus) - Complete Field Reference**

**Current Version**: v1.0.2 | **Field Count**: 80 | **Last Updated**: 2025-06-18

ODIN implements a systematic vulnerability intelligence aggregation workflow through structured research layers. This document provides the definitive reference for all data fields extracted by ODIN's comprehensive intelligence platform.

---

## ** Data Layer Architecture**

ODIN's **5-layer data architecture** aggregates intelligence from authoritative sources:

| Layer | Source Repository | Intelligence Provided | Field Contribution |
|-------|------------------|----------------------|-------------------|
| **1. Foundational Record** | CVEProject/cvelistV5 | Official CVE data, CVSS metrics, references | 35+ fields |
| **2. Exploit Mechanics** | trickest/cve | Proof-of-concept exploits, verification status | 8+ fields |
| **3. Weakness Classification** | mitre/cti | ATT&CK techniques, CAPEC patterns | 12+ fields |
| **4. Threat Context** | t0sche/cvss-bt | CISA KEV, temporal CVSS, indicators | 15+ fields |
| **5. Raw Intelligence** | Patrowl/PatrowlHearsData | Additional feeds, validation data | 10+ fields |

**Total**: **80 structured fields** providing comprehensive vulnerability intelligence

---

## ** Complete Field Reference**

### ** Core CVE Intelligence (12 fields)**

| Field Name | Type | Description | Source Layer |
|------------|------|-------------|--------------|
| **cve_id** | String | Unique CVE identifier (e.g., CVE-2021-44228) | Layer 1 |
| **description** | Text | Official vulnerability description | Layer 1 |
| **cvss_score** | Float | Base CVSS score (0.0-10.0) | Layer 1 |
| **cvss_vector** | String | Complete CVSS vector string | Layer 1 |
| **cvss_version** | String | CVSS version used (2.0, 3.0, 3.1) | Layer 1 |
| **severity** | String | Computed severity (Critical/High/Medium/Low/None) | Layer 1 |
| **published_date** | Date | Official CVE publication date | Layer 1 |
| **cwe_ids** | Array | Common Weakness Enumeration identifiers | Layer 1 |
| **cwe_descriptions** | Array | CWE weakness descriptions | Layer 1 |
| **references** | Array | All reference URLs from CVE record | Layer 1 |
| **reference_count** | Integer | Total number of references | Layer 1 |
| **alternative_cvss_scores** | Array | Additional CVSS scores from ADP entries | Layer 1 |

### ** CVSS Component Breakdown (8 fields)**

| Field Name | Type | Description | Values |
|------------|------|-------------|--------|
| **attack_vector** | String | CVSS Attack Vector | Network/Adjacent/Local/Physical |
| **attack_complexity** | String | CVSS Attack Complexity | Low/High |
| **privileges_required** | String | CVSS Privileges Required | None/Low/High |
| **user_interaction** | String | CVSS User Interaction | None/Required |
| **scope** | String | CVSS Scope | Unchanged/Changed |
| **confidentiality_impact** | String | CVSS Confidentiality Impact | None/Low/High |
| **integrity_impact** | String | CVSS Integrity Impact | None/Low/High |
| **availability_impact** | String | CVSS Availability Impact | None/Low/High |

### ** Exploit Intelligence (8 fields)**

| Field Name | Type | Description | Source Layer |
|------------|------|-------------|--------------|
| **exploits** | Array | Available exploit URLs and metadata | Layer 2 |
| **exploit_count** | Integer | Number of public exploits found | Layer 2 |
| **exploit_verification** | String | Exploit reliability assessment | Layer 2 |
| **exploit_titles** | Array | Enhanced exploit descriptions | Layer 2 |
| **exploit_maturity** | String | Maturity level (unproven/poc/functional/weaponized) | Layer 2 |
| **exploit_types** | Array | Types of exploits (exploit-db, github-poc, etc.) | Layer 2 |
| **has_metasploit** | Boolean | Metasploit module available | Layer 4 |
| **has_nuclei** | Boolean | Nuclei template available | Layer 4 |

### ** Enhanced Problem Classification (6 fields)**

| Field Name | Type | Description | Source Layer |
|------------|------|-------------|--------------|
| **primary_weakness** | String | Primary CWE weakness category | Layer 3 |
| **secondary_weaknesses** | Array | Additional applicable CWE categories | Layer 3 |
| **vulnerability_categories** | Array | Structured vulnerability classifications | Layer 3 |
| **impact_types** | Array | Types of impacts from exploitation | Layer 3 |
| **attack_vectors** | Array | Possible attack vectors | Layer 3 |
| **enhanced_cwe_details** | Object | Detailed CWE mapping and context | Layer 3 |

### ** Product Intelligence (6 fields)**

| Field Name | Type | Description | Source Layer |
|------------|------|-------------|--------------|
| **vendors** | Array | Affected vendor organizations | Layer 1 |
| **products** | Array | Specific products affected | Layer 1 |
| **affected_versions** | Array | Vulnerable product versions | Layer 1 |
| **platforms** | Array | Operating systems/platforms affected | Layer 1 |
| **modules** | Array | Specific software modules/components | Layer 1 |
| **affected** | String | Comma-separated affected products summary | Layer 1 |

### ** Reference Intelligence (4 fields)**

| Field Name | Type | Description | Source Layer |
|------------|------|-------------|--------------|
| **reference_tags** | Array | CVE reference type tags (patch, advisory, etc.) | Layer 1 |
| **mitigations** | Array | URLs for mitigation guidance | Layer 1 |
| **fix_versions** | Array | URLs for patches and fixes | Layer 1 |
| **vendor_advisories** | Array | Vendor security advisory URLs | Layer 1 |

### ** Temporal CVSS Metrics (4 fields)**

| Field Name | Type | Description | Source Layer |
|------------|------|-------------|--------------|
| **exploit_code_maturity** | String | CVSS Temporal: Exploit maturity | Layer 4 |
| **remediation_level** | String | CVSS Temporal: Fix availability | Layer 4 |
| **report_confidence** | String | CVSS Temporal: Confidence level | Layer 4 |
| **cvss_bt_score** | Float | Enhanced CVSS score with temporal factors | Layer 4 |

### ** Threat Context Intelligence (12 fields)**

| Field Name | Type | Description | Source Layer |
|------------|------|-------------|--------------|
| **in_cisa_kev** | Boolean | Listed in CISA Known Exploited Vulnerabilities | Layer 4 |
| **cisa_kev_vulnerability_name** | String | Official CISA KEV vulnerability name | Layer 4 |
| **cisa_kev_vendor_project** | String | CISA KEV vendor/project information | Layer 4 |
| **cisa_kev_product** | String | CISA KEV product information | Layer 4 |
| **cisa_kev_short_description** | String | CISA KEV description | Layer 4 |
| **epss_score** | Float | Exploit Prediction Scoring System score (0.0-1.0) | Layer 4 |
| **actively_exploited** | Boolean | Evidence of active exploitation | Layer 4 |
| **ransomware_campaign** | Boolean | Used in ransomware campaigns | Layer 4 |
| **vulncheck_kev** | Boolean | Listed in VulnCheck KEV catalog | Layer 4 |
| **has_exploitdb** | Boolean | Exploit-DB entry available | Layer 4 |
| **has_poc_github** | Boolean | GitHub proof-of-concept available | Layer 4 |
| **cvss_bt_severity** | String | Enhanced severity classification | Layer 4 |

### ** Control Mappings (3 fields)**

| Field Name | Type | Description | Source Layer |
|------------|------|-------------|--------------|
| **applicable_controls_count** | Integer | Number of NIST 800-53 controls applicable | Layer 3 |
| **control_categories** | Array | Categories of applicable NIST controls | Layer 3 |
| **top_controls** | Array | Most relevant NIST 800-53 control IDs | Layer 3 |

### ** MITRE Enhancement (6 fields)**

| Field Name | Type | Description | Source Layer |
|------------|------|-------------|--------------|
| **attack_techniques** | Array | MITRE ATT&CK technique IDs | Layer 3 |
| **attack_tactics** | Array | MITRE ATT&CK tactic names | Layer 3 |
| **capec_ids** | Array | Common Attack Pattern Enumeration IDs | Layer 3 |
| **enhanced_attack_techniques** | Array | Enhanced ATT&CK descriptions with context | Layer 3 |
| **enhanced_attack_tactics** | Array | Enhanced tactic descriptions with purpose | Layer 3 |
| **enhanced_capec_descriptions** | Array | Detailed attack pattern explanations | Layer 3 |

### ** Additional Intelligence (7 fields)**

| Field Name | Type | Description | Source Layer |
|------------|------|-------------|--------------|
| **cpe_affected_count** | Integer | Number of Common Platform Enumeration entries | Layer 5 |
| **last_enriched** | DateTime | Timestamp of last intelligence update | System |
| **session_cache_hit** | Boolean | Whether data came from session cache | System |
| **data_quality_score** | Float | Completeness score (0.0-1.0) | System |
| **intelligence_sources** | Array | List of sources contributing data | System |
| **processing_duration** | Float | Time taken to aggregate intelligence (seconds) | System |
| **api_rate_limits_hit** | Array | Any rate limits encountered during collection | System |

---

## ** Data Processing Pipeline**

### **Layer 1: Foundational Record Processing**
```
CVEProject/cvelistV5 → JSON Parser → Core CVE Fields + Product Intelligence
├── Basic CVE metadata extraction
├── CVSS parsing with version detection
├── Reference categorization with tags
└── Product/vendor/version intelligence
```

### **Layer 2: Exploit Intelligence Aggregation**
```
trickest/cve → Markdown Parser → Exploit Intelligence Fields
├── Public exploit URL collection
├── Exploit maturity assessment
├── Verification status evaluation
└── Enhanced exploit descriptions
```

### **Layer 3: Weakness & Control Classification**
```
mitre/cti → STIX Parser → Enhanced Classifications + Control Mappings
├── ATT&CK technique mapping with context
├── CAPEC pattern identification
├── NIST 800-53 control relationships
└── Enhanced human-readable descriptions
```

### **Layer 4: Threat Context Integration**
```
t0sche/cvss-bt → CSV Parser → Temporal CVSS + Threat Indicators
├── CISA KEV status verification
├── Temporal CVSS metric calculation
├── Exploitation indicator analysis
└── Enhanced threat intelligence
```

### **Layer 5: Raw Intelligence Validation**
```
Patrowl/PatrowlHearsData → Multi-format Parser → Validation + Additional Fields
├── CPE enumeration processing
├── Additional CVSS source validation
├── Intelligence source verification
└── Data quality assessment
```

---

## ** Field Coverage Statistics**

### **Implementation Status**
- **Total Fields**: 80 (100% implemented)
- **Core CVE Data**: 12/12 fields (100%)
- **Threat Intelligence**: 12/12 fields (100%)
- **Enhanced Classifications**: 15/15 fields (100%)
- **Product Intelligence**: 6/6 fields (100%)
- **MITRE Enhancement**: 6/6 fields (100%)
- **System Metadata**: 7/7 fields (100%)

### **Data Source Reliability**
- **Institutional Sources**: 4/5 (CVEProject, MITRE, t0sche, Patrowl)
- **Community Sources**: 1/5 (trickest - verified quality)
- **Update Frequency**: Daily to continuous
- **Data Quality**: Professional-grade with graceful degradation

---

## ** Export Format Compatibility**

### **JSON Export (Complete Intelligence)**
- **All 80 fields** with full structure
- Nested objects for complex data
- Version metadata included
- Optimized for programmatic access

### **CSV Export (Analysis-Ready)**
- **All 80 fields** flattened for spreadsheet use
- Excel-compatible formatting
- Proper text sanitization
- Optimized for data analysis

### **WebUI Export (Visualization-Ready)**
- **All 80 fields** optimized for web display
- Enhanced metadata structure
- Timestamp-based naming
- Optimized for frontend consumption

---

## ** Research Value by Field Category**

### **High-Impact Intelligence Fields**
1. **Core CVE Data**: Essential for any vulnerability analysis
2. **Exploit Intelligence**: Critical for understanding exploitation reality
3. **Threat Context**: Vital for prioritization and risk assessment
4. **Product Intelligence**: Essential for asset correlation and impact analysis

### **Enhanced Analysis Fields**
1. **Enhanced Classifications**: Structured analysis beyond basic CWE
2. **Control Mappings**: Direct security control relationships
3. **MITRE Enhancement**: Human-readable context for technical frameworks
4. **Reference Intelligence**: Categorized guidance for remediation

### **Operational Intelligence**
1. **Temporal Metrics**: Time-adjusted risk assessment
2. **System Metadata**: Quality assurance and traceability
3. **Processing Information**: Performance and reliability indicators

---

## ** Data Quality Standards**

### **Source Verification**
- All data sources verified for reliability and maintenance
- Institutional sources preferred over community sources
- Regular validation of data extraction accuracy
- Comprehensive error handling and fallback mechanisms

### **Field Validation**
- Type checking for all structured fields
- Range validation for numerical fields
- Format validation for standardized fields (CVE IDs, dates)
- Completeness scoring for data quality assessment

### **Intelligence Integrity**
- Session caching prevents redundant API calls
- Rate limiting respects source API constraints
- Graceful degradation when sources unavailable
- Comprehensive logging for audit trails

---

**ODIN Data Dictionary v1.0.2** - Comprehensive reference for all 80 intelligence fields extracted from 5 authoritative vulnerability data sources.

*Last Updated: 2025-06-18 | Field Implementation: 100% Complete | Source Coverage: 5 Layers*