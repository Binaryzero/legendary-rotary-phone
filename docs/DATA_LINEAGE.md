# ODIN Data Lineage Documentation

## **Complete Field-by-Field Data Source Mapping**

This document provides comprehensive lineage tracking for every field in ODIN's threat intelligence aggregation system, organized by the 5-layer data architecture.

---

## **Layer 1: Foundational Record (CVEProject/cvelistV5)**

**Data Source**: GitHub CVEProject/cvelistV5 repository - Official CVE JSON 5.0/5.1 format
**Research Value**: Authoritative ground truth for vulnerability descriptions and primary references

| Field Name | Data Type | Source Path | Processing Applied | Research Value | Dependencies |
|------------|-----------|-------------|-------------------|----------------|--------------|
| `cve_id` | String | `containers.cna.CVE_data_meta.ID` | None | Unique vulnerability identifier, essential for all research | None |
| `description` | String | `containers.cna.descriptions[0].value` | Text sanitization | Authoritative vulnerability description from CNA | None |
| `cvss_score` | Float | `containers.{cna,adp}.metrics[*].cvssV3_1.baseScore` | Version fallback (3.1→3.0→2.0) | Numerical severity assessment | CVSS Vector |
| `cvss_vector` | String | `containers.{cna,adp}.metrics[*].cvssV3_1.vectorString` | Version fallback | Complete CVSS metrics for impact analysis | CVSS Score |
| `severity` | String | Computed from `cvss_score` | Score to severity mapping | Human-readable severity classification | CVSS Score |
| `published_date` | ISO DateTime | `containers.cna.datePublic` | ISO format conversion | Timeline context for vulnerability disclosure | None |
| `last_modified` | ISO DateTime | `containers.cna.dateUpdated` | ISO format conversion | Data freshness indicator | None |
| `references` | Array[String] | `containers.cna.references[*].url` | URL validation | Primary sources for deep technical analysis | None |

**Product Intelligence Fields** (Enhanced from CVE JSON affected objects):
| Field Name | Data Type | Source Path | Processing Applied | Research Value | Dependencies |
|------------|-----------|-------------|-------------------|----------------|--------------|
| `product_intelligence.vendors` | Array[String] | `containers.cna.affected[*].vendor` | Vendor extraction + deduplication | Affected vendor identification | CVE ID |
| `product_intelligence.products` | Array[String] | `containers.cna.affected[*].product` | Product extraction + deduplication | Specific product identification | CVE ID |
| `product_intelligence.affected_versions` | Array[String] | `containers.cna.affected[*].versions[*]` | Version range parsing | Granular version impact assessment | CVE ID |
| `product_intelligence.platforms` | Array[String] | `containers.cna.affected[*].platforms[*]` | Platform extraction + normalization | Operating system impact scope | CVE ID |
| `product_intelligence.modules` | Array[String] | `containers.cna.affected[*].modules[*]` | Module extraction + deduplication | Component-level impact analysis | CVE ID |
| `product_intelligence.repositories` | Array[String] | `containers.cna.affected[*].repo` | Repository URL validation | Source code impact tracking | CVE ID |

**CVSS Component Breakdown** (Derived from cvss_vector):
| Field Name | Data Type | Source Path | Processing Applied | Research Value | Dependencies |
|------------|-----------|-------------|-------------------|----------------|--------------|
| `attack_vector` | String | CVSS vector AV component | Component extraction + mapping | Network accessibility requirement for exploitation | CVSS Vector |
| `attack_complexity` | String | CVSS vector AC component | Component extraction + mapping | Technical difficulty of successful exploitation | CVSS Vector |
| `privileges_required` | String | CVSS vector PR component | Component extraction + mapping | Authentication requirements for exploitation | CVSS Vector |
| `user_interaction` | String | CVSS vector UI component | Component extraction + mapping | Human interaction requirements for exploitation | CVSS Vector |
| `scope` | String | CVSS vector S component | Component extraction + mapping | Impact boundary analysis for lateral movement | CVSS Vector |
| `confidentiality_impact` | String | CVSS vector C component | Component extraction + mapping | Data confidentiality compromise assessment | CVSS Vector |
| `integrity_impact` | String | CVSS vector I component | Component extraction + mapping | Data integrity compromise assessment | CVSS Vector |
| `availability_impact` | String | CVSS vector A component | Component extraction + mapping | Service availability compromise assessment | CVSS Vector |

**Quality Notes**: 
- CVE JSON format varies between versions 5.0 and 5.1
- Some CVEs may have multiple CVSS versions, priority: 3.1 > 3.0 > 2.0
- References are the most critical asset, often linking to vendor advisories and original research

---

## **Layer 2: Exploit Mechanics & Validation (trickest/cve)**

**Data Source**: GitHub trickest/cve repository - Markdown files with PoC exploit links
**Research Value**: Practical exploitation validation and attack vector analysis

| Field Name | Data Type | Source Path | Processing Applied | Research Value | Dependencies |
|------------|-----------|-------------|-------------------|----------------|--------------|
| `exploits` | Array[Object] | Markdown files `/{CVE-YYYY-NNNNN}.md` | Markdown parsing, URL extraction | Direct observation of exploit preconditions and attack vectors | CVE ID |
| `exploits[].url` | String | Markdown link URLs | URL validation | Direct link to exploit code | None |
| `exploits[].source` | String | Markdown link domain | Domain extraction | Reputation and reliability of exploit source | None |
| `exploits[].type` | String | URL pattern matching | Type classification | Exploit category (PoC, weaponized, etc.) | None |
| `exploit_maturity` | String | Exploit source analysis | Maturity assessment | Sophistication level: unproven/poc/functional/weaponized | Exploits array |

**Exploit Analysis** (Derived from exploit processing):
| Field Name | Data Type | Source Path | Processing Applied | Research Value | Dependencies |
|------------|-----------|-------------|-------------------|----------------|--------------|
| `exploit_count` | Integer | Exploits array | Count calculation | Quantitative measure of exploit availability | Exploits array |
| `exploit_types` | String | Exploits array type classification | Type aggregation | Categorical analysis of exploit sophistication | Exploits array |
| `exploit_refs` | String | Exploits array URLs | URL aggregation | Consolidated exploit reference listing | Exploits array |
| `technology_stack` | String | Trickest markdown badges | Badge extraction + parsing | Technology context for exploitation prerequisites | Markdown content |
| `fix_version` | String | Reference categorization | Version extraction from patch references | Software version information for remediation | References |

**Quality Notes**:
- Near-continuous updates from Trickest team
- Quality varies by exploit source (Exploit-DB > GitHub PoCs > others)
- Exploit maturity derived from source analysis and code sophistication

---

## **Layer 3: Weakness & Tactic Classification (mitre/cti)**

**Data Source**: MITRE CTI STIX bundles - ATT&CK and CAPEC knowledge bases
**Research Value**: Systematic attack pattern classification and control development

| Field Name | Data Type | Source Path | Processing Applied | Research Value | Dependencies |
|------------|-----------|-------------|-------------------|----------------|--------------|
| `weakness.cwe_ids` | Array[String] | CWE database mapping | CWE ID extraction | Weakness classification for control development | CVE ID |
| `weakness.capec_ids` | Array[String] | CAPEC→CWE mapping | Pattern matching | Known attack patterns dictionary | CWE IDs |
| `weakness.attack_techniques` | Array[String] | ATT&CK→CAPEC mapping | Technique extraction | Adversary tactics for compensating controls | CAPEC IDs |
| `weakness.attack_tactics` | Array[String] | ATT&CK framework | Tactic classification | Broader adversary strategy understanding | Attack Techniques |
| `weakness.kill_chain_phases` | Array[String] | Cyber Kill Chain mapping | Phase classification | Attack lifecycle positioning | Attack Techniques |

**Quality Notes**:
- Mapping quality depends on CWE classification accuracy
- Some CVEs may lack structured CWE data
- CAPEC→ATT&CK mappings provide systematic control framework

---

## **Layer 4: Real-World Threat Context**

### **CVSS-BT Source (t0sche/cvss-bt)**
**Data Source**: Single CSV file with CISA KEV, Metasploit, Nuclei data
**Research Value**: Active exploitation evidence and weaponized exploit availability

| Field Name | Data Type | Source Path | Processing Applied | Research Value | Dependencies |
|------------|-----------|-------------|-------------------|----------------|--------------|
| `threat.in_kev` | Boolean | `cisa_kev` column | Boolean conversion | Definitive proof of active exploitation | CVE ID |
| `threat.has_metasploit` | Boolean | `metasploit` column | Boolean conversion | Reliable weaponized exploit existence | CVE ID |
| `threat.has_nuclei` | Boolean | `nuclei` column | Boolean conversion | Automated scanning template availability | CVE ID |
| `threat.ransomware_campaign` | Boolean | `ransomware_use` column | Boolean conversion | Ransomware campaign intelligence | CVE ID |
| `threat.kev_vulnerability_name` | String | `kev_name` column | Text cleaning | CISA official vulnerability name | KEV Status |
| `threat.kev_short_description` | String | `kev_description` column | Text cleaning | CISA vulnerability description | KEV Status |
| `threat.kev_vendor_project` | String | `kev_vendor` column | Text cleaning | Vendor/project identification | KEV Status |
| `threat.kev_product` | String | `kev_product` column | Text cleaning | Specific product affected | KEV Status |

### **ARPSyndicate Source (ARPSyndicate/cve-scores)**
**Data Source**: CSV/JSON files with EPSS and VEDAS scores
**Research Value**: Data-driven exploitation probability and community interest signals

| Field Name | Data Type | Source Path | Processing Applied | Research Value | Dependencies |
|------------|-----------|-------------|-------------------|----------------|--------------|
| `threat.epss_score` | Float | `epss_score` column | Float conversion | Data-driven exploitation probability | CVE ID |
| `threat.epss_percentile` | Float | `epss_percentile` column | Percentile calculation | Relative risk ranking | EPSS Score |
| `threat.vedas_score` | Float | `vedas_score` column | Float conversion | Community vulnerability interest measurement | CVE ID |
| `threat.vedas_percentile` | Float | `vedas_percentile` column | Percentile calculation | Relative community interest ranking | VEDAS Score |
| `threat.vedas_score_change` | Float | `vedas_score_change` column | Delta calculation | Trending vulnerability analysis | VEDAS Score |
| `threat.vedas_detail_url` | String | `vedas_detail_url` column | URL validation | Link to detailed VEDAS analysis | CVE ID |
| `threat.vedas_date` | String | `vedas_date` column | Date formatting | VEDAS score calculation timestamp | CVE ID |
| `threat.actively_exploited` | Boolean | EPSS threshold analysis | Threshold-based classification | Active exploitation indicator | EPSS Score |

**Additional Threat Intelligence** (From CVSS-BT source):
| Field Name | Data Type | Source Path | Processing Applied | Research Value | Dependencies |
|------------|-----------|-------------|-------------------|----------------|--------------|
| `threat.temporal_score` | Float | `temporal_score` column | Float conversion | Time-sensitive CVSS risk assessment | CVE ID |
| `threat.exploit_code_maturity` | String | `exploit_code_maturity` column | Text normalization | Exploit sophistication level tracking | CVE ID |
| `threat.remediation_level` | String | `remediation_level` column | Text normalization | Fix availability status indication | CVE ID |
| `threat.report_confidence` | String | `report_confidence` column | Text normalization | Intelligence confidence assessment | CVE ID |
| `threat.vulncheck_kev` | Boolean | `vulncheck_kev` column | Boolean conversion | VulnCheck KEV catalog inclusion | CVE ID |
| `threat.has_exploitdb` | Boolean | `exploitdb` column | Boolean conversion | Exploit Database availability indicator | CVE ID |
| `threat.has_poc_github` | Boolean | `poc_github` column | Boolean conversion | GitHub proof-of-concept availability | CVE ID |

**Quality Notes**:
- EPSS scores updated daily by FIRST.org
- VEDAS scores provide "present popularity" intelligence
- KEV inclusion is definitive proof of real-world exploitation

---

## **Layer 5: Raw Intelligence Toolkit (Patrowl/PatrowlHearsData)**

**Data Source**: Structured feeds and scraping scripts for CVE, CPE, CWE data
**Research Value**: Comprehensive correlation and enhanced metadata

| Field Name | Data Type | Source Path | Processing Applied | Research Value | Dependencies |
|------------|-----------|-------------|-------------------|----------------|--------------|
| `cpe_affected` | String | `configurations[*].nodes[*].cpeMatch[*].criteria` | CPE parsing | Affected platform identification | CVE ID |
| `vendor_advisories` | Array[String] | Reference URL classification | Advisory pattern matching | Vendor security advisory links | References |
| `patches` | Array[String] | Reference URL classification | Patch pattern matching | Fix and remediation links | References |
| `last_enriched` | ISO DateTime | Processing timestamp | Current timestamp | Data freshness tracking | None |

**Intelligence Metrics** (Derived from Layer 5 processing):
| Field Name | Data Type | Source Path | Processing Applied | Research Value | Dependencies |
|------------|-----------|-------------|-------------------|----------------|--------------|
| `reference_count` | Integer | References array | Count calculation | Volume of available intelligence sources | References |
| `cpe_affected_count` | Integer | CPE affected array | Count calculation | Scope of platform impact assessment | CPE data |
| `vendor_advisory_count` | Integer | Vendor advisories array | Count calculation | Official vendor response availability | Vendor Advisories |
| `patch_reference_count` | Integer | Patches array | Count calculation | Remediation resource availability | Patches |
| `affected` | String | CPE processing | CPE to readable format | Human-readable affected platforms | CPE Affected |
| `mitigations` | String | Reference categorization | Mitigation extraction | Available workaround and mitigation strategies | References |

**Enhanced Problem Type Analysis** (Derived from Patrowl processing):
| Field Name | Data Type | Source Path | Processing Applied | Research Value | Dependencies |
|------------|-----------|-------------|-------------------|----------------|--------------|
| `enhanced_problem_type.primary_weakness` | String | CWE classification | Primary CWE extraction | Main vulnerability weakness | CWE Data |
| `enhanced_problem_type.secondary_weaknesses` | String | CWE classification | Secondary CWE extraction | Additional weaknesses | CWE Data |
| `enhanced_problem_type.vulnerability_categories` | String | CWE categorization | Category mapping | High-level vulnerability classification | CWE Data |
| `enhanced_problem_type.impact_types` | String | Impact analysis | Impact classification | Potential security impacts | CWE Data |
| `enhanced_problem_type.attack_vectors` | String | Vector analysis | Vector classification | Attack delivery methods | CWE Data |
| `enhanced_problem_type.enhanced_cwe_details` | String | CWE processing | Structured CWE information | Comprehensive weakness details | CWE Data |

**NIST 800-53 Control Mapping** (Derived from MITRE mappings):
| Field Name | Data Type | Source Path | Processing Applied | Research Value | Dependencies |
|------------|-----------|-------------|-------------------|----------------|--------------|
| `control_mappings.applicable_controls_count` | Integer | MITRE control mappings | Count calculation | Control recommendation scope | ATT&CK Techniques |
| `control_mappings.control_categories` | String | NIST 800-53 categories | Category aggregation | Control family recommendations | ATT&CK Techniques |
| `control_mappings.top_controls` | String | Control priority ranking | Priority assessment | Key control recommendations | ATT&CK Techniques |

---

## **Data Dependencies & Processing Flow**

### **Layer Dependencies**:
- **Enhanced Problem Type** → Requires CWE data from Patrowl processing
- **Control Mappings** → Requires ATT&CK techniques from MITRE framework analysis
- **Threat Context** → Aggregated from multiple independent sources with varying data quality
- **All Layers** → Depend on foundational CVE ID from Layer 1 for correlation

### **Processing Pipeline**:
1. **CVE ID Input** → Triggers data collection across all layers
2. **Layer 1 (Foundation)** → Establishes authoritative base record
3. **Layer 2 (Validation)** → Adds practical exploitation evidence
4. **Layer 3 (Classification)** → Provides systematic categorization
5. **Layer 4 (Context)** → Enriches with real-world threat intelligence
6. **Layer 5 (Correlation)** → Adds comprehensive metadata and cross-references

### **Data Transformation Flow**:
```
CVE-ID → CVE JSON → Parsed Fields → Enriched Data → Structured Output
    ↓
Layer Processing → Field Mapping → Export Generation → API Response
```

### **Research Workflow Integration**:
Each layer answers a specific research question:
1. **Foundation** → What is the vulnerability?
2. **Validation** → How is it exploited?
3. **Classification** → What type of attack is this?
4. **Context** → Is it being exploited in the wild?
5. **Correlation** → How does it relate to other intelligence?

This systematic data lineage enables comprehensive vulnerability intelligence aggregation and structured research workflows.