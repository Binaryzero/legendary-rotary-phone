# ODIN Data Source Schema Documentation

## **Comprehensive Field Analysis Across All Data Sources**

This document provides detailed schemas for all data sources used by ODIN, documenting every available field to identify extraction opportunities and missing intelligence.

---

## **CVEProject/cvelistV5 - Complete JSON Schema**

**Repository**: https://github.com/CVEProject/cvelistV5
**Format**: JSON 5.0/5.1
**Update Frequency**: Every 7 minutes

### **Root Level Fields**
| Field Name | Data Type | Currently Extracted | Research Value | Notes |
|------------|-----------|-------------------|----------------|-------|
| `dataType` | String | No | Schema validation | Always "CVE_RECORD" |
| `dataVersion` | String | No | Version tracking | "5.0" or "5.1" |
| `cveMetadata` | Object | Partial | Core CVE data | Contains ID, state, dates |
| `containers` | Object | Partial | All vulnerability data | CNA, ADP, and CVE Program containers |

### **cveMetadata Fields**
| Field Name | Data Type | Currently Extracted | Research Value | Notes |
|------------|-----------|-------------------|----------------|-------|
| `cveId` | String | Yes | Primary identifier | CVE-YYYY-NNNNN format |
| `assignerOrgId` | String | No | Assigner identification | Organization UUID |
| `assignerShortName` | String | No | Assigner name | Human-readable org name |
| `state` | String | No | CVE lifecycle status | PUBLISHED, REJECTED, etc. |
| `requesterUserId` | String | No | Request tracking | Internal workflow data |
| `datePublished` | ISO DateTime | Yes | Publication timeline | Public disclosure date |
| `dateReserved` | ISO DateTime | No | Reservation tracking | Internal workflow date |
| `dateUpdated` | ISO DateTime | Yes | Freshness indicator | Last modification date |
| `serial` | Integer | No | Version tracking | Incremental update counter |

### **CNA Container Fields**
| Field Name | Data Type | Currently Extracted | Research Value | Notes |
|------------|-----------|-------------------|----------------|-------|
| `providerMetadata` | Object | No | Source attribution | CNA organization details |
| `title` | String | No | Vulnerability title | Often more descriptive than ID |
| `descriptions` | Array[Object] | Yes | Core vulnerability info | Primary intelligence source |
| `affected` | Array[Object] | Partial | Affected products | Detailed product/version data |
| `problemTypes` | Array[Object] | Yes | CWE classification | Weakness categorization |
| `references` | Array[Object] | Partial | External sources | Enhanced with tags and types |
| `impacts` | Array[Object] | No | Impact assessment | Detailed impact scenarios |
| `metrics` | Array[Object] | Partial | CVSS data | Multiple scoring systems |
| `configurations` | Array[Object] | Partial | CPE data | Affected configurations |
| `workarounds` | Array[Object] | No | Mitigation strategies | Temporary fixes |
| `solutions` | Array[Object] | No | Permanent fixes | Official remediation |
| `exploits` | Array[Object] | No | Official exploit data | CNA-provided exploit info |
| `timeline` | Array[Object] | No | Event timeline | Detailed event history |
| `credits` | Array[Object] | No | Attribution data | Researcher credits |
| `source` | Object | No | Discovery context | How vulnerability was found |
| `tags` | Array[String] | No | Classification tags | Additional categorization |

### **ADP Container Fields (CISA and others)**
| Field Name | Data Type | Currently Extracted | Research Value | Notes |
|------------|-----------|-------------------|----------------|-------|
| `providerMetadata` | Object | No | ADP source info | Third-party enrichment source |
| `title` | String | No | ADP-specific title | Alternative vulnerability naming |
| `descriptions` | Array[Object] | No | Additional descriptions | Supplementary intelligence |
| `affected` | Array[Object] | No | ADP affected products | Additional product mappings |
| `references` | Array[Object] | No | ADP references | Additional intelligence sources |
| `metrics` | Array[Object] | No | ADP CVSS scores | Alternative/additional scoring |
| `problemTypes` | Array[Object] | No | ADP CWE data | Enhanced weakness classification |
| `impacts` | Array[Object] | No | ADP impact assessment | Third-party impact analysis |

### **CVE Program Container Fields**
| Field Name | Data Type | Currently Extracted | Research Value | Notes |
|------------|-----------|-------------------|----------------|-------|
| `title` | String | No | Official CVE title | "CVE Program Container" |
| `providerMetadata` | Object | No | CVE Program metadata | Official program attribution |
| `references` | Array[Object] | No | Program references | Additional official sources |

### **Reference Object Fields (Enhanced)**
| Field Name | Data Type | Currently Extracted | Research Value | Notes |
|------------|-----------|-------------------|----------------|-------|
| `url` | String | Yes | Reference link | Direct URL access |
| `name` | String | No | Reference title | Human-readable name |
| `tags` | Array[String] | No | Reference categorization | exploit, patch, advisory, etc. |
| `type` | String | No | Reference type | Structured categorization |

### **Affected Object Fields (Detailed)**
| Field Name | Data Type | Currently Extracted | Research Value | Notes |
|------------|-----------|-------------------|----------------|-------|
| `vendor` | String | No | Vendor identification | Product manufacturer |
| `product` | String | No | Product name | Specific software/hardware |
| `collectionURL` | String | No | Product information | Official product page |
| `packageName` | String | No | Package identifier | Language-specific packages |
| `cpes` | Array[String] | Partial | CPE identifiers | Structured product IDs |
| `modules` | Array[String] | No | Module names | Specific components |
| `programFiles` | Array[String] | No | File paths | Affected file locations |
| `programRoutines` | Array[Object] | No | Function details | Specific code functions |
| `platforms` | Array[String] | No | Platform support | Operating systems |
| `repo` | String | No | Repository URL | Source code location |
| `versions` | Array[Object] | No | Version details | Detailed version impact |

---

## **Trickest/CVE - Markdown Format Schema**

**Repository**: https://github.com/trickest/cve
**Format**: Markdown with badges
**Update Frequency**: Continuous automated updates

### **Markdown Structure Fields**
| Field Name | Data Type | Currently Extracted | Research Value | Notes |
|------------|-----------|-------------------|----------------|-------|
| `cve_identifier` | String (Title) | Yes | Primary ID | H1 markdown title |
| `severity_badges` | Array[String] | Partial | Visual severity | shields.io badge URLs |
| `version_badges` | Array[String] | No | Affected versions | Software version indicators |
| `exploit_availability` | Array[String] | No | Exploit status | PoC availability badges |
| `product_badges` | Array[String] | Partial | Product context | Technology stack indicators |
| `cwe_badges` | Array[String] | Partial | Weakness classification | CWE categorization badges |
| `poc_links` | Array[String] | Yes | Exploit references | Direct PoC URLs |
| `reference_links` | Array[String] | Partial | Additional sources | General reference URLs |
| `advisory_links` | Array[String] | No | Vendor advisories | Official advisory URLs |
| `description_text` | String | Partial | Markdown description | Formatted vulnerability info |
| `publication_date` | String | No | Date metadata | File modification date |
| `update_history` | Array[String] | No | Change tracking | Git commit history |

### **Badge Extraction Opportunities**
| Badge Type | shields.io Format | Currently Extracted | Research Value |
|------------|------------------|-------------------|----------------|
| Severity | `![Severity](URL)` | Partial | Visual severity mapping |
| CVSS Score | `![CVSS](URL)` | No | Alternative CVSS source |
| Product | `![Product](URL)` | Partial | Technology identification |
| CWE | `![CWE](URL)` | Partial | Weakness classification |
| Version | `![Version](URL)` | No | Affected version ranges |
| Status | `![Status](URL)` | No | Exploit maturity status |

---

## **t0sche/cvss-bt - Complete CSV Schema**

**Repository**: https://github.com/t0sche/cvss-bt
**Format**: CSV with daily updates
**Update Frequency**: Daily

### **CSV Column Fields**
| Field Name | Data Type | Currently Extracted | Research Value | Notes |
|------------|-----------|-------------------|----------------|-------|
| `cve` | String | Yes | Primary identifier | CVE-YYYY-NNNNN |
| `base_score` | Float | No | Base CVSS score | Alternative to NVD |
| `cvss_version` | String | No | CVSS version | 2.0, 3.0, 3.1 |
| `cvss_vector` | String | Yes | Vector string | Complete CVSS metrics |
| `temporal_score` | Float | No | Temporal CVSS | Time-sensitive scoring |
| `exploit_code_maturity` | String | No | Temporal metric | U/P/F/H/A values |
| `remediation_level` | String | No | Temporal metric | Fix availability |
| `report_confidence` | String | No | Temporal metric | Confidence level |
| `cisa_kev` | Boolean | Yes | KEV status | CISA exploitation |
| `vulncheck_kev` | Boolean | Yes | VulnCheck KEV | Alternative KEV source |
| `epss_score` | Float | Yes | EPSS probability | Exploitation prediction |
| `epss_percentile` | Float | Yes | EPSS ranking | Relative risk |
| `metasploit` | Boolean | Yes | Metasploit availability | Weaponized exploits |
| `nuclei` | Boolean | Yes | Nuclei templates | Scanning availability |
| `exploitdb` | Boolean | Yes | ExploitDB presence | Public exploits |
| `poc_github` | Boolean | Yes | GitHub PoCs | Proof-of-concept code |
| `ransomware_use` | Boolean | Yes | Ransomware campaigns | Criminal exploitation |
| `kev_name` | String | Yes | KEV vulnerability name | Official CISA name |
| `kev_description` | String | Partial | KEV description | CISA description |
| `kev_vendor` | String | Yes | KEV vendor | Affected vendor |
| `kev_product` | String | Yes | KEV product | Affected product |
| `kev_date_added` | Date | No | KEV addition date | Timeline tracking |
| `kev_due_date` | Date | No | KEV remediation deadline | Compliance tracking |
| `first_seen` | Date | No | First observation | Discovery timeline |
| `last_seen` | Date | No | Recent observation | Activity tracking |
| `assigner` | String | No | CVE assigner | Attribution data |
| `published_date` | Date | Yes | Publication date | Official disclosure |

---

## **ARPSyndicate/cve-scores - Complete Data Schema**

**Repository**: https://github.com/ARPSyndicate/cve-scores
**Format**: CSV/JSON with EPSS and VEDAS scores
**Update Frequency**: EPSS (24h), VEDAS (6-8h)

### **Main Data Fields**
| Field Name | Data Type | Currently Extracted | Research Value | Notes |
|------------|-----------|-------------------|----------------|-------|
| `cve` | String | Yes | Primary identifier | CVE-YYYY-NNNNN |
| `epss_score` | Float | Yes | EPSS probability | 0.0-1.0 scale |
| `epss_percentile` | Float | Yes | EPSS ranking | 0.0-1.0 percentile |
| `epss_date` | Date | No | Score date | Temporal tracking |
| `vedas_score` | Float | No | VEDAS prevalence | Community interest |
| `vedas_percentile` | Float | No | VEDAS ranking | Relative prevalence |
| `vedas_date` | Date | No | VEDAS date | Update tracking |
| `vedas_detail_url` | String | No | Detailed analysis | vedas.arpsyndicate.io link |

### **Differential Data Fields**
| Field Name | Data Type | Currently Extracted | Research Value | Notes |
|------------|-----------|-------------------|----------------|-------|
| `epss_score_change` | Float | No | Score delta | Trending analysis |
| `epss_percentile_change` | Float | No | Percentile delta | Rank movement |
| `vedas_score_change` | Float | No | VEDAS delta | Interest trending |
| `vedas_percentile_change` | Float | No | VEDAS rank change | Popularity shifts |
| `change_date` | Date | No | Change timestamp | Trend timeline |
| `change_magnitude` | String | No | Change significance | Large/medium/small |

### **Extended Identifier Support**
| Identifier Type | Currently Extracted | Research Value | Notes |
|----------------|-------------------|----------------|-------|
| CVE | Yes | Primary vulnerability ID | Standard format |
| EUVD | No | EU vulnerability database | European sources |
| CNNVD | No | Chinese vulnerability DB | Chinese sources |
| BDU | No | Russian vulnerability DB | Russian sources |
| Others (50+ types) | No | Global coverage | International sources |

---

## **Patrowl/PatrowlHearsData - Complete Structure Schema**

**Repository**: https://github.com/Patrowl/PatrowlHearsData
**Format**: Multiple structured data formats
**Update Frequency**: Regular automated updates

### **CVE Directory Schema**
| Field Name | Data Type | Currently Extracted | Research Value | Notes |
|------------|-----------|-------------------|----------------|-------|
| `cve_id` | String | Yes | Primary identifier | Standard CVE format |
| `description` | String | Yes | Vulnerability description | Enhanced descriptions |
| `cvss_score` | Float | Yes | CVSS scoring | Multiple versions |
| `cvss_vector` | String | Yes | Vector string | Complete metrics |
| `cwe_ids` | Array[String] | Yes | Weakness classification | CWE mappings |
| `cpe_ids` | Array[String] | Partial | Platform enumeration | Affected platforms |
| `references` | Array[Object] | Partial | Reference sources | Enhanced references |
| `exploits` | Array[Object] | Partial | Exploit information | Structured exploit data |
| `patches` | Array[Object] | Partial | Patch information | Remediation data |
| `vendor_advisories` | Array[Object] | Partial | Official advisories | Vendor communications |
| `attack_patterns` | Array[String] | No | CAPEC patterns | Attack methodologies |
| `threat_actors` | Array[String] | No | Attribution data | Threat actor tracking |
| `malware_families` | Array[String] | No | Malware associations | Malware correlations |
| `iocs` | Array[Object] | No | Indicators of compromise | Detection signatures |

### **CPE Directory Schema**
| Field Name | Data Type | Currently Extracted | Research Value | Notes |
|------------|-----------|-------------------|----------------|-------|
| `cpe_id` | String | Partial | Platform identifier | Structured product ID |
| `vendor` | String | No | Product vendor | Manufacturer name |
| `product` | String | No | Product name | Software/hardware name |
| `version` | String | No | Product version | Specific version |
| `update` | String | No | Update level | Patch level |
| `edition` | String | No | Product edition | Edition/variant |
| `language` | String | No | Product language | Localization |
| `sw_edition` | String | No | Software edition | Software-specific |
| `target_sw` | String | No | Target software | Platform dependency |
| `target_hw` | String | No | Target hardware | Hardware dependency |
| `other` | String | No | Additional attributes | Extended metadata |

### **CWE Directory Schema**
| Field Name | Data Type | Currently Extracted | Research Value | Notes |
|------------|-----------|-------------------|----------------|-------|
| `cwe_id` | String | Yes | Weakness identifier | CWE-NNNN format |
| `name` | String | Partial | Weakness name | Human-readable name |
| `description` | String | Partial | Detailed description | Technical explanation |
| `extended_description` | String | No | Extended details | Comprehensive info |
| `related_weaknesses` | Array[String] | No | Related CWEs | Weakness relationships |
| `weakness_ordinalities` | Array[String] | No | Ordinality classification | Primary/resultant |
| `applicable_platforms` | Array[String] | No | Platform applicability | Technology relevance |
| `background_details` | String | No | Background context | Historical information |
| `alternate_terms` | Array[String] | No | Alternative names | Synonym tracking |
| `modes_of_introduction` | Array[Object] | No | Introduction vectors | How weakness occurs |
| `likelihood_of_exploit` | String | No | Exploitation likelihood | Risk assessment |
| `common_consequences` | Array[Object] | No | Impact scenarios | Potential outcomes |
| `detection_methods` | Array[Object] | No | Detection strategies | Identification methods |
| `potential_mitigations` | Array[Object] | No | Mitigation strategies | Prevention methods |

### **VIA (Vulnerability Intelligence Aggregation) Schema**
| Field Name | Data Type | Currently Extracted | Research Value | Notes |
|------------|-----------|-------------------|----------------|-------|
| `vulnerability_id` | String | Partial | Cross-reference ID | Multi-format support |
| `intelligence_sources` | Array[String] | No | Source attribution | Data provenance |
| `confidence_score` | Float | No | Intelligence confidence | Data reliability |
| `correlation_data` | Object | No | Cross-correlation | Related vulnerabilities |
| `enrichment_metadata` | Object | No | Processing metadata | Enhancement tracking |
| `geolocation_data` | Object | No | Geographic context | Regional relevance |
| `industry_impact` | Array[String] | No | Sector impact | Industry targeting |
| `campaign_associations` | Array[String] | No | Campaign tracking | Attack campaign links |
| `temporal_indicators` | Object | No | Time-based analysis | Temporal patterns |

---

## **FIRST.org EPSS API - Complete Response Schema**

**API Endpoint**: https://api.first.org/data/v1/epss
**Format**: JSON API responses
**Update Frequency**: Daily

### **Standard Response Fields**
| Field Name | Data Type | Currently Extracted | Research Value | Notes |
|------------|-----------|-------------------|----------------|-------|
| `cve` | String | Yes | Primary identifier | CVE-YYYY-NNNNN |
| `epss` | Float | Yes | EPSS probability score | 0.0-1.0 range |
| `percentile` | Float | Yes | Percentile ranking | 0.0-1.0 range |
| `date` | Date | No | Score date | Daily timestamp |

### **Time-Series Response Fields**
| Field Name | Data Type | Currently Extracted | Research Value | Notes |
|------------|-----------|-------------------|----------------|-------|
| `cve` | String | No | Primary identifier | Historical tracking |
| `epss_history` | Array[Object] | No | Historical scores | Trend analysis |
| `percentile_history` | Array[Object] | No | Historical percentiles | Rank tracking |
| `date_range` | Object | No | Time span | Analysis period |
| `score_variance` | Float | No | Score stability | Volatility measure |
| `trend_direction` | String | No | Trend analysis | Increasing/decreasing |
| `peak_score` | Float | No | Maximum score | Historical peak |
| `peak_date` | Date | No | Peak timestamp | Peak occurrence |

### **Metadata Fields**
| Field Name | Data Type | Currently Extracted | Research Value | Notes |
|------------|-----------|-------------------|----------------|-------|
| `model_version` | String | No | EPSS model version | Model tracking |
| `score_generation_date` | Date | No | Score creation date | Freshness indicator |
| `data_sources` | Array[String] | No | Source attribution | Data provenance |
| `confidence_interval` | Object | No | Statistical confidence | Score reliability |
| `methodology_version` | String | No | Scoring methodology | Approach tracking |

### **Envelope Response Fields**
| Field Name | Data Type | Currently Extracted | Research Value | Notes |
|------------|-----------|-------------------|----------------|-------|
| `status` | String | No | Request status | API response status |
| `status_code` | Integer | No | HTTP status | Error handling |
| `total` | Integer | No | Total results | Pagination info |
| `offset` | Integer | No | Current offset | Pagination tracking |
| `limit` | Integer | No | Result limit | Pagination size |
| `data` | Array[Object] | Partial | Actual EPSS data | Core response data |

---

## **Summary of Missing Field Opportunities**

### **High-Value Missing Fields (Immediate Implementation)**
1. **VEDAS scores** from ARPSyndicate (vulnerability prevalence)
2. **Temporal CVSS metrics** from cvss-bt (exploit code maturity)
3. **Enhanced reference categorization** from CVE JSON (tags, types)
4. **VIA intelligence aggregation** from Patrowl (correlation data)
5. **Historical EPSS data** from FIRST API (trend analysis)

### **Medium-Value Missing Fields (Future Enhancement)**
1. **Multiple CVSS versions** from CVE JSON
2. **ADP container enrichments** (CISA SSVC data)
3. **Detailed affected product data** from CVE JSON
4. **Enhanced CWE metadata** from Patrowl
5. **Badge-based technology stack** from Trickest

### **Low-Priority Missing Fields (Optional)**
1. **CVE workflow metadata** (assigners, timeline)
2. **Alternative identifier systems** (EUVD, CNNVD, BDU)
3. **Geolocation intelligence** from VIA
4. **Campaign association data** from Patrowl
5. **Statistical confidence intervals** from EPSS API

**Total Identified Missing Fields: 75+ high-value intelligence fields across all data sources**