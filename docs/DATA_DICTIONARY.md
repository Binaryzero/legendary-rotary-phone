# ODIN Data Dictionary

## **ODIN (OSINT Data Intelligence Nexus) - Data Layer Architecture**

ODIN implements a systematic threat intelligence aggregation workflow through structured research layers. This file describes the data fields and sources used in ODIN's comprehensive vulnerability intelligence packages.

## **Data Layer Structure**

| Data Source (Repository) | Research Layer | Data Provided | Value to a Vulnerability Researcher (Why it's useful) |
| :--- | :--- | :--- | :--- |
| **`CVEProject/cvelistV5`** | **1. Foundational Record** | The official, canonical CVE list in structured CVE JSON 5.0/5.1 format. Contains the authoritative description, CVSS base metrics, and, most importantly, primary references from the CVE Numbering Authority (CNA). | This is the non-negotiable starting point. It provides the ground-truth description of the flaw. The **references** are the most critical asset here, often linking directly to vendor security advisories, bug tracker entries, or the original researcher's disclosure, which are the primary sources for deep technical analysis. |
| **`trickest/cve`** | **2. Exploit Mechanics & Validation** | A comprehensive, near-continuously updated collection of links to publicly available Proof-of-Concept (PoC) exploit code, organized in human-readable markdown files. | This is where you move from theory to practice. Analyzing the PoC code allows you to directly observe the **preconditions** for an exploit, understand the specific **attack vector**, and validate the practical **impact** (e.g., remote code execution vs. denial of service). It is the most direct way to understand how a vulnerability is actually exploited in the wild. |
| **`mitre/cti`** | **3. Weakness & Tactic Classification** | The complete MITRE ATT&CK (Adversary Tactics, Techniques, and Common Knowledge) and CAPEC (Common Attack Pattern Enumeration and Classification) knowledge bases, expressed in structured STIX 2.0 format. | This resource is essential for classifying the vulnerability and developing robust mitigating controls. **CAPEC** provides a dictionary of known attack patterns, helping you understand *how* the weakness is exploited in a standardized way. **ATT&CK** describes the broader adversary tactics, which helps in formulating theoretical compensating controls that address the entire class of attack, not just this single CVE instance. |
| **`t0sche/cvss-bt`** | **4. Real-World Threat Context** | A single, machine-readable CSV file that enriches CVEs with data from sources like the CISA KEV catalog, Metasploit, and Nuclei templates. | While you don't prioritize, this data provides critical research context. A flag indicating a CVE is in the **CISA Known Exploited Vulnerabilities (KEV) catalog** is definitive proof of active, in-the-wild exploitation. The presence of a **Metasploit module** or **Nuclei template** signifies that a reliable, weaponized exploit exists, which informs your analysis of the risk and the ease of exploitation. |
| **`ARPSyndicate/cve-scores`** | **4. Real-World Threat Context** | Machine-readable CSV and JSON files containing EPSS (Exploit Prediction Scoring System) scores and the proprietary VEDAS (Vulnerability & Exploit Data Aggregation System) score for CVEs. | This offers two distinct signals for your risk analysis. The **EPSS score** provides a data-driven probability that a flaw will be exploited. The **VEDAS score**, which measures "present popularity" by monitoring broad OSINT sources, can indicate if a vulnerability is being actively discussed or traded in hacker communities, providing crucial qualitative intelligence about adversary interest. |
| **`Patrowl/PatrowlHearsData`** | **5. Raw Intelligence Toolkit** | A collection of raw data feeds and scraping scripts for CVE, CPE (Common Platform Enumeration), CWE (Common Weakness Enumeration), CISA KEV, and EPSS, organized in separate folders. | This repository is a toolkit for building your own custom research database. It gathers the essential FOSS intelligence feeds into one location, allowing you to create your own correlated view by linking a CVE to its underlying weakness type (**CWE**), affected platforms (**CPE**), and real-world exploitation data (**KEV**, **EPSS**). |

---

## **ODIN Export Fields**

This section describes each column exported to CSV/Excel output by ODIN's threat intelligence aggregation process.

## Core CVE Fields
| Column Name   | Description                                                                                 |
|---------------|---------------------------------------------------------------------------------------------| 
| CVE ID        | The unique identifier for the vulnerability (e.g., CVE-2021-44228).                         |
| Description   | The brief summary of the vulnerability as provided in the CVE metadata.                    |
| CVSS          | Base score (CVSS v3.x, or fallback for older CVEs) indicating numerical severity.           |
| Severity      | Computed severity tier mapped from CVSS: None / Low / Medium / High / Critical.            |
| Vector        | The CVSS vector string detailing attack characteristics and impact metrics.               |
| CWE           | Common Weakness Enumeration identifier(s) and description(s) for the underlying issue.     |
| Exploit       | "Yes" if a public exploit was discovered; otherwise "No".                                |
| ExploitRefs   | URLs for actual public exploit references (Exploit-DB, GitHub PoCs, Packet Storm, etc). Excludes CVE reference pages. |
| FixVersion    | URL tagged "upgrade" indicating fixed or upgrade guidance, if available.                  |
| Mitigations   | URLs for advisories or bulletins providing mitigation guidance.                            |
| Affected      | Vendor, product, and version(s) strings of affected software (semicolon-separated).         |
| References    | All collected reference URLs (comma-separated).                                            |

## CVSS Metric Breakdown
| Column Name             | Description                               |
|-------------------------|-------------------------------------------|
| Attack Vector           | CVSS Attack Vector (Network, Adjacent, Local, Physical)|
| Attack Complexity       | CVSS Attack Complexity (Low, High)        |
| Privileges Required     | CVSS Privileges Required (None, Low, High). Maps CVSS v2 Auth to v3 PR. |
| User Interaction        | CVSS User Interaction (None, Required)          |
| Scope                   | CVSS Scope (Unchanged, Changed)                      |
| Confidentiality Impact  | CVSS Confidentiality impact (None, Low, High)  |
| Integrity Impact        | CVSS Integrity impact (None, Low, High)        |
| Availability Impact     | CVSS Availability impact (None, Low, High)     |

## Exploit Intelligence Fields
| Column Name     | Description                                                           |
|-----------------|-----------------------------------------------------------------------|
| Exploit Count   | Number of actual exploit URLs found (excludes CVE reference pages)   |
| Exploit Maturity| Maturity level: unproven, poc, functional, weaponized                |
| Exploit Types   | Types of exploits found (exploit-db, github-poc, packetstorm, etc)   |

## Threat Intelligence Fields
| Column Name        | Description                                                        |
|--------------------|--------------------------------------------------------------------|
| CISA KEV          | "Yes" if listed in CISA Known Exploited Vulnerabilities catalog   |
| VulnCheck KEV     | "Yes" if listed in VulnCheck KEV catalog                          |
| EPSS Score        | Exploit Prediction Scoring System score (0.0-1.0)                |
| EPSS Percentile   | EPSS percentile ranking (0.0-100.0)                               |
| VEDAS Score       | Vulnerability & Exploit Data Aggregation System score (0.0-1.0)   |
| VEDAS Percentile  | VEDAS percentile ranking (0.0-100.0)                              |
| VEDAS Score Change| Change in VEDAS score indicating trending interest                 |
| VEDAS Detail URL  | Link to detailed VEDAS analysis on vedas.arpsyndicate.io          |
| VEDAS Date        | Date of VEDAS score calculation                                    |
| Temporal CVSS Score| Time-adjusted CVSS score considering exploit maturity             |
| Exploit Code Maturity| CVSS temporal metric: Unproven/POC/Functional/High               |
| Remediation Level | CVSS temporal metric: Official Fix/Temporary Fix/Workaround/Unavailable |
| Report Confidence | CVSS temporal metric: Unknown/Reasonable/Confirmed                 |
| Actively Exploited| "Yes" if evidence of active exploitation in the wild              |
| Has Metasploit    | "Yes" if Metasploit module exists                                 |
| Has Nuclei        | "Yes" if Nuclei template exists                                    |
| Ransomware Campaign| "Yes" if used in ransomware campaigns                            |
| KEV Vulnerability Name| Official CISA KEV vulnerability name                             |
| KEV Short Description| CISA KEV description                                             |
| KEV Vendor Project| CISA KEV vendor/project information                               |
| KEV Product       | CISA KEV product information                                       |

## Weakness & Attack Classification (MITRE)
| Column Name       | Description                                           |
|-------------------|-------------------------------------------------------|
| CAPEC IDs         | Common Attack Pattern Enumeration IDs - currently blank |
| Attack Techniques | MITRE ATT&CK technique IDs - currently blank         |
| Attack Tactics    | MITRE ATT&CK tactic names - currently blank          |

## Product Intelligence Fields
| Column Name         | Description                                                    |
|---------------------|----------------------------------------------------------------|
| Affected Vendors    | List of vendors whose products are affected by the vulnerability |
| Affected Products   | List of specific products affected by the vulnerability         |
| Affected Versions   | List of specific product versions that are vulnerable           |
| Affected Platforms  | List of platforms/operating systems where vulnerability exists  |
| Affected Modules    | List of specific software modules or components affected        |
| Source Repositories | List of source code repositories related to the vulnerability   |

## Enhanced Problem Type Fields
| Column Name         | Description                                                    |
|---------------------|----------------------------------------------------------------|
| Primary Weakness    | Primary CWE weakness category for the vulnerability            |
| Secondary Weaknesses| Additional CWE weakness categories that apply                  |
| Vulnerability Categories| Structured categorization of vulnerability types             |
| Impact Types        | Types of impacts possible from exploiting the vulnerability    |
| Attack Vectors      | Possible attack vectors for exploitation                        |
| Enhanced CWE Details| Detailed CWE information and mapping                          |

## NIST Control Mapping Fields
| Column Name         | Description                                                    |
|---------------------|----------------------------------------------------------------|
| Applicable Controls Count| Number of NIST 800-53 controls that apply to this vulnerability |
| Control Categories  | Categories of NIST controls applicable                         |
| Top Controls        | Most relevant NIST 800-53 controls for mitigation             |

## Additional Metadata
| Column Name         | Description                                                    |
|---------------------|----------------------------------------------------------------|
| Reference Count     | Total number of reference URLs found                          |
| CPE Affected Count  | Number of Common Platform Enumeration entries for affected products |
| Vendor Advisories   | URLs for vendor security advisories - currently blank         |
| Patches             | URLs for patches or fixes - currently blank                   |

## ODIN Implementation Details
ODIN's systematic aggregation implementation across the five research layers:

### Layer 1: Foundational Record (CVEProject/cvelistV5)
- **Source**: GitHub CVEProject/cvelistV5 repository
- **Provides**: CVE ID, Description, CVSS Score/Vector, Severity, References, Product Intelligence
- **JSON Paths**: 
  - `containers.cna.descriptions[0].value` → Description
  - `containers.{adp,cna}.metrics[*].{cvssV3_1,cvssV3_0,cvssV2}.*` → CVSS data
  - `containers.cna.references[*].url` → References
  - `containers.cna.affected[*].{vendor,product,versions,platforms}` → Product Intelligence
- **Enhanced Fields**: Vendors, Products, Affected Versions, Platforms, Modules, Repositories

### Layer 2: Exploit Mechanics (trickest/cve)
- **Source**: GitHub trickest/cve repository  
- **Provides**: ExploitRefs, Exploit Count, Exploit Types, Exploit Maturity
- **Content**: Markdown files with exploit URLs from Exploit-DB, GitHub, Packet Storm

### Layer 3: Weakness & Tactics (mitre/cti)
- **Source**: MITRE CTI STIX bundles (placeholder implementation)
- **Provides**: CAPEC IDs, Attack Techniques, Attack Tactics
- **Status**: Currently blank, ready for MITRE STIX data integration

### Layer 4: Real-World Context (Multiple Sources)
- **EPSS Source**: GitHub ARPSyndicate/cve-scores → EPSS Score, EPSS Percentile  
- **VEDAS Source**: GitHub ARPSyndicate/cve-scores → VEDAS Score, VEDAS Percentile, VEDAS Score Change, VEDAS Detail URL, VEDAS Date
- **CVSS-BT Source**: GitHub t0sche/cvss-bt → CISA KEV, VulnCheck KEV, Has Metasploit, Temporal CVSS data
- **Temporal CVSS Fields**: Temporal Score, Exploit Code Maturity, Remediation Level, Report Confidence
- **Provides**: Enhanced threat intelligence, temporal risk assessment, and real-world exploitation data

### Layer 5: Raw Intelligence (Patrowl/PatrowlHearsData)
- **Source**: GitHub Patrowl/PatrowlHearsData repository
- **Provides**: CPE Affected Count, detailed impact metrics, additional CVSS data
- **JSON Paths**:
  - `configurations[*].nodes[*].cpeMatch[*].criteria` → CPE data
  - `impact.baseMetricV3.cvssV3.*` → CVSS v3 metrics
  - `impact.baseMetricV2.cvssV2.*` → CVSS v2 metrics

## Notes
- Fields marked "currently blank" have data structure in place but need enhanced connectors or additional data sources
- ExploitRefs are filtered to exclude CVE reference pages (cve.mitre.org, nvd.nist.gov) and include only actual exploit URLs
- CVSS data uses fallback priority: CVEProject → Patrowl → CVSS-BT
- Severity is computed from CVSS score: Critical (9.0+), High (7.0+), Medium (4.0+), Low (>0), Unknown (0)