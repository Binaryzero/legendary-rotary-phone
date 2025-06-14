# Data Dictionary

This file describes each column exported to CSV/Excel output by the CVE Research Toolkit.

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
| EPSS Score        | Exploit Prediction Scoring System score (0.0-1.0)                |
| EPSS Percentile   | EPSS percentile ranking (0.0-100.0) - currently blank             |
| Actively Exploited| "Yes" if evidence of active exploitation in the wild              |
| Has Metasploit    | "Yes" if Metasploit module exists                                 |
| Has Nuclei        | "Yes" if Nuclei template exists                                    |

## Weakness & Attack Classification (MITRE)
| Column Name       | Description                                           |
|-------------------|-------------------------------------------------------|
| CAPEC IDs         | Common Attack Pattern Enumeration IDs - currently blank |
| Attack Techniques | MITRE ATT&CK technique IDs - currently blank         |
| Attack Tactics    | MITRE ATT&CK tactic names - currently blank          |

## Additional Metadata
| Column Name         | Description                                                    |
|---------------------|----------------------------------------------------------------|
| Reference Count     | Total number of reference URLs found                          |
| CPE Affected Count  | Number of Common Platform Enumeration entries for affected products |
| Vendor Advisories   | URLs for vendor security advisories - currently blank         |
| Patches             | URLs for patches or fixes - currently blank                   |

## Data Layer Sources
The CVE Research Toolkit aggregates data from five research layers:

### Layer 1: Foundational Record (CVEProject/cvelistV5)
- **Source**: GitHub CVEProject/cvelistV5 repository
- **Provides**: CVE ID, Description, CVSS Score/Vector, Severity, References
- **JSON Paths**: 
  - `containers.cna.descriptions[0].value` → Description
  - `containers.{adp,cna}.metrics[*].{cvssV3_1,cvssV3_0,cvssV2}.*` → CVSS data
  - `containers.cna.references[*].url` → References

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
- **CVSS-BT Source**: GitHub t0sche/cvss-bt → CISA KEV, Has Metasploit, additional CVSS data
- **Provides**: Threat intelligence and real-world exploitation data

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