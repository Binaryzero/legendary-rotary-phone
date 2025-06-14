```mermaid
flowchart TD
  subgraph S1["1. Ingestion"]
    A["Read CVE list\n(cves.txt)"]
    B["Fetch CVE JSON\n(MITRE API)"]
  end

  subgraph S2["2. Enrichment"]
    C["Parse CVSS & Description"]
    D["Check Exploit Flags\n(Exploit-DB, Metasploit, Nuclei)"]
    E["Fetch Risk Scores\n(EPSS, VEDAS)"]
  end

  subgraph S3["3. Generation"]
    F["Populate Excel Template\n(report.xlsx)"]
    G["Populate Word Template\n(report.docx)"]
  end

  subgraph S4["4. Distribution"]
    H["Save results.xlsx"]
    I["Save results.docx"]
    J["Publish to reports/"]
  end

  A --> B
  B --> C
  C --> D
  D --> E
  E --> F
  E --> G
  F --> H
  G --> I
  H --> J
  I --> J
