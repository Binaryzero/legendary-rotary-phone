# CVE Research Starter Kit

## Purpose
This kit is designed for **researching and documenting all vulnerabilities**, not just high-severity or high-impact ones. It supports comprehensive analysis of CVE metadata including exploitability, upgrade versions, and available mitigations — without filtering or prioritization.

## Contents
- `cve_metadata_fetcher.py`: Main Python script to fetch and process CVEs from MITRE's CVE JSON v5 feed
- `CVE_Research_Template.xlsx`: Structured Excel output format
- `CVE_Report_Template.docx`: Word template for full CVE write-ups
- `cves.txt`: Sample input file (one CVE per line)

## Features
- Automatically pulls CVE metadata from MITRE’s GitHub repository
- Extracts: description, CVSS, vector, CWE, references
- Identifies: known public exploits (Exploit-DB, GitHub)
- Detects: fixed/upgrade versions if available
- Extracts: mitigation guidance and advisory references
- Outputs results to Excel with structured columns and batch naming

## Usage
1. Populate `cves.txt` with one CVE ID per line
2. Run the script:
```
pip install requests openpyxl
python cve_metadata_fetcher.py
```
3. Open `CVE_Results.xlsx` for the research summary
4. Use `CVE_Report_Template.docx` for any deep-dive documentation

## Testing
This project uses `pytest` to run the unit tests located in the `tests/`
directory. After installing the dependencies, simply run:

```
pytest
```

## Notes
- This kit is **not** intended for remediation prioritization
- It is intended for full-spectrum documentation of vulnerabilities — including technical risk, mitigation references, and system impact

## MITRE Source
https://github.com/CVEProject/cvelistV5
