# CVE Research Starter Kit

## Purpose
This kit is designed for **researching and documenting all vulnerabilities**, not just high-severity or high-impact ones. It supports comprehensive analysis of CVE metadata including exploitability, upgrade versions, and available mitigations — without filtering or prioritization.

## Contents
- `cve_metadata_fetcher.py`: Main Python script to fetch and process CVEs from MITRE's CVE JSON v5 feed and generate per-CVE Word reports
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
- Maps CVSS base score to severity tiers (None/Low/Medium/High/Critical) (inspired by https://github.com/t0sche/cvss-bt)
- Word report generation is **off by default**; use `--reports` to enable per-CVE Word reports in the `reports/` directory
- All CVEs from the input file are processed; missing metadata yields blank fields (no CVEs are skipped due to missing data)

## Usage
1. Populate `cves.txt` with one CVE ID per line
2. Run the script (optional flags shown with defaults; reports off by default):
```
pip install requests openpyxl python-docx
python cve_metadata_fetcher.py --output results.xlsx --reports
```
3. Open the output file (default `CVE_Results.xlsx`, or as specified by `--output`) for the research summary
4. Review generated reports in the directory given by `--reports-dir` if `--reports` was specified

## Data Dictionary

For detailed definitions of each Excel column, see [DATA_DICTIONARY.md](DATA_DICTIONARY.md).

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
