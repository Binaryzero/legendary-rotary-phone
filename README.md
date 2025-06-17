# ODIN (OSINT Data Intelligence Nexus)

This repository provides a collection of utilities for performing vulnerability research across multiple open source intelligence feeds. The toolkit aggregates information from several data layers and exposes a backend API together with a React based user interface.

## Prerequisites

Before you begin, ensure you have the following installed:
- Python 3.x
- Node.js and npm

## Components

### Backend
- **File**: `backend/app.py`
- **Framework**: FastAPI
- Provides endpoints for researching CVEs, retrieving stored results and viewing summary analytics.
- Uses in‑memory storage for demo purposes.

### Frontend
- **Directory**: `frontend/`
- React application written in TypeScript.
- Communicates with the FastAPI backend to display vulnerability data.

### Starting the full UI
The helper script `start_odin_ui.py` installs requirements and launches both the backend and frontend.

```bash
# install Python and Node dependencies
python start_odin_ui.py --install

# start the API on port 8000 and the frontend on port 3000
python start_odin_ui.py
```

To customise ports use `--backend-port` and `--frontend-port`.

Once the backend is running, API documentation is typically available at `http://localhost:8000/docs`.

## Development
Install Python dependencies and run tests using `pytest`:

```bash
pip install -r requirements.txt
python -m pytest
Install Python dependencies and run tests using `pytest`:

This project uses several tools for maintaining code quality, including `flake8`, `black`, `isort`, and `mypy`. These are often managed via `pre-commit` to ensure checks are run before commits.

To run all pre-commit hooks:
```bash
pre-commit run --all-files

The tests are located in the `tests/` directory and exercise both the toolkit libraries and error handling utilities.

| Data Source (Repository)       | Research Layer                          | Data Provided                                                                                                                                                                                                        | Value to a Vulnerability Researcher (Why it's useful)                                                                                                                                                                                                                                                                                                                                                                                        |
| :----------------------------- | :-------------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`CVEProject/cvelistV5`**     | **1. Foundational Record**              | The official, canonical CVE list in structured CVE JSON 5.0/5.1 format. Contains the authoritative description, CVSS base metrics, and, most importantly, primary references from the CVE Numbering Authority (CNA). | This is the non-negotiable starting point. It provides the ground-truth description of the flaw. The **references** are the most critical asset here, often linking directly to vendor security advisories, bug tracker entries, or the original researcher's disclosure, which are the primary sources for deep technical analysis.                                                                                                         |
| **`trickest/cve`**             | **2. Exploit Mechanics & Validation**   | A comprehensive, near-continuously updated collection of links to publicly available Proof-of-Concept (PoC) exploit code, organized in human-readable markdown files.                                                | This is where you move from theory to practice. Analyzing the PoC code allows you to directly observe the **preconditions** for an exploit, understand the specific **attack vector**, and validate the practical **impact** (e.g., remote code execution vs. denial of service). It is the most direct way to understand how a vulnerability is actually exploited in the wild.                                                             |
| **`mitre/cti`**                | **3. Weakness & Tactic Classification** | The complete MITRE ATT&CK® (Adversary Tactics, Techniques, and Common Knowledge) and CAPEC™ (Common Attack Pattern Enumeration and Classification) knowledge bases, expressed in structured STIX 2.0 format.         | This resource is essential for classifying the vulnerability and developing robust mitigating controls. **CAPEC** provides a dictionary of known attack patterns, helping you understand *how* the weakness is exploited in a standardized way. **ATT&CK** describes the broader adversary tactics, which helps in formulating theoretical compensating controls that address the entire class of attack, not just this single CVE instance. |
| **`t0sche/cvss-bt`**           | **4. Real-World Threat Context**        | A single, machine-readable CSV file that enriches CVEs with data from sources like the CISA KEV catalog, Metasploit, and Nuclei templates.                                                                           | While you don't prioritize, this data provides critical research context. A flag indicating a CVE is in the **CISA Known Exploited Vulnerabilities (KEV) catalog** is definitive proof of active, in-the-wild exploitation. The presence of a **Metasploit module** or **Nuclei template** signifies that a reliable, weaponized exploit exists, which informs your analysis of the risk and the ease of exploitation.                       |
| **`Patrowl/PatrowlHearsData`** | **5. Raw Intelligence Toolkit**         | A collection of raw data feeds and scraping scripts for CVE, CPE (Common Platform Enumeration), CWE (Common Weakness Enumeration), CISA KEV, and EPSS, organized in separate folders.                                | This repository is a toolkit for building your own custom research database. It gathers the essential FOSS intelligence feeds into one location, allowing you to create your own correlated view by linking a CVE to its underlying weakness type (**CWE**), affected platforms (**CPE**), and real-world exploitation data (**KEV**, **EPSS**).                                                                                             |
