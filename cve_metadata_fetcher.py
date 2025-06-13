import json
import logging
from datetime import datetime
from pathlib import Path

import requests
from docx import Document
from openpyxl import Workbook

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")

MITRE_BASE = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"

def fetch_cve(cve_id):
    """Retrieve a CVE JSON record from the MITRE repository.

    Args:
        cve_id (str): The CVE identifier, e.g. ``"CVE-2023-1234"``.

    Returns:
        dict | None: Parsed JSON content if found, otherwise ``None`` when the
        request fails.
    """
    year = cve_id.split("-")[1]
    bucket = int(cve_id.split("-")[2]) // 1000
    url = f"{MITRE_BASE}/{year}/{bucket}xxx/{cve_id}.json"
    r = requests.get(url)
    if r.status_code != 200:
        logging.warning(f"Failed to fetch {cve_id}")
        return None
    return r.json()

def parse_cve(cve_json):
    """Extract relevant metadata from a CVE JSON document.

    Args:
        cve_json (dict): JSON structure as returned by :func:`fetch_cve`.

    Returns:
        dict: A dictionary with keys ``Description``, ``CVSS``, ``Vector``,
        ``CWE``, ``Exploit``, ``ExploitRefs``, ``FixVersion`` and
        ``Mitigations``.
    """
    cna = cve_json["containers"]["cna"]
    desc = cna.get("descriptions", [{}])[0].get("value", "")
    cvss = cna.get("metrics", [{}])[0].get("cvssV3_1", {}).get("baseScore", "")
    vector = cna.get("metrics", [{}])[0].get("cvssV3_1", {}).get("vectorString", "")
    cwe_items = []
    for pt in cna.get("problemTypes", []):
        for desc_entry in pt.get("descriptions", []):
            val = desc_entry.get("description") or desc_entry.get("value")
            if val:
                cwe_items.append(val)
    cwe = ", ".join(cwe_items)
    references = cna.get("references", [])
    exploits = [r["url"] for r in references if "exploit-db.com" in r["url"] or "github.com" in r["url"]]
    exploit_flag = "Yes" if exploits else "No"
    fix_version = ""
    mitigations = []
    affected = []
    for r in references:
        url = r.get("url", "")
        if "advisories" in url or "bulletin" in url:
            mitigations.append(url)
        if "upgrade" in r.get("tags", []):
            fix_version = r.get("url", "")
    for a in cna.get("affected", []):
        vendor = a.get("vendor", "")
        product = a.get("product", "")
        versions = ", ".join(v.get("version", "") for v in a.get("versions", []))
        item = " ".join(i for i in [vendor, product, versions] if i)
        if item:
            affected.append(item)
    return {
        "Description": desc,
        "CVSS": cvss,
        "Vector": vector,
        "CWE": cwe,
        "Exploit": exploit_flag,
        "ExploitRefs": ", ".join(exploits),
        "FixVersion": fix_version,
        "Mitigations": ", ".join(mitigations),
        "Affected": "; ".join(affected),
        "References": ", ".join(r.get("url", "") for r in references)
    }


def create_report(cve_id: str, meta: dict) -> None:
    """Generate a Word report based on the template.

    Parameters
    ----------
    cve_id: str
        Identifier for the CVE.
    meta: dict
        Parsed metadata dictionary returned by :func:`parse_cve`.
    """
    template = Path("CVE_Report_Template.docx")
    if not template.exists():
        logging.error("CVE_Report_Template.docx not found")
        return
    doc = Document(template)

    for p in doc.paragraphs:
        txt = p.text.strip()
        if txt.startswith("CVE ID:"):
            p.text = f"CVE ID: {cve_id}"
        elif txt == "Brief summary of the vulnerability.":
            p.text = meta.get("Description", "")
        elif txt == "List of affected products or environments.":
            p.text = meta.get("Affected", "")
        elif txt.startswith("Describe exploit vectors"):
            exp = f"CVSS: {meta.get('CVSS')} ({meta.get('Vector')})\n" \
                  f"CWE: {meta.get('CWE')}\n" \
                  f"Exploit Available: {meta.get('Exploit')} {meta.get('ExploitRefs')}"
            p.text = exp
        elif txt.startswith("Document any known fixes"):
            mitigations = []
            if meta.get("FixVersion"):
                mitigations.append(f"Fix: {meta['FixVersion']}")
            if meta.get("Mitigations"):
                mitigations.append(f"Mitigations: {meta['Mitigations']}")
            p.text = "\n".join(mitigations)
        elif txt.startswith("List external references"):
            p.text = meta.get("References", "")

    out_dir = Path("reports")
    out_dir.mkdir(exist_ok=True)
    doc.save(out_dir / f"{cve_id}.docx")

def main():
    """Read CVE IDs, fetch their metadata and save results to Excel."""
    input_path = Path("cves.txt")
    if not input_path.exists():
        logging.error("Missing cves.txt input file.")
        return
    cve_ids = [line.strip() for line in input_path.read_text().splitlines() if line.strip()]
    wb = Workbook()
    ws = wb.active
    ws.title = f"Batch_{datetime.now().strftime('%Y%m%d_%H%M')}"
    ws.append([
        "CVE ID",
        "Description",
        "CVSS",
        "Vector",
        "CWE",
        "Exploit",
        "ExploitRefs",
        "FixVersion",
        "Mitigations",
        "Affected",
        "References",
    ])
    for cve_id in cve_ids:
        data = fetch_cve(cve_id)
        if not data:
            continue
        parsed = parse_cve(data)
        ws.append([
            cve_id,
            parsed.get("Description", ""),
            parsed.get("CVSS", ""),
            parsed.get("Vector", ""),
            parsed.get("CWE", ""),
            parsed.get("Exploit", ""),
            parsed.get("ExploitRefs", ""),
            parsed.get("FixVersion", ""),
            parsed.get("Mitigations", ""),
            parsed.get("Affected", ""),
            parsed.get("References", ""),
        ])
        create_report(cve_id, parsed)
    wb.save("CVE_Results.xlsx")
    logging.info("CVE_Results.xlsx created.")

if __name__ == "__main__":
    main()
