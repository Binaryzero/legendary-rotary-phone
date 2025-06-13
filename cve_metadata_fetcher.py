import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

import requests
from docx import Document
from openpyxl import Workbook
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from openpyxl.worksheet.worksheet import Worksheet

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")

MITRE_BASE = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"


@dataclass
class CveMetadata:
    """Container for parsed CVE information."""

    description: str = ""
    cvss: str = ""
    vector: str = ""
    cwe: str = ""
    exploit: str = ""
    exploit_refs: str = ""
    fix_version: str = ""
    mitigations: str = ""
    affected: str = ""
    references: str = ""

def fetch_cve(cve_id: str) -> Optional[dict]:
    """Retrieve a CVE JSON record from the MITRE repository.

    Parameters
    ----------
    cve_id:
        The CVE identifier, e.g. ``"CVE-2023-1234"``.

    Returns
    -------
    dict | None
        Parsed JSON content if found, otherwise ``None`` when the request fails.
    """

    try:
        parts = cve_id.split("-")
        if len(parts) < 3:
            logging.warning("Invalid CVE ID format: %s", cve_id)
            return None
        year = parts[1]
        if not (year.isdigit() and len(year) == 4):
            logging.warning("Invalid year in CVE ID: %s", cve_id)
            return None

        bucket_str = parts[2]
        if not bucket_str.isdigit():
            logging.warning("Invalid numeric part in CVE ID: %s", cve_id)
            return None
        bucket = int(bucket_str) // 1000
    except IndexError:
        logging.warning("Invalid CVE ID format: %s", cve_id)
        return None

    url = f"{MITRE_BASE}/{year}/{bucket}xxx/{cve_id}.json"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
    except requests.RequestException as exc:
        logging.warning("Failed to fetch %s: %s", cve_id, exc)
        return None
    return response.json()

def parse_cve(cve_json: dict) -> CveMetadata:
    """Extract relevant metadata from a CVE JSON document.

    Args:
        cve_json (dict): JSON structure as returned by :func:`fetch_cve`.

    Returns
    -------
    CveMetadata
        Structured metadata extracted from the CVE document.
    """
    cna = cve_json.get("containers", {}).get("cna", {})
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
    return CveMetadata(
        description=desc,
        cvss=cvss,
        vector=vector,
        cwe=cwe,
        exploit=exploit_flag,
        exploit_refs=", ".join(exploits),
        fix_version=fix_version,
        mitigations=", ".join(mitigations),
        affected="; ".join(affected),
        references=", ".join(r.get("url", "") for r in references),
    )


def create_report(cve_id: str, meta: CveMetadata) -> None:
    """Generate a Word report based on the template.

    Parameters
    ----------
    cve_id: str
        Identifier for the CVE.
    meta:
        Parsed metadata dataclass returned by :func:`parse_cve`.
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
            p.text = meta.description
        elif txt == "List of affected products or environments.":
            p.text = meta.affected
        elif txt.startswith("Describe exploit vectors"):
            exp = (
                f"CVSS: {meta.cvss} ({meta.vector})\n"
                f"CWE: {meta.cwe}\n"
                f"Exploit Available: {meta.exploit} {meta.exploit_refs}"
            )
            p.text = exp
        elif txt.startswith("Document any known fixes"):
            mitigations = []
            if meta.fix_version:
                mitigations.append(f"Fix: {meta.fix_version}")
            if meta.mitigations:
                mitigations.append(f"Mitigations: {meta.mitigations}")
            p.text = "\n".join(mitigations)
        elif txt.startswith("List external references"):
            p.text = meta.references

    out_dir = Path("reports")
    out_dir.mkdir(exist_ok=True)
    doc.save(out_dir / f"{cve_id}.docx")

def main(input_file: Path = Path("cves.txt")) -> None:
    """Read CVE IDs, fetch their metadata and save results to Excel."""
    if not input_file.exists():
        logging.error("Missing %s input file.", input_file)
        return
    cve_ids = [line.strip() for line in input_file.read_text().splitlines() if line.strip()]
    wb = Workbook()
    ws = wb.active if wb.active is not None else wb.create_sheet()
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
            parsed.description,
            parsed.cvss,
            parsed.vector,
            parsed.cwe,
            parsed.exploit,
            parsed.exploit_refs,
            parsed.fix_version,
            parsed.mitigations,
            parsed.affected,
            parsed.references,
        ])
        create_report(cve_id, parsed)
    wb.save("CVE_Results.xlsx")
    logging.info("CVE_Results.xlsx created.")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Fetch CVE metadata from MITRE")
    parser.add_argument("input", nargs="?", default="cves.txt", help="Path to file containing CVE IDs")
    args = parser.parse_args()

    main(Path(args.input))
