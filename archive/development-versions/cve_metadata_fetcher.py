import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Optional, Union

import requests
from openpyxl import Workbook

if TYPE_CHECKING:
    from openpyxl.worksheet.worksheet import Worksheet

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")

MITRE_BASE = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"

def get_severity(score: Union[str, float]) -> str:
    """Map a CVSS base score to a standard severity tier."""
    try:
        s = float(score)
    except Exception:
        return ""
    if s == 0:
        return "None"
    if s < 4.0:
        return "Low"
    if s < 7.0:
        return "Medium"
    if s < 9.0:
        return "High"
    return "Critical"


@dataclass
class CveMetadata:
    """Container for parsed CVE information."""

    description: str = ""
    cvss: str = ""
    severity: str = ""
    attack_vector: str = ""
    attack_complexity: str = ""
    privileges_required: str = ""
    user_interaction: str = ""
    scope: str = ""
    impact_confidentiality: str = ""
    impact_integrity: str = ""
    impact_availability: str = ""
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
    except Exception as exc:
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
    containers = cve_json.get("containers", {})
    cna = containers.get("cna", {})
    # legacy CVE v4 records embed description/problemtype differently
    if "x_legacyV4Record" in cna:
        legacy = cna["x_legacyV4Record"]
        desc = legacy.get("description", {}).get("description_data", [{}])[0].get("value", "")
        # migrate problemtype -> CWE if not n/a
        cwe_items = []
        for pd in legacy.get("problemtype", {}).get("problemtype_data", []):
            for d in pd.get("description", []):
                val = d.get("value", "").strip()
                if val and val.lower() != "n/a":
                    cwe_items.append(val)
        cwe = ", ".join(cwe_items)
        # no CVSS metrics in legacy v4 container
        cvss = vector = ""
        severity = ""
        # fall through to build metadata below
    else:
        desc = cna.get("descriptions", [{}])[0].get("value", "")
        cwe_items = []

    def find_cvss() -> tuple[str, str]:
        """Search available containers for a CVSS score and vector."""
        order = containers.get("adp", []) + [cna]
        for cont in order:
            if not cont:
                continue
            for metric in cont.get("metrics", []):
                for key in ("cvssV3_1", "cvssV3_0", "cvssV2_1", "cvssV2_0", "cvssV2"):
                    data = metric.get(key)
                    if data:
                        return data.get("baseScore", ""), data.get("vectorString", "")
        return "", ""

    cvss, vector = find_cvss()
    severity = get_severity(cvss)
    # parse individual CVSS metrics from the vector string
    metrics = {}
    for part in vector.split('/'):
        if ':' not in part or part.startswith('CVSS'):
            continue
        k, v = part.split(':', 1)
        metrics[k] = v
    av = metrics.get('AV', '')
    ac = metrics.get('AC', '')
    pr = metrics.get('PR', metrics.get('Au', ''))
    ui = metrics.get('UI', '')
    sc = metrics.get('S', '')
    ci = metrics.get('C', '')
    ii = metrics.get('I', '')
    ai = metrics.get('A', '')
    cwe_items = []
    for container in [cna] + containers.get("adp", []):
        for pt in container.get("problemTypes", []):
            for desc_entry in pt.get("descriptions", []):
                cwe_id = desc_entry.get("cweId")
                text = desc_entry.get("description") or desc_entry.get("value") or ""
                if text.lower() == "n/a":
                    continue
                if cwe_id and not text.startswith(cwe_id):
                    val = f"{cwe_id} {text}".strip()
                else:
                    val = text or cwe_id
                if val:
                    cwe_items.append(val)
    cwe = ", ".join(cwe_items)
    references = cna.get("references", [])
    exploits = [
        r["url"]
        for r in references
        if "exploit-db.com" in r["url"] or "github.com" in r["url"]
    ]
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
        severity=severity,
        attack_vector=av,
        attack_complexity=ac,
        privileges_required=pr,
        user_interaction=ui,
        scope=sc,
        impact_confidentiality=ci,
        impact_integrity=ii,
        impact_availability=ai,
        vector=vector,
        cwe=cwe,
        exploit=exploit_flag,
        exploit_refs=", ".join(exploits),
        fix_version=fix_version,
        mitigations=", ".join(mitigations),
        affected="; ".join(affected),
        references=", ".join(r.get("url", "") for r in references),
    )


def create_report(
    cve_id: str, meta: CveMetadata, out_dir: Path = Path("reports")
) -> None:
    """Generate a Word report based on the template.

    Parameters
    ----------
    cve_id: str
        Identifier for the CVE.
    meta:
        Parsed metadata dataclass returned by :func:`parse_cve`.
    out_dir:
        Directory where the generated report will be saved.

    """
    from docx import Document

    template = Path("CVE_Report_Template.docx")
    if not template.exists():
        logging.error("CVE_Report_Template.docx not found")
        return
    doc = Document(str(template))

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
                f"Severity: {meta.severity}\n"
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
    out_dir.mkdir(exist_ok=True)
    doc.save(str(out_dir / f"{cve_id}.docx"))


def main(
    input_file: Path = Path("cves.txt"),
    *,
    output_file: Path = Path("CVE_Results.xlsx"),
    reports_dir: Path = Path("reports"),
    generate_reports: bool = True,
) -> None:
    """Read CVE IDs, fetch their metadata and save results to Excel."""
    if not input_file.exists():
        logging.error("Missing %s input file.", input_file)
        return
    cve_ids = [
        line.strip() for line in input_file.read_text().splitlines() if line.strip()
    ]
    wb = Workbook()
    ws: "Worksheet" = wb.active if wb.active is not None else wb.create_sheet()
    ws.title = f"Batch_{datetime.now().strftime('%Y%m%d_%H%M')}"
    ws.append([
        "CVE ID",
        "Description",
        "CVSS",
        "Severity",
        "Attack Vector",
        "Attack Complexity",
        "Privileges Required",
        "User Interaction",
        "Scope",
        "Confidentiality Impact",
        "Integrity Impact",
        "Availability Impact",
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
        # only skip when fetch_cve explicitly failed (None);
        # empty dicts yield blank metadata but still included
        if data is None:
            continue
        parsed = parse_cve(data)


        ws.append([
            cve_id,
            parsed.description,
            parsed.cvss,
            parsed.severity,
            parsed.attack_vector,
            parsed.attack_complexity,
            parsed.privileges_required,
            parsed.user_interaction,
            parsed.scope,
            parsed.impact_confidentiality,
            parsed.impact_integrity,
            parsed.impact_availability,
            parsed.vector,
            parsed.cwe,
            parsed.exploit,
            parsed.exploit_refs,
            parsed.fix_version,
            parsed.mitigations,
            parsed.affected,
            parsed.references,
        ])
        if generate_reports:
            create_report(cve_id, parsed, reports_dir)
    wb.save(str(output_file))
    logging.info("%s created.", output_file)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Fetch CVE metadata from MITRE")
    parser.add_argument(
        "input", nargs="?", default="cves.txt", help="Path to file containing CVE IDs"
    )
    parser.add_argument(
        "-o", "--output", default="CVE_Results.xlsx", help="Path to Excel output file"
    )
    parser.add_argument(
        "--reports-dir", default="reports", help="Directory to store Word reports"
    )
    parser.add_argument(
        "--reports", action="store_true", help="Generate Word reports (off by default)"
    )

    args = parser.parse_args()

    main(
        Path(args.input),
        output_file=Path(args.output),
        reports_dir=Path(args.reports_dir),
        generate_reports=args.reports,
    )
