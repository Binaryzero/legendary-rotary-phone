"""CVE Metadata Fetcher - Improved Version

Fetches CVE metadata from MITRE's CVE JSON v5 feed and generates reports.
"""
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple, Union

import requests
from openpyxl import Workbook
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

if TYPE_CHECKING:
    from openpyxl.worksheet.worksheet import Worksheet

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s"
)
logger = logging.getLogger(__name__)

# Constants
MITRE_BASE_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"
REQUEST_TIMEOUT = 10
MAX_WORKERS = 10
CVSS_SEVERITY_THRESHOLDS = {
    0.0: "None",
    4.0: "Low",
    7.0: "Medium",
    9.0: "High",
    10.0: "Critical"
}

# CVSS metric mappings for better readability
CVSS_METRICS = {
    'attack_vector': 'AV',
    'attack_complexity': 'AC',
    'privileges_required': 'PR',
    'privileges_required_v2': 'Au',
    'user_interaction': 'UI',
    'scope': 'S',
    'confidentiality': 'C',
    'integrity': 'I',
    'availability': 'A'
}


def create_session() -> requests.Session:
    """Create a requests session with retry strategy."""
    session = requests.Session()
    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def get_severity(score: Union[str, float]) -> str:
    """Map a CVSS base score to a standard severity tier."""
    try:
        score_float = float(score)
    except (ValueError, TypeError):
        return ""
    
    for threshold, severity in sorted(CVSS_SEVERITY_THRESHOLDS.items(), reverse=True):
        if score_float >= threshold:
            return severity
    return ""


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


class CveFetcher:
    """Handles fetching and parsing of CVE data."""
    
    def __init__(self):
        self.session = create_session()
    
    def validate_cve_id(self, cve_id: str) -> Optional[Tuple[str, int]]:
        """Validate CVE ID format and extract components.
        
        Returns:
            Tuple of (year, bucket) if valid, None otherwise
        """
        try:
            parts = cve_id.split("-")
            if len(parts) < 3 or parts[0] != "CVE":
                logger.warning("Invalid CVE ID format: %s", cve_id)
                return None
            
            year = parts[1]
            if not (year.isdigit() and len(year) == 4):
                logger.warning("Invalid year in CVE ID: %s", cve_id)
                return None
            
            number_str = parts[2]
            if not number_str.isdigit():
                logger.warning("Invalid numeric part in CVE ID: %s", cve_id)
                return None
            
            bucket = int(number_str) // 1000
            return year, bucket
            
        except (IndexError, ValueError) as exc:
            logger.warning("Error parsing CVE ID %s: %s", cve_id, exc)
            return None
    
    def fetch_cve(self, cve_id: str) -> Optional[dict]:
        """Retrieve a CVE JSON record from the MITRE repository."""
        validation_result = self.validate_cve_id(cve_id)
        if not validation_result:
            return None
        
        year, bucket = validation_result
        url = f"{MITRE_BASE_URL}/{year}/{bucket}xxx/{cve_id}.json"
        
        try:
            response = self.session.get(url, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as exc:
            logger.warning("Failed to fetch %s: %s", cve_id, exc)
            return None
        except ValueError as exc:
            logger.warning("Invalid JSON response for %s: %s", cve_id, exc)
            return None
    
    def parse_cvss_metrics(self, vector_string: str) -> Dict[str, str]:
        """Parse CVSS vector string into individual metrics."""
        metrics = {}
        if not vector_string:
            return metrics
        
        for part in vector_string.split('/'):
            if ':' not in part or part.startswith('CVSS'):
                continue
            key, value = part.split(':', 1)
            metrics[key] = value
        
        return metrics
    
    def extract_cwe_items(self, containers: dict) -> List[str]:
        """Extract CWE items from all containers."""
        cwe_items = []
        cna = containers.get("cna", {})
        
        # Check legacy format
        if "x_legacyV4Record" in cna:
            legacy = cna["x_legacyV4Record"]
            for problemtype_data in legacy.get("problemtype", {}).get("problemtype_data", []):
                for desc in problemtype_data.get("description", []):
                    value = desc.get("value", "").strip()
                    if value and value.lower() != "n/a":
                        cwe_items.append(value)
        
        # Check modern format
        for container in [cna] + containers.get("adp", []):
            for problem_type in container.get("problemTypes", []):
                for desc_entry in problem_type.get("descriptions", []):
                    cwe_id = desc_entry.get("cweId")
                    text = desc_entry.get("description") or desc_entry.get("value") or ""
                    
                    if text.lower() == "n/a":
                        continue
                    
                    if cwe_id and not text.startswith(cwe_id):
                        value = f"{cwe_id} {text}".strip()
                    else:
                        value = text or cwe_id
                    
                    if value:
                        cwe_items.append(value)
        
        return cwe_items
    
    def find_cvss_data(self, containers: dict) -> Tuple[str, str]:
        """Search available containers for a CVSS score and vector."""
        search_order = containers.get("adp", []) + [containers.get("cna", {})]
        
        for container in search_order:
            if not container:
                continue
            
            for metric in container.get("metrics", []):
                # Check CVSS versions in order of preference
                for cvss_key in ("cvssV3_1", "cvssV3_0", "cvssV2_1", "cvssV2_0", "cvssV2"):
                    cvss_data = metric.get(cvss_key)
                    if cvss_data:
                        base_score = str(cvss_data.get("baseScore", ""))
                        vector_string = cvss_data.get("vectorString", "")
                        return base_score, vector_string
        
        return "", ""
    
    def parse_references(self, references: List[dict]) -> Dict[str, List[str]]:
        """Parse and categorize references."""
        result = {
            "exploits": [],
            "fix_versions": [],
            "mitigations": [],
            "all_refs": []
        }
        
        for ref in references:
            url = ref.get("url", "")
            if not url:
                continue
            
            result["all_refs"].append(url)
            
            # Categorize references
            if "exploit-db.com" in url or "github.com" in url:
                result["exploits"].append(url)
            
            if "advisories" in url or "bulletin" in url:
                result["mitigations"].append(url)
            
            if "upgrade" in ref.get("tags", []):
                result["fix_versions"].append(url)
        
        return result
    
    def parse_affected_products(self, affected_list: List[dict]) -> List[str]:
        """Parse affected products information."""
        affected_items = []
        
        for affected in affected_list:
            vendor = affected.get("vendor", "")
            product = affected.get("product", "")
            versions = ", ".join(
                version.get("version", "") 
                for version in affected.get("versions", [])
            )
            
            components = [comp for comp in [vendor, product, versions] if comp]
            if components:
                affected_items.append(" ".join(components))
        
        return affected_items
    
    def parse_cve(self, cve_json: dict) -> CveMetadata:
        """Extract relevant metadata from a CVE JSON document."""
        containers = cve_json.get("containers", {})
        cna = containers.get("cna", {})
        
        # Extract description
        if "x_legacyV4Record" in cna:
            legacy = cna["x_legacyV4Record"]
            description = (
                legacy.get("description", {})
                .get("description_data", [{}])[0]
                .get("value", "")
            )
        else:
            description = cna.get("descriptions", [{}])[0].get("value", "")
        
        # Extract CVSS data
        cvss_score, vector_string = self.find_cvss_data(containers)
        severity = get_severity(cvss_score)
        
        # Parse CVSS metrics
        metrics = self.parse_cvss_metrics(vector_string)
        
        # Extract CWE
        cwe_items = self.extract_cwe_items(containers)
        cwe = ", ".join(cwe_items)
        
        # Parse references
        references = cna.get("references", [])
        ref_data = self.parse_references(references)
        
        # Parse affected products
        affected_items = self.parse_affected_products(cna.get("affected", []))
        
        return CveMetadata(
            description=description,
            cvss=cvss_score,
            severity=severity,
            attack_vector=metrics.get(CVSS_METRICS['attack_vector'], ''),
            attack_complexity=metrics.get(CVSS_METRICS['attack_complexity'], ''),
            privileges_required=metrics.get(
                CVSS_METRICS['privileges_required'],
                metrics.get(CVSS_METRICS['privileges_required_v2'], '')
            ),
            user_interaction=metrics.get(CVSS_METRICS['user_interaction'], ''),
            scope=metrics.get(CVSS_METRICS['scope'], ''),
            impact_confidentiality=metrics.get(CVSS_METRICS['confidentiality'], ''),
            impact_integrity=metrics.get(CVSS_METRICS['integrity'], ''),
            impact_availability=metrics.get(CVSS_METRICS['availability'], ''),
            vector=vector_string,
            cwe=cwe,
            exploit="Yes" if ref_data["exploits"] else "No",
            exploit_refs=", ".join(ref_data["exploits"]),
            fix_version=", ".join(ref_data["fix_versions"]),
            mitigations=", ".join(ref_data["mitigations"]),
            affected="; ".join(affected_items),
            references=", ".join(ref_data["all_refs"]),
        )


def create_report(
    cve_id: str, 
    meta: CveMetadata, 
    out_dir: Path = Path("reports")
) -> None:
    """Generate a Word report based on the template."""
    try:
        from docx import Document
    except ImportError:
        logger.error("python-docx not installed. Cannot generate Word reports.")
        return
    
    template = Path("CVE_Report_Template.docx")
    if not template.exists():
        logger.error("CVE_Report_Template.docx not found")
        return
    
    try:
        doc = Document(str(template))
    except Exception as exc:
        logger.error("Failed to load template: %s", exc)
        return
    
    # Update document content
    replacements = {
        "CVE ID:": f"CVE ID: {cve_id}",
        "Brief summary of the vulnerability.": meta.description,
        "List of affected products or environments.": meta.affected,
        "Describe exploit vectors": (
            f"CVSS: {meta.cvss} ({meta.vector})\n"
            f"Severity: {meta.severity}\n"
            f"CWE: {meta.cwe}\n"
            f"Exploit Available: {meta.exploit} {meta.exploit_refs}"
        ),
        "Document any known fixes": "\n".join(filter(None, [
            f"Fix: {meta.fix_version}" if meta.fix_version else "",
            f"Mitigations: {meta.mitigations}" if meta.mitigations else ""
        ])),
        "List external references": meta.references
    }
    
    for paragraph in doc.paragraphs:
        text = paragraph.text.strip()
        for pattern, replacement in replacements.items():
            if text.startswith(pattern):
                paragraph.text = replacement
                break
    
    # Save report
    out_dir.mkdir(exist_ok=True)
    output_path = out_dir / f"{cve_id}.docx"
    
    try:
        doc.save(str(output_path))
        logger.debug("Report saved: %s", output_path)
    except Exception as exc:
        logger.error("Failed to save report for %s: %s", cve_id, exc)


def process_cve_batch(
    cve_ids: List[str],
    fetcher: CveFetcher,
    generate_reports: bool = False,
    reports_dir: Path = Path("reports")
) -> List[Tuple[str, Optional[CveMetadata]]]:
    """Process a batch of CVE IDs concurrently."""
    results = []
    total_cves = len(cve_ids)
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # Submit all fetch tasks
        future_to_cve = {
            executor.submit(fetcher.fetch_cve, cve_id): cve_id 
            for cve_id in cve_ids
        }
        
        # Process results as they complete
        for idx, future in enumerate(as_completed(future_to_cve), 1):
            cve_id = future_to_cve[future]
            
            try:
                data = future.result()
                if data is None:
                    logger.warning("Failed to fetch %s", cve_id)
                    results.append((cve_id, None))
                    continue
                
                metadata = fetcher.parse_cve(data)
                results.append((cve_id, metadata))
                
                if generate_reports:
                    create_report(cve_id, metadata, reports_dir)
                
                if idx % 10 == 0:
                    logger.info("Progress: %d/%d CVEs processed", idx, total_cves)
                    
            except Exception as exc:
                logger.error("Error processing %s: %s", cve_id, exc)
                results.append((cve_id, None))
    
    return results


def write_excel_report(
    results: List[Tuple[str, Optional[CveMetadata]]],
    output_file: Path
) -> None:
    """Write results to Excel file."""
    workbook = Workbook()
    worksheet: "Worksheet" = workbook.active if workbook.active else workbook.create_sheet()
    worksheet.title = f"Batch_{datetime.now().strftime('%Y%m%d_%H%M')}"
    
    # Write header
    headers = [
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
    ]
    worksheet.append(headers)
    
    # Write data
    for cve_id, metadata in results:
        if metadata is None:
            # Include failed CVEs with empty data
            worksheet.append([cve_id] + [""] * (len(headers) - 1))
        else:
            worksheet.append([
                cve_id,
                metadata.description,
                metadata.cvss,
                metadata.severity,
                metadata.attack_vector,
                metadata.attack_complexity,
                metadata.privileges_required,
                metadata.user_interaction,
                metadata.scope,
                metadata.impact_confidentiality,
                metadata.impact_integrity,
                metadata.impact_availability,
                metadata.vector,
                metadata.cwe,
                metadata.exploit,
                metadata.exploit_refs,
                metadata.fix_version,
                metadata.mitigations,
                metadata.affected,
                metadata.references,
            ])
    
    # Save file
    try:
        workbook.save(str(output_file))
        logger.info("Results saved to %s", output_file)
    except Exception as exc:
        logger.error("Failed to save Excel file: %s", exc)
        raise


def main(
    input_file: Path = Path("cves.txt"),
    *,
    output_file: Path = Path("CVE_Results.xlsx"),
    reports_dir: Path = Path("reports"),
    generate_reports: bool = True,
) -> None:
    """Read CVE IDs, fetch their metadata and save results to Excel."""
    # Validate input file
    if not input_file.exists():
        logger.error("Input file not found: %s", input_file)
        return
    
    # Read CVE IDs
    try:
        cve_ids = [
            line.strip() 
            for line in input_file.read_text().splitlines() 
            if line.strip()
        ]
    except Exception as exc:
        logger.error("Failed to read input file: %s", exc)
        return
    
    if not cve_ids:
        logger.warning("No CVE IDs found in input file")
        return
    
    logger.info("Processing %d CVE IDs...", len(cve_ids))
    
    # Process CVEs
    start_time = time.time()
    fetcher = CveFetcher()
    
    try:
        results = process_cve_batch(
            cve_ids, 
            fetcher, 
            generate_reports, 
            reports_dir
        )
        
        # Write Excel report
        write_excel_report(results, output_file)
        
        # Summary statistics
        successful = sum(1 for _, meta in results if meta is not None)
        failed = len(results) - successful
        elapsed = time.time() - start_time
        
        logger.info(
            "Completed in %.1f seconds. Success: %d, Failed: %d",
            elapsed, successful, failed
        )
        
    except KeyboardInterrupt:
        logger.warning("Process interrupted by user")
    except Exception as exc:
        logger.error("Unexpected error: %s", exc)
        raise


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Fetch CVE metadata from MITRE and generate reports"
    )
    parser.add_argument(
        "input",
        nargs="?",
        default="cves.txt",
        help="Path to file containing CVE IDs (one per line)"
    )
    parser.add_argument(
        "-o", "--output",
        default="CVE_Results.xlsx",
        help="Path to Excel output file"
    )
    parser.add_argument(
        "--reports-dir",
        default="reports",
        help="Directory to store Word reports"
    )
    parser.add_argument(
        "--reports",
        action="store_true",
        help="Generate Word reports (off by default)"
    )
    
    args = parser.parse_args()
    
    main(
        Path(args.input),
        output_file=Path(args.output),
        reports_dir=Path(args.reports_dir),
        generate_reports=args.reports,
    )