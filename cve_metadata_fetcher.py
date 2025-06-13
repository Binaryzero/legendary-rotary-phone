import json, requests, logging
from openpyxl import Workbook
from datetime import datetime
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")

MITRE_BASE = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"

def fetch_cve(cve_id):
    year = cve_id.split("-")[1]
    bucket = int(cve_id.split("-")[2]) // 1000
    url = f"{MITRE_BASE}/{year}/{bucket}xxx/{cve_id}.json"
    r = requests.get(url)
    if r.status_code != 200:
        logging.warning(f"Failed to fetch {cve_id}")
        return None
    return r.json()

def parse_cve(cve_json):
    cna = cve_json["containers"]["cna"]
    desc = cna.get("descriptions", [{}])[0].get("value", "")
    cvss = cna.get("metrics", [{}])[0].get("cvssV3_1", {}).get("baseScore", "")
    vector = cna.get("metrics", [{}])[0].get("cvssV3_1", {}).get("vectorString", "")
    cwe = ", ".join(
        i["description"][0]["value"]
        for i in cna.get("problemTypes", [{}])[0].get("descriptions", [])
    ) if cna.get("problemTypes") else ""
    references = cna.get("references", [])
    exploits = [r["url"] for r in references if "exploit-db.com" in r["url"] or "github.com" in r["url"]]
    exploit_flag = "Yes" if exploits else "No"
    fix_version = ""
    mitigations = []
    for r in references:
        url = r.get("url", "")
        if "advisories" in url or "bulletin" in url:
            mitigations.append(url)
        if "upgrade" in r.get("tags", []):
            fix_version = r.get("url", "")
    return {
        "Description": desc,
        "CVSS": cvss,
        "Vector": vector,
        "CWE": cwe,
        "Exploit": exploit_flag,
        "ExploitRefs": ", ".join(exploits),
        "FixVersion": fix_version,
        "Mitigations": ", ".join(mitigations)
    }

def main():
    input_path = Path("cves.txt")
    if not input_path.exists():
        logging.error("Missing cves.txt input file.")
        return
    cve_ids = [line.strip() for line in input_path.read_text().splitlines() if line.strip()]
    wb = Workbook()
    ws = wb.active
    ws.title = f"Batch_{datetime.now().strftime('%Y%m%d_%H%M')}"
    ws.append(["CVE ID", "Description", "CVSS", "Vector", "CWE", "Exploit", "ExploitRefs", "FixVersion", "Mitigations"])
    for cve_id in cve_ids:
        data = fetch_cve(cve_id)
        if not data:
            continue
        parsed = parse_cve(data)
        ws.append([cve_id] + [parsed.get(k, "") for k in ["Description", "CVSS", "Vector", "CWE", "Exploit", "ExploitRefs", "FixVersion", "Mitigations"]])
    wb.save("CVE_Results.xlsx")
    logging.info("CVE_Results.xlsx created.")

if __name__ == "__main__":
    main()
