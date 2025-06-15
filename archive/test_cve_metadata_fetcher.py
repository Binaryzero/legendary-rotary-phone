import sys
from pathlib import Path
import types

import pytest
from unittest.mock import patch

# dynamically load the module under test, so it can be imported below
fetcher = types.ModuleType("cve_research_toolkit_fixed")
module_path = Path(__file__).parent.parent / "cve_research_toolkit_fixed.py"
exec(module_path.read_text(), fetcher.__dict__)
sys.modules["cve_research_toolkit_fixed"] = fetcher

# Import what we need for legacy test compatibility
from cve_research_toolkit_fixed import ResearchData as CveMetadata, main_research as main

LEGACY_JSON = {
    "containers": {
        "cna": {
            "x_legacyV4Record": {
                "description": {"description_data": [{"value": "Legacy desc"}]},
                "problemtype": {"problemtype_data": [{"description": [{"value": "CWE-123"}]}]},
            }
        }
    }
}

SAMPLE_JSON = {
    "containers": {
        "cna": {
            "descriptions": [{"value": "Sample description"}],
            "metrics": [
                {"cvssV3_1": {"baseScore": 5.0, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"}}
            ],
            "problemTypes": [{"descriptions": [{"description": "CWE-79"}]}],
            "references": [
                {"url": "https://exploit-db.com/exploits/1"},
                {"url": "https://example.com/patch", "tags": ["upgrade"]},
        {"url": "https://vendor.com/advisories/123"},
            ],
            "affected": [
                {"vendor": "Acme", "product": "App", "versions": [{"version": "1.0"}]}
            ],
        }
    }
}
NESTED_JSON = {
    "containers": {
        "adp": [
            {
                "metrics": [
                    {"other": {"type": "rating"}},
                    {"cvssV3_1": {"baseScore": 8.8, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}
                ],
                "problemTypes": [
                    {"descriptions": [{"cweId": "CWE-123", "description": "Sample CWE description"}]}
                ]
            }
        ],
        "cna": {}
    }
}

def test_parse_cve_extracts_fields():
    parsed = parse_cve(SAMPLE_JSON)
    assert isinstance(parsed, CveMetadata)
    assert parsed.description == "Sample description"
    assert parsed.cvss == 5.0
    assert parsed.vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
    assert parsed.cwe == "CWE-79"
    assert parsed.exploit == "Yes"
    assert parsed.exploit_refs == "https://exploit-db.com/exploits/1"
    assert parsed.fix_version == "https://example.com/patch"
    assert parsed.mitigations == "https://vendor.com/advisories/123"
    assert parsed.affected == "Acme App 1.0"
    assert parsed.severity == "Medium"
    # CVSS v3 metric breakdown
    assert parsed.attack_vector == "N"
    assert parsed.attack_complexity == "L"
    assert parsed.privileges_required == "N"
    assert parsed.user_interaction == "N"
    assert parsed.scope == "U"
    assert parsed.impact_confidentiality == "N"
    assert parsed.impact_integrity == "N"
    assert parsed.impact_availability == "N"


def test_fetch_cve_returns_none_on_failure():
    with patch("cve_metadata_fetcher.requests.get") as mock_get:
        mock_get.side_effect = Exception("fail")
        assert fetch_cve("CVE-0000-0000") is None

def test_fetch_cve_invalid_format_ignored():
    with patch("cve_metadata_fetcher.requests.get") as mock_get:
        assert fetch_cve("BADFORMAT") is None
        mock_get.assert_not_called()

def test_parse_cve_handles_nested_metrics_and_cwe():
    parsed = parse_cve(NESTED_JSON)
    assert parsed.cvss == 8.8
    assert parsed.vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert parsed.cwe == "CWE-123 Sample CWE description"
    assert parsed.severity == "High"
    # CVSS v3 nested metric breakdown
    assert parsed.attack_vector == "N"
    assert parsed.attack_complexity == "L"
    assert parsed.privileges_required == "N"
    assert parsed.user_interaction == "N"
    assert parsed.scope == "U"
    assert parsed.impact_confidentiality == "H"
    assert parsed.impact_integrity == "H"
    assert parsed.impact_availability == "H"

def test_parse_legacy_v4_record():
    parsed = parse_cve(LEGACY_JSON)
    assert isinstance(parsed, CveMetadata)
    assert parsed.description == "Legacy desc"
    assert parsed.cvss == ""
    assert parsed.vector == ""
    assert parsed.severity == ""
    assert parsed.cwe == "CWE-123"
    assert parsed.severity == "High"


class DummySheet:
    def __init__(self):
        self.rows = []
        self.title = ""

    def append(self, row):
        self.rows.append(row)


class DummyWorkbook:
    def __init__(self):
        self.active = DummySheet()
        self.saved = None

    def create_sheet(self):
        self.active = DummySheet()
        return self.active

    def save(self, path):
        self.saved = path

def test_main_allows_skipping_reports(tmp_path):
    input_file = tmp_path / "cves.txt"
    input_file.write_text("CVE-1234-0001\n")
    wb = DummyWorkbook()
    with patch("cve_metadata_fetcher.fetch_cve", return_value=SAMPLE_JSON), patch(
        "cve_metadata_fetcher.Workbook", return_value=wb
    ), patch("cve_metadata_fetcher.create_report") as mock_report:
        main(
            input_file,
            output_file=tmp_path / "out.xlsx",
            reports_dir=tmp_path,
            generate_reports=False,
        )
        assert not mock_report.called
        assert wb.saved == str(tmp_path / "out.xlsx")
        # Verify header columns align with data breakdown
        expected_header = [
            "CVE ID", "Description", "CVSS", "Severity",
            "Attack Vector", "Attack Complexity", "Privileges Required",
            "User Interaction", "Scope", "Confidentiality Impact",
            "Integrity Impact", "Availability Impact", "Vector",
            "CWE", "Exploit", "ExploitRefs", "FixVersion",
            "Mitigations", "Affected", "References",
        ]
        header_row = wb.active.rows[0]
        assert header_row == expected_header
        # Check a data row matches the parsed SAMPLE_JSON values
        data_row = wb.active.rows[1]
        assert data_row[0] == "CVE-1234-0001"
        assert data_row[2] == 5.0
        assert data_row[3] == "Medium"
        assert data_row[4] == "N"
        assert data_row[5] == "L"
        assert data_row[6] == "N"
        assert data_row[7] == "N"
        assert data_row[8] == "U"
        assert data_row[9] == "N"
        assert data_row[10] == "N"
        assert data_row[11] == "N"
        assert data_row[12] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
        # CWE is "CWE-79", next fields tested elsewhere
