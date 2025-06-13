from unittest.mock import patch

import pytest

import sys
from pathlib import Path

import types

sys.modules.setdefault(
    "requests", types.SimpleNamespace(RequestException=Exception, get=lambda *a, **k: None)
)
sys.modules.setdefault("docx", types.SimpleNamespace(Document=lambda *a, **k: None))
sys.modules.setdefault("openpyxl", types.SimpleNamespace(Workbook=lambda *a, **k: None))

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cve_metadata_fetcher import CveMetadata, fetch_cve, parse_cve, main


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
        assert wb.active.rows

