from unittest.mock import patch

import pytest

import sys
from pathlib import Path

import types

class DummyParagraph:
    def __init__(self, text=""):
        self.text = text


class DummyDocument:
    def __init__(self, *_, **__):
        self.paragraphs = [
            DummyParagraph("CVE ID:"),
            DummyParagraph("Brief summary of the vulnerability."),
            DummyParagraph("List of affected products or environments."),
            DummyParagraph("Describe exploit vectors"),
            DummyParagraph("Document any known fixes"),
            DummyParagraph("List external references"),
        ]

    def save(self, *args, **_kwargs):
        self.saved = args[0] if args else None


class DummyWorksheet:
    def __init__(self):
        self.rows = []
        self.title = ""

    def append(self, row):
        self.rows.append(row)


class DummyWorkbook:
    def __init__(self, *_, **__):
        self.active = DummyWorksheet()

    def save(self, *_args, **_kwargs):
        pass


sys.modules.setdefault(
    "requests", types.SimpleNamespace(RequestException=Exception, get=lambda *a, **k: None)
)
sys.modules.setdefault("docx", types.SimpleNamespace(Document=DummyDocument))
sys.modules.setdefault("openpyxl", types.SimpleNamespace(Workbook=DummyWorkbook))

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import os

from cve_metadata_fetcher import CveMetadata, create_report, fetch_cve, parse_cve


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


def test_create_report_runs(tmp_path, monkeypatch):
    template = tmp_path / "CVE_Report_Template.docx"
    template.write_text("dummy")
    monkeypatch.chdir(tmp_path)

    dummy = DummyDocument()
    monkeypatch.setattr('cve_metadata_fetcher.Document', lambda *_: dummy)

    meta = CveMetadata(description="desc")
    create_report("CVE-0000-0001", meta)
    assert hasattr(dummy, "saved")
    assert dummy.saved.name == "CVE-0000-0001.docx"

