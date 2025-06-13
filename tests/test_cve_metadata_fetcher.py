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


class DummyCell:
    def __init__(self, value=""):
        self.value = value
        self.font = None


class DummyColumnDimension:
    def __init__(self):
        self.width = None


class DummyWorksheet:
    def __init__(self):
        self.rows = []
        self.title = ""
        self.column_dimensions = {}
        self.freeze_panes = None

    def append(self, row):
        self.rows.append([DummyCell(v) for v in row])

    def __getitem__(self, idx):
        if isinstance(idx, int):
            return self.rows[idx - 1]
        raise TypeError("Invalid index")

    @property
    def max_row(self):
        return len(self.rows)

    @property
    def max_column(self):
        return len(self.rows[0]) if self.rows else 0

    def iter_cols(self, min_row=1, max_col=None, max_row=None):
        max_col = max_col or self.max_column
        max_row = max_row or self.max_row
        cols = zip(*[row[:max_col] for row in self.rows[min_row - 1:max_row]])
        for col in cols:
            yield list(col)


class DummyWorkbook:
    def __init__(self, *_, **__):
        self.active = DummyWorksheet()

    def save(self, *_args, **_kwargs):
        pass


sys.modules.setdefault(
    "requests",
    types.SimpleNamespace(
        RequestException=Exception,
        get=lambda *a, **k: None,
        Session=lambda: types.SimpleNamespace(get=lambda *a, **k: None, close=lambda: None),
    ),
)
sys.modules.setdefault("docx", types.SimpleNamespace(Document=DummyDocument))
sys.modules.setdefault(
    "openpyxl",
    types.SimpleNamespace(
        Workbook=DummyWorkbook,
    ),
)
sys.modules.setdefault("openpyxl.styles", types.SimpleNamespace(Font=lambda *a, **k: None))

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
    assert parsed.cvss == "5.0"
    assert parsed.vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
    assert parsed.cwe == "CWE-79"
    assert parsed.exploit == "Yes"
    assert parsed.exploit_refs == "https://exploit-db.com/exploits/1"
    assert parsed.fix_version == "https://example.com/patch"
    assert parsed.mitigations == "https://vendor.com/advisories/123"
    assert parsed.affected == "Acme App 1.0"


def test_parse_cve_handles_missing_lists():
    empty_lists = {
        "containers": {
            "cna": {
                "descriptions": [],
                "metrics": [],
                "problemTypes": [],
                "references": [],
                "affected": [],
            }
        }
    }
    parsed = parse_cve(empty_lists)
    assert parsed.description == ""
    assert parsed.cvss == ""
    assert parsed.vector == ""
    assert parsed.cwe == ""


def test_fetch_cve_returns_none_on_failure():
    with patch("cve_metadata_fetcher.requests.Session") as mock_session:
        mock_instance = mock_session.return_value
        mock_instance.get.side_effect = Exception("fail")
        assert fetch_cve("CVE-0000-0000") is None

def test_fetch_cve_invalid_format_ignored():
    with patch("cve_metadata_fetcher.requests.Session") as mock_session:
        assert fetch_cve("BADFORMAT") is None
        mock_session.assert_not_called()


def test_create_report_runs(tmp_path, monkeypatch):
    template = tmp_path / "CVE_Report_Template.docx"
    template.write_text("dummy")
    monkeypatch.chdir(tmp_path)

    dummy = DummyDocument()
    monkeypatch.setattr('cve_metadata_fetcher.Document', lambda *_: dummy)

    meta = CveMetadata(description="desc")
    create_report("CVE-0000-0001", meta, template, Path("."))
    assert hasattr(dummy, "saved")
    assert dummy.saved.name == "CVE-0000-0001.docx"

