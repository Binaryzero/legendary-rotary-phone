from unittest.mock import patch

import pytest

import sys
from pathlib import Path
import importlib
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
        cells = [DummyCell(v) for v in row]
        self.rows.append(cells)
        for idx in range(len(cells)):
            letter = chr(65 + idx)
            self.column_dimensions.setdefault(letter, DummyColumnDimension())

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


class DummySession:
    def get(self, *a, **k):
        return types.SimpleNamespace(json=lambda: {}, raise_for_status=lambda: None)

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()


class DummyFont:
    pass


@pytest.fixture
def fetcher(monkeypatch):
    """Import ``cve_metadata_fetcher`` with stubbed external modules."""
    req = types.ModuleType("requests")
    req.RequestException = Exception
    req.Session = DummySession

    docx_mod = types.ModuleType("docx")
    docx_mod.Document = DummyDocument

    openpyxl_mod = types.ModuleType("openpyxl")
    openpyxl_mod.Workbook = DummyWorkbook
    styles_mod = types.ModuleType("openpyxl.styles")
    styles_mod.Font = lambda *a, **k: DummyFont()
    utils_mod = types.ModuleType("openpyxl.utils")
    utils_mod.get_column_letter = lambda i: chr(64 + i)

    monkeypatch.setitem(sys.modules, "requests", req)
    monkeypatch.setitem(sys.modules, "docx", docx_mod)
    monkeypatch.setitem(sys.modules, "openpyxl", openpyxl_mod)
    monkeypatch.setitem(sys.modules, "openpyxl.styles", styles_mod)
    monkeypatch.setitem(sys.modules, "openpyxl.utils", utils_mod)
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1]))

    module = importlib.import_module("cve_metadata_fetcher")
    importlib.reload(module)
    return module


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


def test_parse_cve_extracts_fields(fetcher):
    parsed = fetcher.parse_cve(SAMPLE_JSON)
    assert isinstance(parsed, fetcher.CveMetadata)
    assert parsed.description == "Sample description"
    assert parsed.cvss == "5.0"
    assert parsed.vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
    assert parsed.cwe == "CWE-79"
    assert parsed.exploit == "Yes"
    assert parsed.exploit_refs == "https://exploit-db.com/exploits/1"
    assert parsed.fix_version == "https://example.com/patch"
    assert parsed.mitigations == "https://vendor.com/advisories/123"
    assert parsed.affected == "Acme App 1.0"


def test_parse_cve_handles_missing_lists(fetcher):
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
    parsed = fetcher.parse_cve(empty_lists)
    assert parsed.description == ""
    assert parsed.cvss == ""
    assert parsed.vector == ""
    assert parsed.cwe == ""


def test_fetch_cve_returns_none_on_failure(fetcher):
    with patch("cve_metadata_fetcher.requests.Session") as mock_session:
        mock_instance = mock_session.return_value
        mock_instance.get.side_effect = Exception("fail")
        assert fetcher.fetch_cve("CVE-0000-0000") is None

def test_fetch_cve_invalid_format_ignored(fetcher):
    with patch("cve_metadata_fetcher.requests.Session") as mock_session:
        assert fetcher.fetch_cve("BADFORMAT") is None
        mock_session.assert_not_called()


def test_create_report_runs(fetcher, tmp_path, monkeypatch):
    template = tmp_path / "CVE_Report_Template.docx"
    template.write_text("dummy")
    monkeypatch.chdir(tmp_path)

    dummy = DummyDocument()
    monkeypatch.setattr(fetcher, 'Document', lambda *_: dummy)

    meta = fetcher.CveMetadata(
        description="desc",
        affected="aff",
        cvss="5.0",
        vector="v",
        cwe="CWE-1",
        exploit="Yes",
        exploit_refs="ref",
        fix_version="fix",
        mitigations="mit",
        references="ref2",
    )
    fetcher.create_report("CVE-0000-0001", meta, template, Path("."))
    assert hasattr(dummy, "saved")
    assert dummy.saved.name == "CVE-0000-0001.docx"
    assert dummy.paragraphs[0].text == "CVE ID: CVE-0000-0001"
    assert dummy.paragraphs[1].text == meta.description
    assert dummy.paragraphs[2].text == meta.affected
    exp_txt = (
        f"CVSS: {meta.cvss} ({meta.vector})\n"
        f"CWE: {meta.cwe}\n"
        f"Exploit Available: {meta.exploit} {meta.exploit_refs}"
    )
    assert dummy.paragraphs[3].text == exp_txt
    assert dummy.paragraphs[4].text == f"Fix: {meta.fix_version}\nMitigations: {meta.mitigations}"
    assert dummy.paragraphs[5].text == meta.references


def test_main_skip_docs(fetcher, monkeypatch, tmp_path):
    input_file = tmp_path / "cves.txt"
    input_file.write_text("CVE-1111-2222")

    monkeypatch.setattr(fetcher, 'fetch_cve', lambda *_: SAMPLE_JSON)

    called = False

    def fake_report(*_args, **_kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr(fetcher, 'create_report', fake_report)

    fetcher.main(
        input_file,
        excel_out=tmp_path / "out.xlsx",
        template_path=tmp_path / "template.docx",
        report_dir=tmp_path / "reports",
        write_reports=False,
    )

    assert not called

