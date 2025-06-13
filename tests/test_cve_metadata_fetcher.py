import os
import sys
import json
from unittest.mock import patch, Mock

import pytest

from cve_metadata_fetcher import parse_cve, fetch_cve


SAMPLE_CVE_DATA = {


def test_parse_cve_extracts_fields():
    parsed = parse_cve(SAMPLE_JSON)
    assert parsed["Description"] == "Sample description"
    assert parsed["CVSS"] == 5.0
    assert parsed["Vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
    assert parsed["CWE"] == "CWE-79"
    assert parsed["Exploit"] == "Yes"
    assert parsed["ExploitRefs"] == "https://exploit-db.com/exploits/1"
    assert parsed["FixVersion"] == "https://example.com/patch"
    assert parsed["Mitigations"] == "https://vendor.com/advisories/123"


def test_fetch_cve_returns_none_on_failure():
    with patch('cve_metadata_fetcher.requests.get') as mock_get:
        mock_response = Mock(status_code=404)
        mock_get.return_value = mock_response
        assert fetch_cve('CVE-0000-0000') is None

