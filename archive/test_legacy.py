#!/usr/bin/env python3
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).parent))
from cve_metadata_fetcher import parse_cve
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
parsed = parse_cve(LEGACY_JSON)
print(parsed)
