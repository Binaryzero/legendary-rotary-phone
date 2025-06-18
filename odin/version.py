"""ODIN Version Management

This module centralizes version information for ODIN (OSINT Data Intelligence Nexus).
Version is automatically updated with each PR merge.
"""

from datetime import datetime
from typing import Dict, Any

# Core version information
__version__ = "1.0.3"
__build__ = "20250618.3"  # YYYYMMDD.build_number
__git_commit__ = "ce3b98d589dd6a6934c0f5a8344896d0844aa995"  # Updated by CI/CD
__release_date__ = "2025-06-18"
__release_name__ = "Foundation"

# Feature compatibility information
DATA_MODEL_VERSION = "1.0"  # Changes when data models are modified
API_VERSION = "1.0"  # Changes when API contracts change
EXPORT_FORMAT_VERSION = "1.0"  # Changes when export formats change

# Component versions (for compatibility checking)
ENHANCED_FIELDS_VERSION = "1.0"  # Phase 1 enhanced fields
UI_ARCHITECTURE_VERSION = "2.0"  # After modular refactor
CONNECTOR_SYSTEM_VERSION = "1.0"  # Modular connector architecture

def get_version_info() -> Dict[str, Any]:
    """Get comprehensive version information."""
    return {
        "version": __version__,
        "build": __build__,
        "git_commit": __git_commit__,
        "release_date": __release_date__,
        "release_name": __release_name__,
        "data_model_version": DATA_MODEL_VERSION,
        "api_version": API_VERSION,
        "export_format_version": EXPORT_FORMAT_VERSION,
        "enhanced_fields_version": ENHANCED_FIELDS_VERSION,
        "ui_architecture_version": UI_ARCHITECTURE_VERSION,
        "connector_system_version": CONNECTOR_SYSTEM_VERSION,
        "build_timestamp": datetime.now().isoformat()
    }

def get_version_string() -> str:
    """Get a formatted version string for display."""
    return f"ODIN v{__version__} ({__release_name__}) Build {__build__}"

def check_compatibility(required_version: str) -> bool:
    """Check if current version meets minimum requirements."""
    try:
        from packaging import version
        return version.parse(__version__) >= version.parse(required_version)
    except ImportError:
        # Fallback to string comparison if packaging not available
        return __version__ >= required_version

# Version history for reference
VERSION_HISTORY = [
    
    
    {
        "version": "1.0.3",
        "build": "20250618.3",
        "date": "2025-06-18",
        "name": "TBD",
        "changes": ['Fix critical export format gaps and documentation inaccuracies']
    },{
        "version": "1.0.2",
        "build": "20250618.2",
        "date": "2025-06-18",
        "name": "TBD",
        "changes": ['feat: Deploy modern release automation and workflow fixes']
    },{
        "version": "1.0.1",
        "build": "20250618.1",
        "date": "2025-06-18",
        "name": "TBD",
        "changes": ['Dev 2 odin']
    },{
        "version": "1.0.0",
        "build": "20250617.2",
        "date": "2025-06-17",
        "name": "Foundation",
        "changes": [
            "Data pipeline crisis resolution - engine mapping bug fix",
            "JSON export enhancement - all Phase 1 enhanced fields included",
            "CSV export Excel compatibility verified",
            "Complete modular architecture consolidation",
            "25/25 tests passing with full functionality"
        ]
    }
]