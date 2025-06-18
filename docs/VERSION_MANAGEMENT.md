# ODIN Version Management System

## Overview

ODIN implements a comprehensive version management system that automatically tracks versions, builds, and component compatibility across PR merges. This system provides "old version" detection and ensures proper version tracking for all releases.

## Components

### 1. Central Version Module (`odin/version.py`)

**Core Version Information:**
- `__version__`: Semantic version (e.g., "1.0.0")
- `__build__`: Build identifier with date and number (e.g., "20250617.2")
- `__git_commit__`: Git commit hash (auto-updated)
- `__release_date__`: Release date
- `__release_name__`: Release codename

**Component Compatibility Versions:**
- `DATA_MODEL_VERSION`: Changes when data models are modified
- `API_VERSION`: Changes when API contracts change
- `EXPORT_FORMAT_VERSION`: Changes when export formats change
- `ENHANCED_FIELDS_VERSION`: Phase 1 enhanced fields compatibility
- `UI_ARCHITECTURE_VERSION`: UI component architecture version
- `CONNECTOR_SYSTEM_VERSION`: Modular connector system version

### 2. Version Display Integration

**CLI Version Display:**
```bash
# Show detailed version information
python odin_cli.py --version

# Version shown in startup banner
ODIN v1.0.2 (Foundation) Build 20250618.2
```

**Backend API Version Endpoint:**
```bash
GET /api/version
# Returns complete version information JSON
```

**JSON Export Metadata:**
All JSON exports include comprehensive version metadata:
```json
{
  "metadata": {
    "version": "1.0.0",
    "build": "20250617.2", 
    "git_commit": "34c43b2e",
    "data_model_version": "1.0",
    "export_timestamp": "2025-06-17T19:09:44.897574",
    "format": "ODIN JSON Export"
  },
  "data": [...]
}
```

### 3. Automatic Version Updates

**Manual Version Bump Script:**
```bash
# Increment version types
python scripts/bump-version.py patch    # 1.0.0 -> 1.0.1
python scripts/bump-version.py minor    # 1.0.0 -> 1.1.0  
python scripts/bump-version.py major    # 1.0.0 -> 2.0.0
python scripts/bump-version.py build    # Only increment build number

# With change description
python scripts/bump-version.py patch --changes "Fix critical data pipeline bug" "Add JSON export metadata"
```

**GitHub Actions Workflow (`.github/workflows/version-update.yml`):**
- Automatically triggers on PR merge to main branch
- Determines version bump type from PR labels:
  - `major`: Breaking changes (1.0.0 -> 2.0.0)
  - `minor`: New features (1.0.0 -> 1.1.0)  
  - `patch`: Bug fixes (1.0.0 -> 1.0.1)
  - Default: patch for unlabeled PRs
- Updates version.py with PR title as change description
- Commits version update and creates git tag
- Updates git commit hash automatically

### 4. Version History Tracking

**VERSION_HISTORY Array:**
Maintains complete changelog with version entries:
```python
VERSION_HISTORY = [
    {
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
```

### 5. Compatibility Checking

**Version Compatibility Function:**
```python
from odin.version import check_compatibility

# Check if current version meets requirements
if check_compatibility("1.0.0"):
    # Proceed with feature that requires v1.0.0+
    pass
```

**Component Version Validation:**
- Data model compatibility for import/export operations
- API version validation for client integrations
- Export format compatibility warnings
- Enhanced fields version checking

## Usage Patterns

### For Developers

**Before Creating PR:**
1. Run manual version bump if needed: `python scripts/bump-version.py patch`
2. Add appropriate labels to PR (`major`, `minor`, `patch`)
3. GitHub Actions will auto-update version on merge

**Version Display:**
```python
from odin import get_version_string, get_version_info

print(get_version_string())  # "ODIN v1.0.2 (Foundation) Build 20250618.2"
version_data = get_version_info()  # Complete version dictionary
```

### For Users

**Check Version:**
```bash
python odin_cli.py --version
curl http://localhost:8000/api/version  # If backend running
```

**"Old Version" Detection:**
- CLI displays current version in startup banner
- JSON exports include version metadata for verification
- API provides version endpoint for client compatibility checks
- Error messages can include version for support requests

### For CI/CD

**Automated Workflow:**
1. PR merged to main branch
2. GitHub Actions determines bump type from labels
3. Version bumped and committed automatically
4. Git tag created (e.g., `v1.0.0`)
5. Version history updated with PR changes

## Benefits

### Professional Version Management
- Semantic versioning with build numbers
- Automatic git commit hash tracking
- Component-specific compatibility versions
- Complete changelog maintenance

### "Old Version" Detection
- Users can easily verify they have current version
- Export files include version metadata for validation
- API clients can check compatibility
- Support requests include version information

### Developer Workflow Integration
- Manual and automatic version updates
- PR-driven version increments
- Git tag creation for releases
- Version history with change tracking

### Enterprise Compatibility
- API version validation for integrations
- Data model compatibility checking
- Export format version tracking
- Component upgrade path planning

## Implementation Status

 **Completed:**
- Central version module with all metadata
- CLI version display and --version flag
- Backend API version endpoint
- JSON export version metadata
- Manual version bump script
- GitHub Actions automatic version updates
- GitHub Actions automatic release creation
- Version history tracking
- Component compatibility versions
- Test suite updated for new JSON format
- GitHub repository configured with major/minor/patch labels
- Complete release automation with download packages

 **Ready for Use:**
- Complete version management system functional (v1.0.2 operational)
- 25/25 tests passing with version integration
- Manual and automatic version updates working
- All version display methods operational
- GitHub repository fully configured with labels
- Automatic release creation with professional packages tested
- Complete workflow from PR merge to downloadable release verified

## GitHub Integration Status

 **Repository Configuration Complete:**
- GitHub labels configured: `major`, `minor`, `patch`
- GitHub Actions workflows active and tested
- Automatic version bump on PR merge operational
- Automatic release creation with download packages functional

**Usage Pattern:**
1. Create PR and add appropriate label (`major`, `minor`, or `patch`)
2. Merge PR to main branch
3. GitHub Actions automatically:
   - Updates version in `odin/version.py`
   - Commits version update
   - Creates git tag (e.g., `v1.0.1`)
   - Creates GitHub release with download package
   - Includes professional release notes and installation scripts

This version management system provides enterprise-grade version tracking with automatic updates and professional release distribution, ensuring users always know their ODIN version and can easily download the latest release.