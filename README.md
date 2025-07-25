# ODIN (OSINT Data Intelligence Nexus)

ODIN is a comprehensive vulnerability intelligence aggregation platform that collects and structures vulnerability data from multiple authoritative OSINT sources.

## Core Philosophy

ODIN is a **data collector and aggregator**, not a decision maker. It provides comprehensive, traceable intelligence so humans can make informed security decisions.

## Key Features

- **80+ structured data fields** extracted from verified sources
- **4-layer data architecture** from authoritative sources
- **CLI-centric file-based architecture** for security and simplicity
- **Multiple export formats** (JSON, CSV, Excel) generated automatically
- **Multiple output formats** for analysis and visualization
- **Enterprise-grade version management** with automated releases

## Data Sources (4 Layers)

1. **Foundational Record**: CVEProject/cvelistV5 (canonical CVE data)
2. **Exploit Mechanics**: trickest/cve (proof-of-concept exploits)
3. **Weakness Classification**: mitre/cti (ATT&CK techniques, CAPEC patterns)
4. **Raw Intelligence**: Patrowl/PatrowlHearsData + t0sche/cvss-bt (additional feeds, threat context, CISA KEV, EPSS, temporal CVSS)

## Architecture

```
CLI Tool → ODIN Engine → Generate Output Files (JSON, CSV, Excel)
```

## Quick Start

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd odin
```

2. Install dependencies:
```bash
# Activate virtual environment (if available)
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Basic Usage

1. Create a file with CVE IDs (one per line):
```bash
echo "CVE-2021-44228" > cves.txt
echo "CVE-2023-23397" >> cves.txt
```

2. Run ODIN research:
```bash
# Make sure virtual environment is activated
source .venv/bin/activate

# Run research
python odin_cli.py cves.txt
```

3. View results in the `research_output/` directory:
   - `research_report_YYYYMMDD_HHMMSS.json` - Structured data for analysis
   - `research_report_YYYYMMDD_HHMMSS.csv` - Excel-compatible format
   - `research_report_YYYYMMDD_HHMMSS.xlsx` - Formatted spreadsheet

### Advanced Usage

```bash
# Specify custom output directory
python odin_cli.py cves.txt --output-dir /path/to/output

# Enable detailed logging
python odin_cli.py cves.txt --detailed

# Show version information
python odin_cli.py --version

# Get help
python odin_cli.py --help
```

**Note**: Make sure to activate the virtual environment first:
```bash
source .venv/bin/activate
```

### Alternative Entry Points

```bash
# Run as Python module
python -m odin cves.txt

# Import in Python code
from odin import VulnerabilityResearchEngine
```

## Output Formats

### JSON Export
Comprehensive structured data with all 80+ fields for programmatic analysis.

### CSV Export
Excel-compatible format optimized for analysis and reporting.

### Excel Export
Multi-sheet workbook with structured data organization and formatting.

## Data Fields

ODIN extracts 80+ structured data fields including:

- **Core CVE Data**: ID, description, severity scores, publication dates
- **Exploit Intelligence**: PoC availability, exploit types, GitHub repositories
- **Weakness Classification**: CWE mappings, MITRE ATT&CK techniques, CAPEC patterns
- **Threat Context**: CISA KEV status, EPSS scores, temporal CVSS metrics
- **Reference Analysis**: Vendor advisories, patches, technical details
- **Enhanced Metadata**: Problem types, impact analysis, affected systems

## Development

### Setup Development Environment

```bash
# Activate virtual environment
source .venv/bin/activate

# Install development dependencies
pip install -r requirements.txt

# Install pre-commit hooks
pre-commit install
```

### Testing

```bash
# Run test suite
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ --cov=odin --cov-report=html
```

### Quality Checks

```bash
# Complete quality check
bash scripts/quality-check.sh

# Type checking only
bash scripts/type-check.sh

# Format code
black --line-length=88 .
isort --profile=black .
```

### Version Management

```bash
# Manual version bump
python scripts/bump-version.py patch|minor|major
```

## Project Structure

```
├── odin/                   # Core Python package
│   ├── cli.py             # Command-line interface
│   ├── core/              # Research engine
│   ├── connectors/        # Data source connectors
│   ├── models/            # Data models and schemas
│   ├── reporting/         # Export generation
│   └── utils/             # Utilities and helpers
├── tests/                 # Test suite
├── scripts/               # Development and automation scripts
├── research_output/       # Generated research reports
├── odin_cli.py           # Primary CLI entry point
└── requirements.txt      # Python dependencies
```

## Technology Stack

### Core Technologies
- **Python 3.8+**: Main language for CLI and data processing

### Key Dependencies
- **aiohttp**: Async HTTP client for data source connectors
- **pandas**: Data manipulation and CSV export
- **click**: CLI framework
- **rich**: Enhanced console output and logging
- **openpyxl**: Excel file generation
- **pytest**: Testing framework with async support

## Architecture Patterns

- **Modular connector system**: Each data source has its own connector
- **Async/await**: All data fetching is asynchronous
- **Session caching**: Prevents redundant API calls during batch processing
- **Graceful degradation**: Continues with partial data when sources unavailable
- **File-based architecture**: CLI generates multiple output formats (JSON, CSV, Excel)

## What ODIN IS NOT

- Vulnerability scanner or discovery tool
- Risk scoring or prioritization engine
- Real-time threat monitoring system
- Decision-making or recommendation system

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run quality checks: `bash scripts/quality-check.sh`
5. Submit a pull request

## License

See [LICENSE](LICENSE) file for details.

## Version

Current version: **1.0.3** (Foundation)
Build: 20250618.3

For version history and compatibility information, see `odin/version.py`.