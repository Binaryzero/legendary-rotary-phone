# ODIN (OSINT Data Intelligence Nexus)

**ODIN v1.0.2** - A comprehensive vulnerability intelligence aggregation platform that collects and structures vulnerability data from multiple authoritative OSINT sources. ODIN focuses on data collection and aggregation, not prioritization or risk scoring, enabling researchers to make informed decisions with complete intelligence context.

## 🎯 What ODIN Does

ODIN aggregates vulnerability intelligence from **5 authoritative data layers** and presents it through multiple interfaces:

- **80+ structured data fields** extracted from verified sources
- **Professional web interface** with advanced filtering and search
- **Command-line toolkit** for automated research workflows  
- **Multiple export formats** (JSON, CSV, Excel, WebUI) for analysis
- **Enterprise-grade version management** with automated releases

### Core Philosophy
ODIN is a **data collector and aggregator**, not a decision maker. It provides comprehensive, traceable intelligence so humans can make informed security decisions.

## 🏗️ Architecture Overview

### **5-Layer Data Architecture**

| Layer | Source | Intelligence Provided |
|-------|--------|----------------------|
| **1. Foundational Record** | CVEProject/cvelistV5 | Canonical CVE data, CVSS metrics, official references |
| **2. Exploit Mechanics** | trickest/cve | Proof-of-concept exploits, exploit maturity assessment |
| **3. Weakness Classification** | mitre/cti | ATT&CK techniques, CAPEC patterns, enhanced descriptions |
| **4. Threat Context** | t0sche/cvss-bt | CISA KEV, temporal CVSS, exploitation indicators |
| **5. Raw Intelligence** | Patrowl/PatrowlHearsData | Additional feeds and validation data |

### **Current Capabilities (80 Fields)**
- **Enhanced CVE Intelligence**: CVSS version, alternative scores, reference categorization
- **Product Intelligence**: Vendor/product/version/platform extraction  
- **Enhanced Problem Classification**: Structured weakness analysis beyond CWE
- **MITRE Enhancement**: Human-readable technique/tactic/CAPEC descriptions
- **Exploit Intelligence**: Verification status, enhanced titles, reliability assessment
- **Control Mappings**: NIST 800-53 control relationships

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- Node.js 16+ and npm (for web interface)
- Internet connection for vulnerability data sources

### Installation

```bash
# Clone repository
git clone https://github.com/Binaryzero/legendary-rotary-phone.git
cd legendary-rotary-phone

# Install dependencies
pip install -r requirements.txt
cd frontend && npm install && cd ..
```

### Basic Usage

#### Command-Line Interface
```bash
# Research a single CVE
echo "CVE-2021-44228" > cves.txt
python odin_cli.py cves.txt --format json

# Batch research with CSV export  
python odin_cli.py cves.txt --format csv --output research_results.csv

# Get version information
python odin_cli.py --version
```

#### Web Interface
```bash
# Start full web interface (backend + frontend)
python start_odin_ui.py

# Custom ports
python start_odin_ui.py --backend-port 8080 --frontend-port 3001
```

The web interface will be available at `http://localhost:3000` with API documentation at `http://localhost:8000/docs`.

## 📊 Export Formats

### JSON Export (Comprehensive)
```bash
python odin_cli.py cves.txt --format json
```
- All 80+ fields with structured data
- Version metadata for traceability
- Nested objects for complex intelligence

### CSV Export (Excel-Compatible)
```bash
python odin_cli.py cves.txt --format csv
```
- Flattened structure for spreadsheet analysis
- All fields with proper sanitization
- Excel-compatible formatting

### WebUI Export (Visualization-Ready)
```bash
python odin_cli.py cves.txt --format webui
```
- Optimized for web interface visualization
- Timestamp-based file naming
- Enhanced metadata structure

## 🛠️ Development

### Running Tests
```bash
# Install test dependencies
pip install -r requirements.txt

# Run test suite
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ --cov=odin --cov-report=html
```

### Code Quality Tools
```bash
# Type checking
python scripts/type-check.sh

# Quality checks
python scripts/quality-check.sh

# Manual version bump
python scripts/bump-version.py patch
```

### Project Structure
```
odin/                   # Core package
├── core/               # Research engine
├── connectors/         # Data source connectors  
├── models/            # Data models and schemas
├── reporting/         # Export generation
└── utils/            # Utilities and helpers

backend/               # FastAPI backend
frontend/             # React TypeScript UI
tests/                # Test suite
scripts/              # Development tools
docs/                 # Documentation
```

## 📈 Version Management

ODIN uses **enterprise-grade version management** with automatic releases:

- **Semantic Versioning**: major.minor.patch format
- **Automatic Updates**: PR merges trigger version bumps based on labels
- **GitHub Releases**: Automated release creation with download packages
- **Version Tracking**: All exports include version metadata

### Current Version: v1.0.2
- **Build**: 20250618.2
- **Release Date**: 2025-06-18  
- **Data Model**: v1.0
- **Enhanced Fields**: v1.0

## 🔒 Security Considerations

**⚠️ IMPORTANT**: ODIN is currently in development with **known security limitations**:

- No authentication or authorization implemented
- Input validation needs enhancement  
- Not recommended for production deployment without security hardening
- See [SECURITY.md](SECURITY.md) for current security status

## 📋 Data Sources

### Authoritative Sources
| Repository | Layer | Purpose | Update Frequency |
|------------|-------|---------|------------------|
| **CVEProject/cvelistV5** | Foundation | Official CVE records | Daily |
| **trickest/cve** | Exploit | Proof-of-concept exploits | Continuous |
| **mitre/cti** | Classification | ATT&CK/CAPEC knowledge | Weekly |
| **t0sche/cvss-bt** | Threat Context | CISA KEV, temporal metrics | Daily |
| **Patrowl/PatrowlHearsData** | Intelligence | Additional feeds | Varies |

### Data Quality Standards
- **Institutional Sources Preferred**: Authoritative, maintained sources
- **Graceful Degradation**: Continues with partial data when sources unavailable
- **Session Caching**: Prevents redundant API calls during batch processing
- **Error Handling**: Comprehensive logging and fallback mechanisms

## 🤝 Contributing

We welcome contributions! Please see our development guidelines:

1. **Evidence-Based Development**: Verify data source capabilities before implementation
2. **Quality Over Quantity**: Prefer reliable fields over speculative features  
3. **User-Centric Design**: Focus on practical vulnerability research workflows
4. **Security First**: Consider security implications in all contributions

### Development Process
1. Fork the repository
2. Create feature branch with descriptive name
3. Add tests for new functionality
4. Run quality checks and tests
5. Submit PR with appropriate labels (major/minor/patch)
6. Version management handles automatic updates

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Issues**: Report bugs and feature requests on [GitHub Issues](https://github.com/Binaryzero/legendary-rotary-phone/issues)
- **Documentation**: See [docs/](docs/) directory for detailed documentation
- **API Reference**: Available at `/docs` endpoint when backend is running

## 🎯 Philosophy: Data Collection, Not Decision Making

ODIN embodies the principle that **comprehensive data enables better human decisions**. Rather than algorithmic black boxes that make prioritization decisions, ODIN provides transparent, traceable intelligence that security professionals can validate and reason about.

**What ODIN IS:**
- Comprehensive vulnerability intelligence aggregator
- Multi-source data collector with structured output
- Research tool for security professionals
- Foundation for informed human decision-making

**What ODIN IS NOT:**
- Vulnerability scanner or discovery tool
- Risk scoring or prioritization engine  
- Real-time threat monitoring system
- Decision-making or recommendation system

---

## 📊 Current Status

**Core Functionality**: ✅ Complete - All enhanced fields operational  
**Export System**: ✅ JSON/WebUI working, CSV functional
**Version Management**: ✅ Complete - Automatic updates operational  
**Release Automation**: ✅ Complete - GitHub releases working
**Security Status**: ⚠️ Development - Security hardening in progress
**Field Coverage**: **80 fields** from 5 authoritative sources

**ODIN provides the intelligence. You make the decisions.**