# ODIN Release Package

This is the complete ODIN (OSINT Data Intelligence Nexus) release package.

## Quick Installation

### Linux/Mac
```bash
./install.sh
```

### Windows
```batch
install.bat
```

## Manual Installation

1. **Install Python 3.8+** (if not already installed)
2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
3. **Make scripts executable** (Linux/Mac):
   ```bash
   chmod +x odin_cli.py start_odin_ui.py
   ```

## Quick Start

### CLI Research
```bash
# Research a single CVE
echo "CVE-2021-44228" > cves.txt
python odin_cli.py cves.txt --format json

# Multiple CVEs
python odin_cli.py cves.txt --format csv --detailed
```

### Web Interface
```bash
# Start the web UI
python start_odin_ui.py
# Open http://localhost:3000 in your browser
```

### API Server
```bash
# Start the backend API
cd backend
python app.py
# API available at http://localhost:8000
```

## What's Included

- **CLI Tool** (`odin_cli.py`) - Command-line vulnerability research
- **Web UI** (`start_odin_ui.py`) - Browser-based analysis interface
- **API Backend** (`backend/`) - FastAPI server for data access
- **Core Package** (`odin/`) - Main research engine and connectors
- **Frontend** (`frontend/`) - React web interface
- **Scripts** (`scripts/`) - Utility scripts and tools
- **Tests** (`tests/`) - Comprehensive test suite
- **Documentation** (`docs/`) - Complete usage and API documentation

## Getting Help

```bash
# CLI help
python odin_cli.py --help

# Version information
python odin_cli.py --version

# API documentation (when backend running)
# Visit http://localhost:8000/docs
```

## Requirements

- Python 3.8 or higher
- Internet connection for vulnerability data sources
- ~100MB disk space
- 2GB RAM recommended for large datasets

## Troubleshooting

### Common Issues

**Import Errors:**
```bash
pip install -r requirements.txt
```

**Permission Errors (Linux/Mac):**
```bash
chmod +x odin_cli.py start_odin_ui.py
```

**Port Already in Use:**
- Web UI: Edit `start_odin_ui.py` to change port
- API: Edit `backend/app.py` to change port

For more help, see the documentation in the `docs/` directory.