# CVE Research Toolkit

This repository provides a collection of utilities for performing vulnerability research across multiple open source intelligence feeds. The toolkit aggregates information from several data layers and exposes a backend API together with a React based user interface.

## Prerequisites

Before you begin, ensure you have the following installed:
- Python 3.x
- Node.js and npm

## Components

### Backend
- **File**: `backend/app.py`
- **Framework**: FastAPI
- Provides endpoints for researching CVEs, retrieving stored results and viewing summary analytics.
- Uses in‑memory storage for demo purposes.

### Frontend
- **Directory**: `frontend/`
- React application written in TypeScript.
- Communicates with the FastAPI backend to display vulnerability data.

### Starting the full UI
The helper script `start_ui.py` installs requirements and launches both the backend and frontend.

```bash
# install Python and Node dependencies
python start_ui.py --install

# start the API on port 8000 and the frontend on port 3000
python start_ui.py
```

To customise ports use `--backend-port` and `--frontend-port`.

Once the backend is running, API documentation is typically available at `http://localhost:8000/docs`.

## Development
Install Python dependencies and run tests using `pytest`:

```bash
pip install -r requirements.txt
python -m pytest
Install Python dependencies and run tests using `pytest`:

This project uses several tools for maintaining code quality, including `flake8`, `black`, `isort`, and `mypy`. These are often managed via `pre-commit` to ensure checks are run before commits.

To run all pre-commit hooks:
```bash
pre-commit run --all-files

The tests are located in the `tests/` directory and exercise both the toolkit libraries and error handling utilities.
