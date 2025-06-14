# CVE Research Toolkit - Development Workflow Automation
.PHONY: help install install-dev format lint type-check test test-cov security clean all check setup-hooks

# Default target
help:
	@echo "CVE Research Toolkit - Development Commands"
	@echo "==========================================="
	@echo ""
	@echo "Setup Commands:"
	@echo "  install      Install production dependencies"
	@echo "  install-dev  Install development dependencies"
	@echo "  setup-hooks  Install pre-commit hooks"
	@echo ""
	@echo "Code Quality Commands:"
	@echo "  format       Format code with black and isort"
	@echo "  lint         Run flake8 linting"
	@echo "  type-check   Run mypy static type checking"
	@echo "  security     Run bandit security scanning"
	@echo ""
	@echo "Testing Commands:"
	@echo "  test         Run all tests"
	@echo "  test-cov     Run tests with coverage report"
	@echo "  test-unit    Run unit tests only"
	@echo "  test-integration Run integration tests only"
	@echo ""
	@echo "Workflow Commands:"
	@echo "  check        Run all quality checks (format, lint, type-check, test)"
	@echo "  all          Run complete development workflow"
	@echo "  clean        Clean temporary files and caches"

# Installation commands
install:
	pip install -e .

install-dev:
	pip install -e .[dev]
	pip install pre-commit

setup-hooks: install-dev
	pre-commit install
	pre-commit install --hook-type commit-msg

# Code formatting
format:
	@echo "🎨 Formatting code with black..."
	black cve_research_toolkit_fixed.py test_research_comprehensive.py
	@echo "🔄 Sorting imports with isort..."
	isort cve_research_toolkit_fixed.py test_research_comprehensive.py
	@echo "✅ Code formatting complete!"

# Linting
lint:
	@echo "🔍 Running flake8 linting..."
	flake8 cve_research_toolkit_fixed.py test_research_comprehensive.py
	@echo "✅ Linting complete!"

# Static type checking
type-check:
	@echo "🔬 Running mypy static type checking..."
	mypy cve_research_toolkit_fixed.py --ignore-missing-imports --strict
	@echo "✅ Type checking complete!"

# Security scanning
security:
	@echo "🛡️  Running bandit security scanning..."
	bandit -r cve_research_toolkit_fixed.py -f json -o bandit-report.json
	@echo "✅ Security scanning complete! Report saved to bandit-report.json"

# Testing
test:
	@echo "🧪 Running comprehensive tests..."
	python test_research_comprehensive.py
	@echo "✅ All tests passed!"

test-cov:
	@echo "🧪 Running tests with coverage..."
	pytest test_research_comprehensive.py --cov=. --cov-report=html --cov-report=term
	@echo "✅ Tests with coverage complete! Report in htmlcov/"

test-unit:
	@echo "🧪 Running unit tests..."
	pytest test_research_comprehensive.py -m "not integration"
	@echo "✅ Unit tests complete!"

test-integration:
	@echo "🧪 Running integration tests..."
	pytest test_research_comprehensive.py -m "integration"
	@echo "✅ Integration tests complete!"

# Combined quality checks
check: format lint type-check test
	@echo ""
	@echo "🎉 All quality checks passed!"
	@echo "   ✅ Code formatted"
	@echo "   ✅ Linting passed"
	@echo "   ✅ Type checking passed"
	@echo "   ✅ Tests passed"

# Complete development workflow
all: clean install-dev setup-hooks check security
	@echo ""
	@echo "🚀 Complete development workflow finished!"
	@echo "   ✅ Dependencies installed"
	@echo "   ✅ Pre-commit hooks configured"
	@echo "   ✅ Code quality checks passed"
	@echo "   ✅ Security scanning complete"

# Cleanup
clean:
	@echo "🧹 Cleaning temporary files..."
	rm -rf __pycache__/
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf htmlcov/
	rm -rf .coverage
	rm -rf *.egg-info/
	rm -rf build/
	rm -rf dist/
	rm -f bandit-report.json
	find . -name "*.pyc" -delete
	find . -name "*.pyo" -delete
	@echo "✅ Cleanup complete!"

# Development server (for future web interface)
dev-server:
	@echo "🖥️  Starting development server..."
	python cve_research_toolkit_fixed.py --help

# Quick workflow validation
quick-check: format lint type-check
	@echo "⚡ Quick quality check complete!"

# Pre-commit hook validation
validate-hooks:
	@echo "🔗 Validating pre-commit hooks..."
	pre-commit run --all-files
	@echo "✅ Pre-commit validation complete!"

# Documentation generation (future)
docs:
	@echo "📚 Documentation generation not yet implemented"

# Package building (future)
build:
	@echo "📦 Building package..."
	python -m build
	@echo "✅ Package built successfully!"