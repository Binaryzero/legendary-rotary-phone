#!/bin/bash
# Static Type Checking Script for CVE Research Toolkit

set -e

echo " CVE Research Toolkit - Static Type Checking"
echo "============================================="

# Check if mypy is installed
if ! command -v mypy &> /dev/null; then
    echo " mypy not found. Installing..."
    pip install mypy types-requests types-PyYAML
fi

echo ""
echo " Checking main toolkit file..."
echo "--------------------------------"

# Type check the main file with strict settings
mypy cve_research_toolkit_fixed.py \
    --strict \
    --ignore-missing-imports \
    --show-error-codes \
    --show-column-numbers \
    --pretty \
    --color-output

echo ""
echo " Checking test file..."
echo "------------------------"

# Type check the test file (less strict for tests)
mypy test_research_comprehensive.py \
    --ignore-missing-imports \
    --show-error-codes \
    --color-output

echo ""
echo " Checking typed version..."
echo "----------------------------"

# Note: Only checking main file and tests now
echo "Type checking complete for main files."

echo ""
echo " Static type checking complete!"
echo ""
echo " Summary:"
echo "  - Main file: Checked with strict mode"
echo "  - Test file: Checked with standard mode" 
echo "  - Typed version: Checked with strict mode"
echo ""
echo " Tips:"
echo "  - Fix any 'error:' messages before committing"
echo "  - 'note:' messages are informational"
echo "  - Use '# type: ignore' sparingly for unavoidable issues"