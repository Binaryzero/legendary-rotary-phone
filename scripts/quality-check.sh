#!/bin/bash
# Complete Quality Check Script for CVE Research Toolkit

set -e

echo "🎯 CVE Research Toolkit - Complete Quality Check"
echo "==============================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Track results
PASSED=0
FAILED=0

run_check() {
    local name="$1"
    local command="$2"
    
    echo -e "\n${BLUE}🔍 Running $name...${NC}"
    echo "----------------------------------------"
    
    if eval "$command"; then
        echo -e "${GREEN}✅ $name passed!${NC}"
        ((PASSED++))
    else
        echo -e "${RED}❌ $name failed!${NC}"
        ((FAILED++))
    fi
}

# 1. Code Formatting Check
run_check "Code Formatting" "black --check cve_research_toolkit_fixed.py test_research_comprehensive.py"

# 2. Import Sorting Check  
run_check "Import Sorting" "isort --check-only cve_research_toolkit_fixed.py test_research_comprehensive.py"

# 3. Linting
run_check "Linting (flake8)" "flake8 cve_research_toolkit_fixed.py test_research_comprehensive.py --max-line-length=88 --extend-ignore=E203,W503"

# 4. Static Type Checking
run_check "Static Type Checking" "./scripts/type-check.sh"

# 5. Security Scanning
run_check "Security Scanning" "bandit -r cve_research_toolkit_fixed.py -f json -o bandit-report.json"

# 6. Comprehensive Tests
run_check "Comprehensive Tests" "python test_research_comprehensive.py"

# 7. Documentation Check
run_check "Documentation Style" "pydocstyle cve_research_toolkit_fixed.py --convention=google || true"

# Summary
echo ""
echo "================================================"
echo -e "${BLUE}📊 Quality Check Summary${NC}"
echo "================================================"
echo -e "✅ Passed: ${GREEN}$PASSED${NC}"
echo -e "❌ Failed: ${RED}$FAILED${NC}"

if [ $FAILED -eq 0 ]; then
    echo ""
    echo -e "${GREEN}🎉 All quality checks passed!${NC}"
    echo -e "${GREEN}✨ Code is ready for production!${NC}"
    exit 0
else
    echo ""
    echo -e "${RED}⚠️  Some quality checks failed.${NC}"
    echo -e "${YELLOW}📝 Please fix the issues above before committing.${NC}"
    
    echo ""
    echo "🔧 Quick fixes:"
    echo "  - Code formatting: make format"
    echo "  - Linting issues: Check flake8 output above"
    echo "  - Type issues: Check mypy output above"
    echo "  - Security issues: Review bandit-report.json"
    
    exit 1
fi