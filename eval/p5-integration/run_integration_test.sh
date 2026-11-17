#!/usr/bin/env bash
# Integration test: run the full pipeline on both vulnerable and fixed app.
# Run from repo root with Git Bash.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

export GITLEAKS_PATH="$USERPROFILE/.cache/devsecops/gitleaks-latest/gitleaks.exe"
export HADOLINT_PATH="$USERPROFILE/.cache/devsecops/hadolint-2.12.0/hadolint.exe"
export TRIVY_PATH="$USERPROFILE/.cache/devsecops/trivy-bin/trivy.exe"
export SYFT_PATH="$USERPROFILE/.cache/devsecops/syft-1.18.1/syft.exe"
# Use the venv Python (works on both Windows Git Bash and Linux)
if [ -f "$REPO_ROOT/.venv/Scripts/python.exe" ]; then
    export PYTHON="$REPO_ROOT/.venv/Scripts/python.exe"
elif [ -f "$REPO_ROOT/.venv/bin/python" ]; then
    export PYTHON="$REPO_ROOT/.venv/bin/python"
fi

echo "========================================"
echo " Phase 5 Integration Test"
echo " $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
echo "========================================"

echo ""
echo "=== RUN 1: Vulnerable app (expect BLOCKED) ==="
VULN_EXIT=0
bash scripts/run-local-pipeline.sh demo-app/vulnerable || VULN_EXIT=$?
echo "Vulnerable pipeline exit: $VULN_EXIT"

echo ""
echo "=== RUN 2: Fixed app (expect ALLOWED) ==="
FIXED_EXIT=0
bash scripts/run-local-pipeline.sh demo-app/fixed || FIXED_EXIT=$?
echo "Fixed pipeline exit: $FIXED_EXIT"

echo ""
echo "========================================"
echo " Integration Test Summary"
echo "========================================"
PASS=true
if [ "$VULN_EXIT" -eq 1 ]; then
    echo "  [PASS] Vulnerable app BLOCKED (exit 1) ✓"
else
    echo "  [FAIL] Vulnerable app should be BLOCKED (exit 1), got $VULN_EXIT"
    PASS=false
fi

if [ "$FIXED_EXIT" -eq 0 ]; then
    echo "  [PASS] Fixed app ALLOWED (exit 0) ✓"
else
    echo "  [FAIL] Fixed app should be ALLOWED (exit 0), got $FIXED_EXIT"
    PASS=false
fi

if [ "$PASS" = true ]; then
    echo ""
    echo "  ALL INTEGRATION TESTS PASSED ✅"
    exit 0
else
    echo ""
    echo "  INTEGRATION TEST FAILURES — see above"
    exit 1
fi
