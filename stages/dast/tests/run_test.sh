#!/usr/bin/env bash
# stages/dast/tests/run_test.sh
# Integration test for the dast stub stage.
# P3: extend this with real known-bad inputs.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
STAGE_SCRIPT="$REPO_ROOT/stages/dast/run.sh"
PYTHON="${PYTHON:-python3}"

# Create temp output directory
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

echo "--- Testing stage: dast ---"

# Run the stage against the demo-app target
bash "$STAGE_SCRIPT" "$REPO_ROOT/demo-app/vulnerable" "$TMP_DIR"

# Assert SARIF was written
if [ ! -f "$TMP_DIR/dast.sarif" ]; then
    echo "FAIL: dast.sarif not found in output directory" >&2
    exit 1
fi
echo "PASS: dast.sarif exists"

# Assert SARIF is valid per the contract
if "$PYTHON" "$REPO_ROOT/contracts/validate.py" "$TMP_DIR/dast.sarif" --stage dast; then
    echo "PASS: dast.sarif is valid per contracts/validate.py"
else
    echo "FAIL: dast.sarif failed validation" >&2
    exit 1
fi

echo "--- Stage dast test: PASSED ---"
