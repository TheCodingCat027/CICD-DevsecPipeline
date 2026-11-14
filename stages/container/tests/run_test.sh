#!/usr/bin/env bash
# stages/container/tests/run_test.sh
# Integration test for the container stub stage.
# P3: extend this with real known-bad inputs.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
STAGE_SCRIPT="$REPO_ROOT/stages/container/run.sh"
PYTHON="${PYTHON:-python3}"

# Create temp output directory
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

echo "--- Testing stage: container ---"

# Run the stage against the demo-app target
bash "$STAGE_SCRIPT" "$REPO_ROOT/demo-app/vulnerable" "$TMP_DIR"

# Assert SARIF was written
if [ ! -f "$TMP_DIR/container.sarif" ]; then
    echo "FAIL: container.sarif not found in output directory" >&2
    exit 1
fi
echo "PASS: container.sarif exists"

# Assert SARIF is valid per the contract
if "$PYTHON" "$REPO_ROOT/contracts/validate.py" "$TMP_DIR/container.sarif" --stage container; then
    echo "PASS: container.sarif is valid per contracts/validate.py"
else
    echo "FAIL: container.sarif failed validation" >&2
    exit 1
fi

echo "--- Stage container test: PASSED ---"
