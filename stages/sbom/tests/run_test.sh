#!/usr/bin/env bash
# stages/sbom/tests/run_test.sh
# Integration test for the sbom stub stage.
# P3: extend this with real known-bad inputs.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
STAGE_SCRIPT="$REPO_ROOT/stages/sbom/run.sh"
PYTHON="${PYTHON:-python3}"

# Create temp output directory
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

echo "--- Testing stage: sbom ---"

# Run the stage against the demo-app target
bash "$STAGE_SCRIPT" "$REPO_ROOT/demo-app/vulnerable" "$TMP_DIR"

# Assert SARIF was written
if [ ! -f "$TMP_DIR/sbom.sarif" ]; then
    echo "FAIL: sbom.sarif not found in output directory" >&2
    exit 1
fi
echo "PASS: sbom.sarif exists"

# Assert SARIF is valid per the contract
if "$PYTHON" "$REPO_ROOT/contracts/validate.py" "$TMP_DIR/sbom.sarif" --stage sbom; then
    echo "PASS: sbom.sarif is valid per contracts/validate.py"
else
    echo "FAIL: sbom.sarif failed validation" >&2
    exit 1
fi

# Assert CycloneDX artifact was written
if [ ! -f "$TMP_DIR/artifacts/sbom/sbom.cdx.json" ]; then
    echo "FAIL: sbom.cdx.json not found in artifacts/sbom/" >&2
    exit 1
fi
echo "PASS: sbom.cdx.json artifact exists"

echo "--- Stage sbom test: PASSED ---"
