#!/usr/bin/env bash
# stages/sca/tests/run_test.sh
# Test suite for sca stage (Trivy filesystem mode)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
STAGE_SCRIPT="$REPO_ROOT/stages/sca/run.sh"
INSTALL_SCRIPT="$REPO_ROOT/stages/sca/install.sh"
PYTHON="${PYTHON:-python3}"
if ! command -v "$PYTHON" >/dev/null 2>&1; then
  PYTHON="python"
fi

TRIVY_VERSION="0.58.1"
TRIVY_BIN="${TRIVY_PATH:-${XDG_CACHE_HOME:-$HOME/.cache}/devsecops/trivy-${TRIVY_VERSION}/trivy}"

echo "========================================"
echo " Running tests for stage: sca"
echo "========================================"

FAILED_TESTS=0

# Pre-flight check: ensure Trivy is installed
if [ ! -x "$TRIVY_BIN" ]; then
  echo "[test-setup] Trivy not found at $TRIVY_BIN. Attempting installation..."
  if ! bash "$INSTALL_SCRIPT"; then
    echo "SKIPPED: Trivy tool unavailable and install failed."
    exit 0
  fi
fi

if [ ! -x "$TRIVY_BIN" ]; then
  echo "SKIPPED: Trivy tool unavailable."
  exit 0
fi

# ------------------------------------------------------------------------------
# Test A: Known bad (demo-app/vulnerable)
# ------------------------------------------------------------------------------
echo "--- Test A: Known bad input (demo-app/vulnerable) ---"
TMP_A="$(mktemp -d)"

SET_EC=0
bash "$STAGE_SCRIPT" "$REPO_ROOT/demo-app/vulnerable" "$TMP_A" || SET_EC=$?

if [ "$SET_EC" -ne 0 ]; then
  echo "FAIL: Test A exited with code $SET_EC (expected 0)"
  FAILED_TESTS=$((FAILED_TESTS + 1))
elif [ ! -f "$TMP_A/sca.sarif" ]; then
  echo "FAIL: Test A did not create sca.sarif"
  FAILED_TESTS=$((FAILED_TESTS + 1))
else
  # Assert SARIF is valid per contracts/validate.py
  if "$PYTHON" "$REPO_ROOT/contracts/validate.py" "$TMP_A/sca.sarif" --stage sca; then
    echo "PASS: Test A SARIF is valid"
  else
    echo "FAIL: Test A SARIF failed validate.py"
    FAILED_TESTS=$((FAILED_TESTS + 1))
  fi

  # Check findings count > 0
  FINDING_COUNT=$("$PYTHON" -c '
import json, sys
data = json.load(open(sys.argv[1]))
results = data.get("runs", [{}])[0].get("results", [])
print(len(results))
' "$TMP_A/sca.sarif")

  if [ "$FINDING_COUNT" -gt 0 ]; then
    echo "PASS: Test A detected $FINDING_COUNT finding(s)"
  else
    echo "FAIL: Test A detected 0 findings (expected > 0)"
    FAILED_TESTS=$((FAILED_TESTS + 1))
  fi

  # Check seeded CVEs
  FOUND_SEEDED=$("$PYTHON" -c '
import json, sys
data = json.load(open(sys.argv[1]))
results = data.get("runs", [{}])[0].get("results", [])
rule_ids = {r.get("ruleId", "") for r in results}
seeded = {"CVE-2019-10906", "CVE-2019-20477"}
matched = seeded.intersection(rule_ids)
if matched:
    print(f"matched: {list(matched)}")
else:
    print("none")
' "$TMP_A/sca.sarif")

  if [[ "$FOUND_SEEDED" == matched* ]]; then
    echo "INFO: Seeded CVE(s) confirmed in SARIF results: $FOUND_SEEDED"
  else
    echo "WARNING: Seeded CVEs (CVE-2019-10906, CVE-2019-20477) not explicitly reported by Trivy (per seeded-vulnerabilities.json cve_verified: false)"
  fi
fi
rm -rf "$TMP_A"

# ------------------------------------------------------------------------------
# Test B: Empty directory
# ------------------------------------------------------------------------------
echo "--- Test B: Empty directory ---"
TMP_EMPTY_TARGET="$(mktemp -d)"
TMP_B="$(mktemp -d)"

EC_B=0
bash "$STAGE_SCRIPT" "$TMP_EMPTY_TARGET" "$TMP_B" || EC_B=$?

if [ "$EC_B" -ne 0 ]; then
  echo "FAIL: Test B exited with code $EC_B (expected 0)"
  FAILED_TESTS=$((FAILED_TESTS + 1))
elif [ ! -f "$TMP_B/sca.sarif" ]; then
  echo "FAIL: Test B did not create sca.sarif"
  FAILED_TESTS=$((FAILED_TESTS + 1))
else
  COUNT_B=$("$PYTHON" -c '
import json, sys
data = json.load(open(sys.argv[1]))
print(len(data.get("runs", [{}])[0].get("results", [])))
' "$TMP_B/sca.sarif")
  if [ "$COUNT_B" -eq 0 ]; then
    echo "PASS: Test B produced 0 findings as expected"
  else
    echo "FAIL: Test B produced $COUNT_B findings (expected 0)"
    FAILED_TESTS=$((FAILED_TESTS + 1))
  fi
fi
rm -rf "$TMP_EMPTY_TARGET" "$TMP_B"

# ------------------------------------------------------------------------------
# Test C: Wrong argument count
# ------------------------------------------------------------------------------
echo "--- Test C: Wrong argument count ---"
EC_C=0
bash "$STAGE_SCRIPT" "only_one_arg" 2>/dev/null || EC_C=$?
if [ "$EC_C" -eq 2 ]; then
  echo "PASS: Test C exited 2 on wrong arg count"
else
  echo "FAIL: Test C exited $EC_C (expected 2)"
  FAILED_TESTS=$((FAILED_TESTS + 1))
fi

# ------------------------------------------------------------------------------
# Test D: Missing target path
# ------------------------------------------------------------------------------
echo "--- Test D: Missing target path ---"
TMP_D="$(mktemp -d)"
EC_D=0
bash "$STAGE_SCRIPT" "/nonexistent/path/for/sca/test" "$TMP_D" 2>/dev/null || EC_D=$?
if [ "$EC_D" -eq 2 ]; then
  echo "PASS: Test D exited 2 on missing target"
else
  echo "FAIL: Test D exited $EC_D (expected 2)"
  FAILED_TESTS=$((FAILED_TESTS + 1))
fi
rm -rf "$TMP_D"

# ------------------------------------------------------------------------------
# Test E: Fail closed (scanner crash/failure)
# ------------------------------------------------------------------------------
echo "--- Test E: Fail closed on scanner failure ---"
TMP_E="$(mktemp -d)"
FAKE_TRIVY="$(mktemp)"
cat << 'EOF' > "$FAKE_TRIVY"
#!/usr/bin/env bash
echo "Simulated scanner crash" >&2
exit 1
EOF
chmod +x "$FAKE_TRIVY"

EC_E=0
TRIVY_PATH="$FAKE_TRIVY" bash "$STAGE_SCRIPT" "$REPO_ROOT/demo-app/vulnerable" "$TMP_E" 2>/dev/null || EC_E=$?
rm -f "$FAKE_TRIVY"

if [ "$EC_E" -eq 1 ] && [ ! -f "$TMP_E/sca.sarif" ]; then
  echo "PASS: Test E failed closed (exit 1, no SARIF file)"
else
  echo "FAIL: Test E exited $EC_E (expected 1) or SARIF was created"
  FAILED_TESTS=$((FAILED_TESTS + 1))
fi
rm -rf "$TMP_E"

# ------------------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------------------
echo "========================================"
if [ "$FAILED_TESTS" -eq 0 ]; then
  echo "ALL TESTS PASSED"
  exit 0
else
  echo "$FAILED_TESTS TEST(S) FAILED"
  exit 1
fi
