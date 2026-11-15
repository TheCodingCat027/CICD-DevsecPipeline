#!/usr/bin/env bash
# stages/secrets/tests/run_test.sh - Integration test suite for secrets stage
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STAGE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$STAGE_DIR/../.." && pwd)"
PYTHON="${PYTHON:-python3}"

TESTS_PASSED=0
TESTS_FAILED=0

echo "=== Running secrets stage test suite ==="

# Tool availability check
GL_VERSION="8.21.2"
GL_BIN="${XDG_CACHE_HOME:-$HOME/.cache}/devsecops/gitleaks-${GL_VERSION}/gitleaks"

if [ ! -x "$GL_BIN" ]; then
  echo "[test] Gitleaks not found at $GL_BIN, attempting install..." >&2
  if ! bash "$STAGE_DIR/install.sh" >&2; then
    echo "SKIPPED (tool unavailable): gitleaks installation failed"
    exit 0
  fi
fi

if [ ! -x "$GL_BIN" ]; then
  echo "SKIPPED (tool unavailable): gitleaks installation failed"
  exit 0
fi

TMPDIR_TEST="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_TEST"' EXIT

# Synthetic key construction (split so no complete secret is committed to git)
KEY_PART1="AKIA"
KEY_PART2="IOSFODNN7EXAMPLE"

# ── Test A: known-bad fixture ──────────────────────────────────────────────────
echo "--- Test A: known-bad fixture ---"
mkdir -p "$TMPDIR_TEST/fixture"
echo "AWS_KEY = '${KEY_PART1}${KEY_PART2}'" > "$TMPDIR_TEST/fixture/config.py"
mkdir -p "$TMPDIR_TEST/out_a"

if bash "$STAGE_DIR/run.sh" "$TMPDIR_TEST/fixture" "$TMPDIR_TEST/out_a"; then
  if [ -f "$TMPDIR_TEST/out_a/secrets.sarif" ]; then
    if "$PYTHON" "$REPO_ROOT/contracts/validate.py" "$TMPDIR_TEST/out_a/secrets.sarif" --stage secrets >/dev/null 2>&1; then
      COUNT_A=$("$PYTHON" -c "import json; d=json.load(open('$TMPDIR_TEST/out_a/secrets.sarif')); print(len(d['runs'][0]['results']))")
      if [ "$COUNT_A" -gt 0 ]; then
        echo "PASS: Test A (detected $COUNT_A secrets in known-bad fixture)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
      else
        echo "FAIL: Test A (expected > 0 findings, got 0)"
        TESTS_FAILED=$((TESTS_FAILED + 1))
      fi
    else
      echo "FAIL: Test A (SARIF validation failed)"
      TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
  else
    echo "FAIL: Test A (secrets.sarif missing)"
    TESTS_FAILED=$((TESTS_FAILED + 1))
  fi
else
  echo "FAIL: Test A (run.sh failed)"
  TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# ── Test B: clean directory ───────────────────────────────────────────────────
echo "--- Test B: clean directory ---"
mkdir -p "$TMPDIR_TEST/clean"
touch "$TMPDIR_TEST/clean/empty.py"
mkdir -p "$TMPDIR_TEST/out_b"

if bash "$STAGE_DIR/run.sh" "$TMPDIR_TEST/clean" "$TMPDIR_TEST/out_b"; then
  if [ -f "$TMPDIR_TEST/out_b/secrets.sarif" ]; then
    if "$PYTHON" "$REPO_ROOT/contracts/validate.py" "$TMPDIR_TEST/out_b/secrets.sarif" --stage secrets >/dev/null 2>&1; then
      COUNT_B=$("$PYTHON" -c "import json; d=json.load(open('$TMPDIR_TEST/out_b/secrets.sarif')); print(len(d['runs'][0]['results']))")
      if [ "$COUNT_B" -eq 0 ]; then
        echo "PASS: Test B (clean directory produced 0 findings)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
      else
        echo "FAIL: Test B (expected 0 findings, got $COUNT_B)"
        TESTS_FAILED=$((TESTS_FAILED + 1))
      fi
    else
      echo "FAIL: Test B (SARIF validation failed)"
      TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
  else
    echo "FAIL: Test B (secrets.sarif missing)"
    TESTS_FAILED=$((TESTS_FAILED + 1))
  fi
else
  echo "FAIL: Test B (run.sh failed)"
  TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# ── Test C: wrong arguments ───────────────────────────────────────────────────
echo "--- Test C: wrong arguments ---"
set +e
bash "$STAGE_DIR/run.sh" >/dev/null 2>&1
EC_C=$?
set -e
if [ "$EC_C" -eq 2 ]; then
  echo "PASS: Test C (wrong args returned exit code 2)"
  TESTS_PASSED=$((TESTS_PASSED + 1))
else
  echo "FAIL: Test C (expected exit code 2, got $EC_C)"
  TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# ── Test D: nonexistent target ────────────────────────────────────────────────
echo "--- Test D: nonexistent target ---"
set +e
bash "$STAGE_DIR/run.sh" /nonexistent/path/does/not/exist "$TMPDIR_TEST/out_d" >/dev/null 2>&1
EC_D=$?
set -e
if [ "$EC_D" -eq 2 ]; then
  echo "PASS: Test D (nonexistent target returned exit code 2)"
  TESTS_PASSED=$((TESTS_PASSED + 1))
else
  echo "FAIL: Test D (expected exit code 2, got $EC_D)"
  TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# ── Test E: V1 detection in demo-app/vulnerable ─────────────────────────────────
echo "--- Test E: V1 detection in demo-app/vulnerable ---"
mkdir -p "$TMPDIR_TEST/out_e"

if bash "$STAGE_DIR/run.sh" "$REPO_ROOT/demo-app/vulnerable" "$TMPDIR_TEST/out_e"; then
  if [ -f "$TMPDIR_TEST/out_e/secrets.sarif" ]; then
    FOUND_V1=$("$PYTHON" -c "
import json
data = json.load(open('$TMPDIR_TEST/out_e/secrets.sarif'))
rules = [r['ruleId'] for r in data['runs'][0]['results']]
print('yes' if 'aws-access-token' in rules else 'no')
")
    if [ "$FOUND_V1" = "yes" ]; then
      echo "PASS: Test E (V1 aws-access-token detected in demo-app/vulnerable)"
      TESTS_PASSED=$((TESTS_PASSED + 1))
    else
      echo "FAIL: Test E (aws-access-token not found in SARIF results)"
      TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
  else
    echo "FAIL: Test E (secrets.sarif missing)"
    TESTS_FAILED=$((TESTS_FAILED + 1))
  fi
else
  echo "FAIL: Test E (run.sh failed on demo-app/vulnerable)"
  TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# ── Test F: secret redaction in SARIF output ──────────────────────────────────
echo "--- Test F: secret redaction ---"
LEAK_FOUND=0
if grep -q "${KEY_PART2}" "$TMPDIR_TEST/out_a/secrets.sarif"; then
  LEAK_FOUND=1
fi
if [ -f "$TMPDIR_TEST/out_e/secrets.sarif" ] && grep -q "${KEY_PART2}" "$TMPDIR_TEST/out_e/secrets.sarif"; then
  LEAK_FOUND=1
fi

if [ "$LEAK_FOUND" -eq 0 ]; then
  echo "PASS: Test F (no secret values found in SARIF output - redacted)"
  TESTS_PASSED=$((TESTS_PASSED + 1))
else
  echo "FAIL: Test F (secret value was found unredacted in SARIF output)"
  TESTS_FAILED=$((TESTS_FAILED + 1))
fi

echo "========================================"
echo "Summary: $TESTS_PASSED passed, $TESTS_FAILED failed"
if [ "$TESTS_FAILED" -gt 0 ]; then
  exit 1
fi
exit 0
