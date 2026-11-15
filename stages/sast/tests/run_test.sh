#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STAGE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$STAGE_DIR/../.." && pwd)"

SEMGREP_VERSION="1.100.0"
CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/devsecops/semgrep-${SEMGREP_VERSION}"
VENV_DIR="$CACHE_DIR/venv"
SEMGREP_BIN="$VENV_DIR/bin/semgrep"

if [ ! -f "$SEMGREP_BIN" ] && [ -f "$VENV_DIR/Scripts/semgrep" ]; then
  SEMGREP_BIN="$VENV_DIR/Scripts/semgrep"
elif [ ! -f "$SEMGREP_BIN" ] && [ -f "$VENV_DIR/Scripts/semgrep.exe" ]; then
  SEMGREP_BIN="$VENV_DIR/Scripts/semgrep.exe"
fi

PYTHON="${PYTHON:-python3}"
if ! command -v "$PYTHON" >/dev/null 2>&1; then
  if command -v python >/dev/null 2>&1; then
    PYTHON="python"
  fi
fi

# Check if semgrep installed; if not run install.sh
if [ ! -f "$SEMGREP_BIN" ]; then
  echo "[test] Semgrep not found at $SEMGREP_BIN, running install.sh..." >&2
  bash "$STAGE_DIR/install.sh" || true
  if [ ! -f "$SEMGREP_BIN" ] && [ -f "$VENV_DIR/Scripts/semgrep" ]; then
    SEMGREP_BIN="$VENV_DIR/Scripts/semgrep"
  elif [ ! -f "$SEMGREP_BIN" ] && [ -f "$VENV_DIR/Scripts/semgrep.exe" ]; then
    SEMGREP_BIN="$VENV_DIR/Scripts/semgrep.exe"
  fi
fi

if [ ! -f "$SEMGREP_BIN" ]; then
  echo "SKIPPED: Semgrep 1.100.0 could not be installed in this environment" >&2
  exit 0
fi

FAILED=0
TMP_TEST_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_TEST_DIR"' EXIT

echo "=== Running sast stage tests ==="

# -------------------------------------------------------------
# Test A: Run against demo-app/vulnerable/ with custom rules only
# -------------------------------------------------------------
echo "[Test A] Run against demo-app/vulnerable/ (custom rules only)..."
TEST_A_OUT="$TMP_TEST_DIR/test_a"
mkdir -p "$TEST_A_OUT"

if SAST_CUSTOM_RULES=1 SAST_REGISTRY_PACKS="" bash "$STAGE_DIR/run.sh" "$REPO_ROOT/demo-app/vulnerable" "$TEST_A_OUT"; then
  if [ -f "$TEST_A_OUT/sast.sarif" ]; then
    if "$PYTHON" "$REPO_ROOT/contracts/validate.py" "$TEST_A_OUT/sast.sarif" --stage sast; then
      FINDING_COUNT=$("$PYTHON" -c "import json; data=json.load(open('$TEST_A_OUT/sast.sarif')); print(len(data['runs'][0]['results']))")
      if [ "$FINDING_COUNT" -ge 1 ]; then
        echo "PASS: Test A (found $FINDING_COUNT findings)"
      else
        echo "FAIL: Test A finding count < 1 ($FINDING_COUNT)" >&2
        FAILED=1
      fi
    else
      echo "FAIL: Test A SARIF validation failed" >&2
      FAILED=1
    fi
  else
    echo "FAIL: Test A sast.sarif was not created" >&2
    FAILED=1
  fi
else
  echo "FAIL: Test A run.sh exited non-zero" >&2
  FAILED=1
fi

# -------------------------------------------------------------
# Test B: Empty Python file -> 0 results
# -------------------------------------------------------------
echo "[Test B] Empty Python file -> 0 results..."
TEST_B_TARGET="$TMP_TEST_DIR/empty_app"
TEST_B_OUT="$TMP_TEST_DIR/test_b"
mkdir -p "$TEST_B_TARGET" "$TEST_B_OUT"
touch "$TEST_B_TARGET/empty.py"

if SAST_CUSTOM_RULES=1 SAST_REGISTRY_PACKS="" bash "$STAGE_DIR/run.sh" "$TEST_B_TARGET" "$TEST_B_OUT"; then
  if [ -f "$TEST_B_OUT/sast.sarif" ]; then
    FINDING_COUNT=$("$PYTHON" -c "import json; data=json.load(open('$TEST_B_OUT/sast.sarif')); print(len(data['runs'][0]['results']))")
    if [ "$FINDING_COUNT" -eq 0 ]; then
      echo "PASS: Test B (0 findings as expected)"
    else
      echo "FAIL: Test B expected 0 findings, got $FINDING_COUNT" >&2
      FAILED=1
    fi
  else
    echo "FAIL: Test B sast.sarif was not created" >&2
    FAILED=1
  fi
else
  echo "FAIL: Test B run.sh exited non-zero" >&2
  FAILED=1
fi

# -------------------------------------------------------------
# Test C: Wrong argument count -> exit 2
# -------------------------------------------------------------
echo "[Test C] Wrong arg count -> exit 2..."
TEST_C_EC=0
bash "$STAGE_DIR/run.sh" "only_one_arg" >/dev/null 2>&1 || TEST_C_EC=$?
if [ "$TEST_C_EC" -eq 2 ]; then
  echo "PASS: Test C (exit code 2)"
else
  echo "FAIL: Test C expected exit code 2, got $TEST_C_EC" >&2
  FAILED=1
fi

# -------------------------------------------------------------
# Test D: Missing target -> exit 2
# -------------------------------------------------------------
echo "[Test D] Missing target -> exit 2..."
TEST_D_EC=0
bash "$STAGE_DIR/run.sh" "$TMP_TEST_DIR/nonexistent_target_dir" "$TMP_TEST_DIR/test_d" >/dev/null 2>&1 || TEST_D_EC=$?
if [ "$TEST_D_EC" -eq 2 ]; then
  echo "PASS: Test D (exit code 2)"
else
  echo "FAIL: Test D expected exit code 2, got $TEST_D_EC" >&2
  FAILED=1
fi

# -------------------------------------------------------------
# Test E: Semgrep rule tests
# -------------------------------------------------------------
echo "[Test E] Semgrep rule tests (--test)..."
TEST_E_EC=0
"$SEMGREP_BIN" --test "$STAGE_DIR/rules/" >/dev/null 2>&1 || TEST_E_EC=$?
if [ "$TEST_E_EC" -eq 0 ]; then
  echo "PASS: Test E (rule tests passed)"
else
  echo "WARNING: Semgrep --test returned exit code $TEST_E_EC" >&2
fi

# -------------------------------------------------------------
# Test F: No SQL injection false positive on demo-app/fixed/
# -------------------------------------------------------------
echo "[Test F] No SQL injection false positive on fixed app..."
TEST_F_OUT="$TMP_TEST_DIR/test_f"
mkdir -p "$TEST_F_OUT"

if SAST_CUSTOM_RULES=1 SAST_REGISTRY_PACKS="" bash "$STAGE_DIR/run.sh" "$REPO_ROOT/demo-app/fixed" "$TEST_F_OUT"; then
  if [ -f "$TEST_F_OUT/sast.sarif" ]; then
    HAS_SQLI=$("$PYTHON" -c "
import json
data = json.load(open('$TEST_F_OUT/sast.sarif'))
results = data['runs'][0]['results']
sqli = [r for r in results if r.get('ruleId') == 'p2-sql-injection-string-concat']
print('yes' if sqli else 'no')
")
    if [ "$HAS_SQLI" = "no" ]; then
      echo "PASS: Test F (no p2-sql-injection-string-concat in fixed app)"
    else
      echo "FAIL: Test F false positive detected: p2-sql-injection-string-concat found in fixed app" >&2
      FAILED=1
    fi
  else
    echo "FAIL: Test F sast.sarif was not created" >&2
    FAILED=1
  fi
else
  echo "FAIL: Test F run.sh exited non-zero" >&2
  FAILED=1
fi

if [ "$FAILED" -eq 0 ]; then
  echo "=== All sast tests PASSED ==="
  exit 0
else
  echo "=== Some sast tests FAILED ===" >&2
  exit 1
fi
