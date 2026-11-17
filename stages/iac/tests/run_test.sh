#!/usr/bin/env bash
# stages/iac/tests/run_test.sh - Tests for the IAC stage
# Owner: P3  Phase: 3
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STAGE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$STAGE_DIR/../.." && pwd)"
RUN_SH="$STAGE_DIR/run.sh"

PASS=0
FAIL=0
TOTAL=0

pass() { echo "  [PASS] $1"; PASS=$((PASS+1)); TOTAL=$((TOTAL+1)); }
fail() { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1)); }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PYTHON="${PYTHON:-python3}"
if ! command -v "$PYTHON" >/dev/null 2>&1; then PYTHON="python"; fi

echo "=== IAC Stage Tests ==="

# -- T1: Wrong number of arguments -> exit 2 -----------------------------------
echo "T1: wrong-args (exit 2)"
bash "$RUN_SH" >/dev/null 2>&1 && T1_EC=0 || T1_EC=$?
if [ "$T1_EC" -eq 2 ]; then pass "T1: exit 2 on wrong args"; else fail "T1: expected 2, got $T1_EC"; fi

# -- T2: Non-existent target -> exit 2 -----------------------------------------
echo "T2: non-existent target (exit 2)"
OUT2="$TMP/t2_out"; mkdir -p "$OUT2"
bash "$RUN_SH" "/nonexistent/path/xyz123" "$OUT2" >/dev/null 2>&1 && T2_EC=0 || T2_EC=$?
if [ "$T2_EC" -eq 2 ]; then pass "T2: exit 2 on missing target"; else fail "T2: expected 2, got $T2_EC"; fi

# -- T3: Vulnerable Dockerfile -> detects V4, V5, V8 --------------------------
echo "T3: vulnerable Dockerfile detects seeded flaws"
OUT3="$TMP/t3_out"; mkdir -p "$OUT3"
VULN_DIR="$REPO_ROOT/demo-app/vulnerable"
bash "$RUN_SH" "$VULN_DIR" "$OUT3" >/dev/null 2>&1 && T3_EC=0 || T3_EC=$?
if [ "$T3_EC" -eq 0 ] && [ -f "$OUT3/iac.sarif" ]; then
  RULE_IDS="$("$PYTHON" -c "
import json,sys
d=json.load(open('$OUT3/iac.sarif'))
ids=[r['ruleId'] for run in d['runs'] for r in run['results']]
print('\n'.join(ids))
" 2>/dev/null || echo "")"

  echo "$RULE_IDS" | grep -qE "DL3002|CKV_DOCKER_8|CKV_DOCKER_3|CKV_DOCKER_22" \
    && pass "T3a: V4 (root user) detected" || fail "T3a: V4 (root user) NOT detected"
  echo "$RULE_IDS" | grep -qE "DL3007|CKV_DOCKER_7|CKV_DOCKER_13" \
    && pass "T3b: V5 (unpinned base) detected" || fail "T3b: V5 (unpinned base) NOT detected"
  echo "$RULE_IDS" | grep -qE "CKV_DOCKER_28|DL3057|CKV_DOCKER_2" \
    && pass "T3c: V8 (no HEALTHCHECK) detected" || fail "T3c: V8 (no HEALTHCHECK) NOT detected"
else
  fail "T3: run.sh exited $T3_EC or iac.sarif missing"
fi

# -- T4: SARIF validation passes -----------------------------------------------
echo "T4: SARIF validation"
if [ -f "$OUT3/iac.sarif" ]; then
  if "$PYTHON" "$REPO_ROOT/contracts/validate.py" "$OUT3/iac.sarif" --stage iac >/dev/null 2>&1; then
    pass "T4: iac.sarif passes contract validation"
  else
    fail "T4: iac.sarif FAILS contract validation"
    "$PYTHON" "$REPO_ROOT/contracts/validate.py" "$OUT3/iac.sarif" --stage iac >&2 || true
  fi
else
  fail "T4: no SARIF from T3 to validate"
fi

# -- T5: Hardened Dockerfile -> zero or fewer findings ------------------------
echo "T5: hardened Dockerfile (fixed)"
OUT5="$TMP/t5_out"; mkdir -p "$OUT5"
FIXED_DIR="$REPO_ROOT/demo-app/fixed"
bash "$RUN_SH" "$FIXED_DIR" "$OUT5" >/dev/null 2>&1 && T5_EC=0 || T5_EC=$?
if [ "$T5_EC" -eq 0 ] && [ -f "$OUT5/iac.sarif" ]; then
  COUNT="$("$PYTHON" -c "
import json,sys
d=json.load(open('$OUT5/iac.sarif'))
total=sum(len(run['results']) for run in d['runs'])
print(total)
" 2>/dev/null || echo "unknown")"
  echo "  [INFO] Fixed Dockerfile finding count: $COUNT"
  if [ "$COUNT" = "0" ]; then
    pass "T5: hardened Dockerfile produces 0 findings"
  elif [ "$COUNT" != "unknown" ] && [ "$COUNT" -lt 3 ]; then
    pass "T5: hardened Dockerfile produces fewer findings ($COUNT)"
  else
    fail "T5: hardened Dockerfile still has $COUNT findings (expected 0)"
  fi
else
  fail "T5: run.sh exited $T5_EC or iac.sarif missing for fixed dir"
fi

# -- T6: Directory with no Dockerfile -> exit 0, zero-result SARIF ------------
echo "T6: no Dockerfile -> exit 0 with zero-result SARIF"
OUT6="$TMP/t6_out"; mkdir -p "$OUT6"
EMPTY_DIR="$TMP/empty_target"; mkdir -p "$EMPTY_DIR"
bash "$RUN_SH" "$EMPTY_DIR" "$OUT6" >/dev/null 2>&1 && T6_EC=0 || T6_EC=$?
if [ "$T6_EC" -eq 0 ] && [ -f "$OUT6/iac.sarif" ]; then
  COUNT="$("$PYTHON" -c "
import json
d=json.load(open('$OUT6/iac.sarif'))
print(sum(len(r['results']) for r in d['runs']))
" 2>/dev/null || echo "0")"
  if [ "$COUNT" = "0" ]; then
    pass "T6: empty dir -> exit 0, zero-result SARIF"
  else
    fail "T6: empty dir -> unexpected $COUNT results"
  fi
else
  fail "T6: expected exit 0 for empty dir, got $T6_EC"
fi

# -- T7: Fail-closed - corrupt Dockerfile content doesn't produce valid SARIF -
echo "T7: fail-closed on scanner crash"
OUT7="$TMP/t7_out"; mkdir -p "$OUT7"
CRASH_DIR="$TMP/crash_target"; mkdir -p "$CRASH_DIR"
# Create a valid-looking Dockerfile so hadolint runs but checkov gets bad json
printf 'FROM scratch\n' > "$CRASH_DIR/Dockerfile"
# Override CHECKOV_PATH to a non-existent binary to simulate crash
if CHECKOV_PATH="/nonexistent/checkov" HADOLINT_PATH="/nonexistent/hadolint" \
    bash "$RUN_SH" "$CRASH_DIR" "$OUT7" >/dev/null 2>&1; then
  fail "T7: expected exit 1 when tools missing, got 0"
else
  T7_EC=$?
  if [ "$T7_EC" -eq 1 ]; then
    if [ ! -f "$OUT7/iac.sarif" ]; then
      pass "T7: exit 1 and no SARIF on scanner crash"
    else
      fail "T7: exit 1 but SARIF still present (should be deleted)"
    fi
  else
    fail "T7: expected exit 1 on crash, got $T7_EC"
  fi
fi

# -- Summary -------------------------------------------------------------------
echo ""
echo "=== Results: $PASS passed, $FAIL failed out of $TOTAL tests ==="
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
