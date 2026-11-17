#!/usr/bin/env bash
# stages/container/tests/run_test.sh - Tests for the container stage
# Owner: P3  Phase: 3
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STAGE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$STAGE_DIR/../.." && pwd)"
RUN_SH="$STAGE_DIR/run.sh"

PASS=0; FAIL=0; TOTAL=0

pass() { echo "  [PASS] $1"; PASS=$((PASS+1)); TOTAL=$((TOTAL+1)); }
fail() { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1)); }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PYTHON="${PYTHON:-python3}"
if ! command -v "$PYTHON" >/dev/null 2>&1; then PYTHON="python"; fi

echo "=== Container Stage Tests ==="

# T1: wrong args -> exit 2
echo "T1: wrong args (exit 2)"
bash "$RUN_SH" >/dev/null 2>&1 && T1_EC=0 || T1_EC=$?
[ "$T1_EC" -eq 2 ] && pass "T1: exit 2 on wrong args" || fail "T1: expected 2, got $T1_EC"

# T2: non-existent target -> exit 2
echo "T2: non-existent target (exit 2)"
OUT2="$TMP/t2"; mkdir -p "$OUT2"
bash "$RUN_SH" "/nonexistent/xyz123" "$OUT2" >/dev/null 2>&1 && T2_EC=0 || T2_EC=$?
[ "$T2_EC" -eq 2 ] && pass "T2: exit 2 on missing target" || fail "T2: expected 2, got $T2_EC"

# T3: vulnerable Dockerfile -> posture findings (DSP-IMG-001, DSP-IMG-002)
# Note: Trivy image scan needs Docker; falls back to filesystem scan
echo "T3: vulnerable Dockerfile posture checks"
OUT3="$TMP/t3"; mkdir -p "$OUT3"
# Use filesystem fallback by not setting IMAGE_REF
bash "$RUN_SH" "$REPO_ROOT/demo-app/vulnerable" "$OUT3" >/dev/null 2>&1 && T3_EC=0 || T3_EC=$?
if [ "$T3_EC" -eq 0 ] && [ -f "$OUT3/container.sarif" ]; then
  RULE_IDS="$("$PYTHON" -c "
import json
d=json.load(open('$OUT3/container.sarif'))
print('\n'.join(r['ruleId'] for run in d['runs'] for r in run['results']))
" 2>/dev/null || echo "")"
  echo "$RULE_IDS" | grep -q "DSP-IMG-001" \
    && pass "T3a: DSP-IMG-001 (root user) detected" || fail "T3a: DSP-IMG-001 NOT detected"
  echo "$RULE_IDS" | grep -q "DSP-IMG-002" \
    && pass "T3b: DSP-IMG-002 (untagged base) detected" || fail "T3b: DSP-IMG-002 NOT detected"
else
  fail "T3: run.sh exited $T3_EC or container.sarif missing"
fi

# T4: SARIF validation passes
echo "T4: SARIF validation"
if [ -f "$OUT3/container.sarif" ]; then
  if "$PYTHON" "$REPO_ROOT/contracts/validate.py" "$OUT3/container.sarif" --stage container >/dev/null 2>&1; then
    pass "T4: container.sarif passes validation"
  else
    fail "T4: container.sarif FAILS validation"
    "$PYTHON" "$REPO_ROOT/contracts/validate.py" "$OUT3/container.sarif" --stage container >&2 || true
  fi
else
  fail "T4: no SARIF from T3"
fi

# T5: Hardened Dockerfile -> DSP-IMG-001 and DSP-IMG-002 NOT present
echo "T5: hardened Dockerfile (fixed) - no posture failures"
OUT5="$TMP/t5"; mkdir -p "$OUT5"
bash "$RUN_SH" "$REPO_ROOT/demo-app/fixed" "$OUT5" >/dev/null 2>&1 && T5_EC=0 || T5_EC=$?
if [ "$T5_EC" -eq 0 ] && [ -f "$OUT5/container.sarif" ]; then
  RULE_IDS5="$("$PYTHON" -c "
import json
d=json.load(open('$OUT5/container.sarif'))
print('\n'.join(r['ruleId'] for run in d['runs'] for r in run['results']))
" 2>/dev/null || echo "")"
  echo "$RULE_IDS5" | grep -q "DSP-IMG-001" \
    && fail "T5: DSP-IMG-001 still present in fixed Dockerfile" \
    || pass "T5a: DSP-IMG-001 absent from fixed Dockerfile"
  echo "$RULE_IDS5" | grep -q "DSP-IMG-002" \
    && fail "T5: DSP-IMG-002 still present in fixed Dockerfile" \
    || pass "T5b: DSP-IMG-002 absent from fixed Dockerfile"
else
  fail "T5: run.sh exited $T5_EC or container.sarif missing for fixed dir"
fi

# T6: category is always "container"
echo "T6: all results have category=container"
if [ -f "$OUT3/container.sarif" ]; then
  WRONG_CAT="$("$PYTHON" -c "
import json
d=json.load(open('$OUT3/container.sarif'))
wrong=[r['ruleId'] for run in d['runs'] for r in run['results']
       if r.get('properties',{}).get('category')!='container']
print('\n'.join(wrong))
" 2>/dev/null || echo "")"
  if [ -z "$WRONG_CAT" ]; then
    pass "T6: all results have category=container"
  else
    fail "T6: some results have wrong category: $WRONG_CAT"
  fi
else
  fail "T6: no SARIF to check"
fi

echo ""
echo "=== Results: $PASS passed, $FAIL failed out of $TOTAL tests ==="
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
