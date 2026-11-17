#!/usr/bin/env bash
# stages/sbom/tests/run_test.sh - Tests for the SBOM stage
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

echo "=== SBOM Stage Tests ==="

# T1: wrong args -> exit 2
echo "T1: wrong args (exit 2)"
bash "$RUN_SH" >/dev/null 2>&1 && T1_EC=0 || T1_EC=$?
[ "$T1_EC" -eq 2 ] && pass "T1: exit 2 on wrong args" || fail "T1: expected 2, got $T1_EC"

# T2: non-existent target -> exit 2
echo "T2: non-existent target (exit 2)"
OUT2="$TMP/t2"; mkdir -p "$OUT2"
bash "$RUN_SH" "/nonexistent/xyz123" "$OUT2" >/dev/null 2>&1 && T2_EC=0 || T2_EC=$?
[ "$T2_EC" -eq 2 ] && pass "T2: exit 2 on missing target" || fail "T2: expected 2, got $T2_EC"

# T3: scan demo-app/vulnerable -> exit 0, produce sbom.sarif + sbom.cdx.json
echo "T3: vulnerable dir -> exit 0, SARIF + CycloneDX"
OUT3="$TMP/t3"; mkdir -p "$OUT3"
bash "$RUN_SH" "$REPO_ROOT/demo-app/vulnerable" "$OUT3" >/dev/null 2>&1 && T3_EC=0 || T3_EC=$?
if [ "$T3_EC" -eq 0 ]; then
  [ -f "$OUT3/sbom.sarif" ] && pass "T3a: sbom.sarif created" || fail "T3a: sbom.sarif missing"
  [ -f "$OUT3/artifacts/sbom/sbom.cdx.json" ] && pass "T3b: sbom.cdx.json created" || fail "T3b: sbom.cdx.json missing"
  [ -f "$OUT3/artifacts/sbom/sbom-summary.json" ] && pass "T3c: sbom-summary.json created" || fail "T3c: sbom-summary.json missing"
else
  fail "T3: run.sh exited $T3_EC (expected 0)"
fi

# T4: SARIF has zero results (inventory only)
echo "T4: SARIF has zero results"
if [ -f "$OUT3/sbom.sarif" ]; then
  COUNT="$("$PYTHON" -c "
import json
d=json.load(open('$OUT3/sbom.sarif'))
print(sum(len(r['results']) for r in d['runs']))
" 2>/dev/null || echo "unknown")"
  [ "$COUNT" = "0" ] && pass "T4: SARIF has 0 results (inventory only)" || fail "T4: SARIF has $COUNT results, expected 0"
else
  fail "T4: no SARIF from T3"
fi

# T5: SARIF validation passes
echo "T5: SARIF validation"
if [ -f "$OUT3/sbom.sarif" ]; then
  if "$PYTHON" "$REPO_ROOT/contracts/validate.py" "$OUT3/sbom.sarif" --stage sbom >/dev/null 2>&1; then
    pass "T5: sbom.sarif passes contract validation"
  else
    fail "T5: sbom.sarif FAILS contract validation"
    "$PYTHON" "$REPO_ROOT/contracts/validate.py" "$OUT3/sbom.sarif" --stage sbom >&2 || true
  fi
else
  fail "T5: no SARIF from T3"
fi

# T6: CycloneDX validity
echo "T6: CycloneDX format validation"
if [ -f "$OUT3/artifacts/sbom/sbom.cdx.json" ]; then
  VALID="$("$PYTHON" -c "
import json, sys
try:
    d=json.load(open('$OUT3/artifacts/sbom/sbom.cdx.json'))
    assert d.get('bomFormat')=='CycloneDX', 'wrong bomFormat'
    assert d.get('specVersion'), 'missing specVersion'
    print('ok')
except Exception as e:
    print(f'FAIL: {e}')
" 2>/dev/null || echo "FAIL")"
  [ "$VALID" = "ok" ] && pass "T6: CycloneDX SBOM is valid" || fail "T6: CycloneDX SBOM invalid: $VALID"
else
  fail "T6: no sbom.cdx.json from T3"
fi

# T7: tool.driver.name == "syft"
echo "T7: tool driver name is syft"
if [ -f "$OUT3/sbom.sarif" ]; then
  DRIVER_NAME="$("$PYTHON" -c "
import json
d=json.load(open('$OUT3/sbom.sarif'))
print(d['runs'][0]['tool']['driver']['name'])
" 2>/dev/null || echo "")"
  [ "$DRIVER_NAME" = "syft" ] && pass "T7: tool.driver.name=syft" || fail "T7: tool.driver.name='$DRIVER_NAME', expected 'syft'"
else
  fail "T7: no SARIF"
fi

echo ""
echo "=== Results: $PASS passed, $FAIL failed out of $TOTAL tests ==="
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
