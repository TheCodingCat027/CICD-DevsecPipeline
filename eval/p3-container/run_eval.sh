#!/usr/bin/env bash
# eval/p3-container/run_eval.sh - Run Phase 3 evaluation
# Owner: P3  Phase: 3
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
EVAL_DIR="$SCRIPT_DIR"
RUNS_DIR="$EVAL_DIR/runs"
mkdir -p "$RUNS_DIR"

PYTHON="${PYTHON:-python3}"
if ! command -v "$PYTHON" >/dev/null 2>&1; then PYTHON="python"; fi

echo "=== Phase 3 Evaluation ==="
echo "Repo: $REPO_ROOT"
echo ""

# -- Run IAC stage on vulnerable and fixed ------------------------------------
echo "[eval] Running IAC stage on vulnerable Dockerfile..."
mkdir -p "$RUNS_DIR/iac-vulnerable"
bash "$REPO_ROOT/stages/iac/run.sh" \
  "$REPO_ROOT/demo-app/vulnerable" \
  "$RUNS_DIR/iac-vulnerable" 2>&1 | sed 's/^/  [iac-vuln] /'
cp "$RUNS_DIR/iac-vulnerable/iac.sarif" "$EVAL_DIR/iac-vulnerable.sarif" 2>/dev/null || true

echo "[eval] Running IAC stage on fixed Dockerfile..."
mkdir -p "$RUNS_DIR/iac-fixed"
bash "$REPO_ROOT/stages/iac/run.sh" \
  "$REPO_ROOT/demo-app/fixed" \
  "$RUNS_DIR/iac-fixed" 2>&1 | sed 's/^/  [iac-fixed] /'
cp "$RUNS_DIR/iac-fixed/iac.sarif" "$EVAL_DIR/iac-fixed.sarif" 2>/dev/null || true

# -- Run Container stage on vulnerable and fixed ------------------------------
echo "[eval] Running Container stage on vulnerable Dockerfile..."
mkdir -p "$RUNS_DIR/container-vulnerable"
bash "$REPO_ROOT/stages/container/run.sh" \
  "$REPO_ROOT/demo-app/vulnerable" \
  "$RUNS_DIR/container-vulnerable" 2>&1 | sed 's/^/  [cont-vuln] /'
cp "$RUNS_DIR/container-vulnerable/container.sarif" "$EVAL_DIR/container-vulnerable.sarif" 2>/dev/null || true

echo "[eval] Running Container stage on fixed Dockerfile..."
mkdir -p "$RUNS_DIR/container-fixed"
bash "$REPO_ROOT/stages/container/run.sh" \
  "$REPO_ROOT/demo-app/fixed" \
  "$RUNS_DIR/container-fixed" 2>&1 | sed 's/^/  [cont-fixed] /'
cp "$RUNS_DIR/container-fixed/container.sarif" "$EVAL_DIR/container-fixed.sarif" 2>/dev/null || true

# -- Run SBOM stage -----------------------------------------------------------
echo "[eval] Running SBOM stage on vulnerable app..."
mkdir -p "$RUNS_DIR/sbom-vulnerable"
bash "$REPO_ROOT/stages/sbom/run.sh" \
  "$REPO_ROOT/demo-app/vulnerable" \
  "$RUNS_DIR/sbom-vulnerable" 2>&1 | sed 's/^/  [sbom] /'
cp "$RUNS_DIR/sbom-vulnerable/sbom.sarif" "$EVAL_DIR/sbom.sarif" 2>/dev/null || true
cp "$RUNS_DIR/sbom-vulnerable/artifacts/sbom/sbom.cdx.json" "$EVAL_DIR/sbom.cdx.json" 2>/dev/null || true

# -- Generate evaluation report -----------------------------------------------
echo "[eval] Generating evaluation report..."
"$PYTHON" "$EVAL_DIR/evaluate.py" \
  "$EVAL_DIR/iac-vulnerable.sarif" \
  "$EVAL_DIR/iac-fixed.sarif" \
  "$EVAL_DIR/container-vulnerable.sarif" \
  "$EVAL_DIR/container-fixed.sarif" \
  "$EVAL_DIR/sbom.sarif" \
  "$EVAL_DIR/results.json" \
  "$EVAL_DIR/results.md" 2>&1

echo ""
echo "=== Evaluation complete. See eval/p3-container/results.md ==="
