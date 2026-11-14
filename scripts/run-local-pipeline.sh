#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-demo-app/vulnerable}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# On Windows (Git Bash/MSYS), convert paths to Windows native format for Python if needed
conv_path() {
    if command -v cygpath >/dev/null 2>&1; then
        cygpath -w "$1"
    else
        echo "$1"
    fi
}

STAGES_JSON="$REPO_ROOT/stages/stages.json"
REPORTS_DIR="$REPO_ROOT/reports"
GATE_OUT_DIR="$REPO_ROOT/gate-out"

if [ -z "${PYTHON:-}" ]; then
    if [ -f "$REPO_ROOT/.venv/bin/python" ]; then
        PYTHON="$REPO_ROOT/.venv/bin/python"
    elif [ -f "$REPO_ROOT/.venv/Scripts/python.exe" ]; then
        PYTHON="$REPO_ROOT/.venv/Scripts/python.exe"
    elif command -v python3 >/dev/null 2>&1; then
        PYTHON="python3"
    else
        PYTHON="python"
    fi
fi

PYTHON_WIN="$(conv_path "$PYTHON")"
STAGES_JSON_WIN="$(conv_path "$STAGES_JSON")"
REPO_ROOT_WIN="$(conv_path "$REPO_ROOT")"

echo "======================================"
echo "  Local DevSecOps Pipeline"
echo "  Target: $TARGET"
echo "  Time: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
echo "======================================"

rm -rf "$REPORTS_DIR" "$GATE_OUT_DIR"
mkdir -p "$REPORTS_DIR" "$GATE_OUT_DIR"

# Read enabled stages from stages.json
ENABLED_STAGES=$("$PYTHON" -c "
import json, sys
with open(r'''$STAGES_JSON_WIN''', encoding='utf-8') as f:
    data = json.load(f)
stages = [s['name'] for s in data['stages'] if s.get('enabled', False)]
print(' '.join(stages))
")

echo ""
echo "--- Running Security Stages ---"
START_TIME=$(date +%s)

for stage in $ENABLED_STAGES; do
    echo ""
    echo "[$(date -u +"%H:%M:%S")] Starting stage: $stage"
    stage_script="$REPO_ROOT/stages/$stage/run.sh"
    stage_reports="$REPORTS_DIR/$stage"
    mkdir -p "$stage_reports"

    if bash "$stage_script" "$REPO_ROOT/$TARGET" "$stage_reports"; then
        echo "[$(date -u +"%H:%M:%S")] Stage $stage completed. Validating output..."
        SARIF_PATH_WIN="$(conv_path "$stage_reports/$stage.sarif")"
        if "$PYTHON" "$REPO_ROOT_WIN/contracts/validate.py" "$SARIF_PATH_WIN" --stage "$stage"; then
            echo "[OK] Stage $stage: output valid"
        else
            echo "[ERROR] Stage $stage: SARIF validation failed"
            exit 1
        fi
    else
        echo "[ERROR] Stage $stage: scanner crashed (exit code $?)"
        exit 1
    fi
done

END_STAGE_TIME=$(date +%s)
echo ""
echo "--- All stages completed in $((END_STAGE_TIME - START_TIME))s ---"

echo ""
echo "--- Running Policy Gate ---"
GATE_START=$(date +%s)

REPORTS_DIR_WIN="$(conv_path "$REPORTS_DIR")"
POLICY_WIN="$(conv_path "$REPO_ROOT/security-policy.yaml")"
GATE_OUT_DIR_WIN="$(conv_path "$GATE_OUT_DIR")"

GATE_EXIT=0
"$PYTHON" "$REPO_ROOT_WIN/gate/run_gate.py" \
    --reports "$REPORTS_DIR_WIN" \
    --policy "$POLICY_WIN" \
    --out "$GATE_OUT_DIR_WIN" || GATE_EXIT=$?

GATE_END=$(date +%s)
echo "Gate completed in $((GATE_END - GATE_START))s"

echo ""
echo "======================================"
if [ "$GATE_EXIT" -eq 0 ]; then
    echo "  WOULD DEPLOY"
    echo "======================================"
    exit 0
else
    echo "  DEPLOY BLOCKED"
    echo "  Gate exit code: $GATE_EXIT"
    echo "======================================"
    exit 1
fi
