#!/usr/bin/env bash
# stages/secrets/run.sh - Gitleaks secret scanning stage
# Phase 2 | Owner: P2
# Interface: run.sh <target_path> <output_dir>
# Exit: 2=usage error, 1=scanner failure, 0=success (even with findings)
set -euo pipefail

STAGE_TIMEOUT=${STAGE_TIMEOUT:-600}
PYTHON="${PYTHON:-python3}"

if [ "$#" -ne 2 ]; then
  echo "Usage: $0 <target_path> <output_dir>" >&2; exit 2
fi

TARGET_PATH="$1"
OUTPUT_DIR="$2"

if [ ! -e "$TARGET_PATH" ]; then
  echo "ERROR: target_path '$TARGET_PATH' does not exist" >&2; exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

if [ -d "$TARGET_PATH" ]; then
  TARGET_PATH="$(cd "$TARGET_PATH" && pwd)"
else
  TARGET_DIR="$(cd "$(dirname "$TARGET_PATH")" && pwd)"
  TARGET_PATH="$TARGET_DIR/$(basename "$TARGET_PATH")"
fi

TARGET_REL="$("$PYTHON" -c "import os; print(os.path.relpath('$TARGET_PATH', '$REPO_ROOT'))")"

mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"

TMPDIR_SCAN=$(mktemp -d)
trap "rm -rf $TMPDIR_SCAN" EXIT

echo "[secrets] Installing Gitleaks..." >&2
bash "$SCRIPT_DIR/install.sh" || { echo "ERROR: Failed to install Gitleaks" >&2; exit 1; }

GL_VERSION="8.21.2"
GL_BIN="${XDG_CACHE_HOME:-$HOME/.cache}/devsecops/gitleaks-${GL_VERSION}/gitleaks"

if [ ! -x "$GL_BIN" ]; then
  echo "ERROR: Gitleaks binary not found or not executable at $GL_BIN" >&2
  exit 1
fi

# --- Working-tree scan ---
echo "[secrets] Running working-tree scan on $TARGET_PATH..." >&2
timeout "$STAGE_TIMEOUT" "$GL_BIN" detect \
  --source "$TARGET_PATH" \
  --config "$SCRIPT_DIR/gitleaks.toml" \
  --report-format json \
  --report-path "$TMPDIR_SCAN/wt.json" \
  --redact \
  --no-banner \
  --exit-code 0 2>>"$TMPDIR_SCAN/gitleaks.log" || {
    EC=$?
    if [ $EC -eq 124 ]; then
      echo "ERROR: Gitleaks working-tree scan timed out after ${STAGE_TIMEOUT}s" >&2
    else
      echo "ERROR: Gitleaks working-tree scan failed with exit code $EC" >&2
    fi
    exit 1
  }

# --- History scan (if in git repo) ---
if git -C "$REPO_ROOT" rev-parse --git-dir > /dev/null 2>&1; then
  echo "[secrets] Running git history scan..." >&2
  timeout "$STAGE_TIMEOUT" "$GL_BIN" detect \
    --source "$REPO_ROOT" \
    --config "$SCRIPT_DIR/gitleaks.toml" \
    --report-format json \
    --report-path "$TMPDIR_SCAN/hist.json" \
    --redact \
    --no-banner \
    --log-opts "--all" \
    --exit-code 0 2>>"$TMPDIR_SCAN/gitleaks.log" || {
      echo "WARNING: History scan failed (non-fatal); continuing with working-tree results only" >&2
    }
else
  echo "[secrets] Not a git repo; skipping history scan" >&2
fi

# --- Merge JSON arrays ---
"$PYTHON" - <<'PYEOF' "$TMPDIR_SCAN/wt.json" "${TMPDIR_SCAN}/hist.json" "$TMPDIR_SCAN/merged.json"
import json, sys

wt_file = sys.argv[1]
hist_file = sys.argv[2]
out_file = sys.argv[3]

def load(path):
    try:
        with open(path) as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception:
        return []

merged = load(wt_file) + load(hist_file)
with open(out_file, 'w') as f:
    json.dump(merged, f)
PYEOF

# --- Convert to SARIF ---
echo "[secrets] Converting to SARIF..." >&2
"$PYTHON" "$SCRIPT_DIR/to_sarif.py" \
  "$TMPDIR_SCAN/merged.json" \
  "$TARGET_REL" \
  "$REPO_ROOT" \
  "$GL_VERSION" \
  "$OUTPUT_DIR/secrets.sarif" || {
    rm -f "$OUTPUT_DIR/secrets.sarif"
    echo "ERROR: SARIF conversion failed" >&2
    exit 1
  }

# --- Validate output ---
echo "[secrets] Validating SARIF output..." >&2
"$PYTHON" "$REPO_ROOT/contracts/validate.py" "$OUTPUT_DIR/secrets.sarif" --stage secrets || {
  rm -f "$OUTPUT_DIR/secrets.sarif"
  echo "ERROR: SARIF validation failed" >&2
  exit 1
}

echo "[secrets] Done. Output: $OUTPUT_DIR/secrets.sarif" >&2
exit 0
