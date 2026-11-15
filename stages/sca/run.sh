#!/usr/bin/env bash
# stages/sca/run.sh - Trivy filesystem SCA scanner stage
# Owner: P2  Phase: 2
# See: contracts/stage-interface.md
set -euo pipefail

# -- Argument validation -------------------------------------------------------
if [ "$#" -ne 2 ]; then
  echo "Usage: $0 <target_path> <output_dir>" >&2
  echo "  target_path: path to the directory or manifest to scan" >&2
  echo "  output_dir:  directory where sca.sarif will be written" >&2
  exit 2
fi

TARGET_PATH="$1"
OUTPUT_DIR="$2"

if [ ! -e "$TARGET_PATH" ]; then
  echo "ERROR: target_path '$TARGET_PATH' does not exist" >&2
  exit 2
fi

# -- Locate repo root and script dir -------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# -- Create output and temporary directories ------------------------------------
mkdir -p "$OUTPUT_DIR"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

# -- Setup Trivy configuration and binary --------------------------------------
TRIVY_VERSION="0.58.1"
TRIVY_DB_CACHE="${XDG_CACHE_HOME:-$HOME/.cache}/devsecops/trivy-db"
STAGE_TIMEOUT="${STAGE_TIMEOUT:-600}"
export TRIVY_NO_PROGRESS=true

if [ -z "${TRIVY_PATH:-}" ]; then
  bash "$SCRIPT_DIR/install.sh"
  TRIVY_BIN="${XDG_CACHE_HOME:-$HOME/.cache}/devsecops/trivy-${TRIVY_VERSION}/trivy"
else
  TRIVY_BIN="$TRIVY_PATH"
fi

if [ ! -x "$TRIVY_BIN" ]; then
  echo "ERROR: Trivy binary not executable: $TRIVY_BIN" >&2
  exit 1
fi

# -- Determine tool version ----------------------------------------------------
TOOL_VERSION="$("$TRIVY_BIN" --version 2>/dev/null | head -1 | awk '{print $NF}' | sed 's/^v//' || echo "$TRIVY_VERSION")"
if [ -z "$TOOL_VERSION" ]; then
  TOOL_VERSION="$TRIVY_VERSION"
fi

# -- Compute target relative path to repo root ---------------------------------
TARGET_ABS="$(cd "$TARGET_PATH" 2>/dev/null && pwd || echo "$TARGET_PATH")"
TARGET_REL=""
if [ "$TARGET_ABS" != "$REPO_ROOT" ]; then
  TARGET_REL="${TARGET_ABS#$REPO_ROOT/}"
  if [ "$TARGET_REL" = "$TARGET_ABS" ]; then
    TARGET_REL="$TARGET_PATH"
  fi
fi

# -- Construct scan arguments --------------------------------------------------
SCAN_ARGS=(
  filesystem
  --format json
  --output "$TMP_DIR/trivy.json"
  --severity CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN
  --vuln-type library
  --scanners vuln
  --skip-dirs .git,node_modules,.venv,venv,__pycache__
  --cache-dir "$TRIVY_DB_CACHE"
  --exit-code 0
)

if [ -n "${TRIVY_DB_REPOSITORY:-}" ]; then
  SCAN_ARGS+=(--db-repository "$TRIVY_DB_REPOSITORY")
fi

TIMEOUT_CMD=()
if command -v timeout >/dev/null 2>&1; then
  TIMEOUT_CMD=(timeout "$STAGE_TIMEOUT")
fi

# -- Run Trivy scan with retry loop (3 attempts) -------------------------------
for attempt in 1 2 3; do
  echo "[sca] Trivy scan attempt $attempt/3..." >&2
  if "${TIMEOUT_CMD[@]}" "$TRIVY_BIN" "${SCAN_ARGS[@]}" "$TARGET_PATH" 2>>"$TMP_DIR/trivy.log"; then
    break
  fi
  EC=$?
  echo "WARNING: Trivy attempt $attempt failed (exit $EC)" >&2
  if [ -f "$TMP_DIR/trivy.log" ]; then
    cat "$TMP_DIR/trivy.log" >&2
  fi
  if [ "$attempt" -eq 3 ]; then
    echo "ERROR: Trivy scan failed after 3 attempts" >&2
    exit 1
  fi
  sleep 5
done

if [ ! -f "$TMP_DIR/trivy.json" ]; then
  echo "ERROR: Trivy did not produce JSON output" >&2
  exit 1
fi

# -- Convert Trivy JSON to SARIF 2.1.0 -----------------------------------------
PYTHON="${PYTHON:-python3}"
if ! command -v "$PYTHON" >/dev/null 2>&1; then
  PYTHON="python"
fi

if ! "$PYTHON" "$SCRIPT_DIR/to_sarif.py" \
    "$TMP_DIR/trivy.json" \
    "$TARGET_REL" \
    "$REPO_ROOT" \
    "$TOOL_VERSION" \
    "$OUTPUT_DIR/sca.sarif"; then
  echo "ERROR: Failed to convert Trivy JSON to SARIF" >&2
  exit 1
fi

# -- Validate generated SARIF against contracts --------------------------------
if ! "$PYTHON" "$REPO_ROOT/contracts/validate.py" "$OUTPUT_DIR/sca.sarif" --stage sca; then
  echo "ERROR: Generated sca.sarif failed validation against contracts/validate.py" >&2
  exit 1
fi

echo "[sca] Scan complete. Output: $OUTPUT_DIR/sca.sarif" >&2
exit 0
