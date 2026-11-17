#!/usr/bin/env bash
# stages/iac/run.sh - Hadolint + Checkov IaC scanning stage
# Owner: P3  Phase: 3
# Interface: stages/<name>/run.sh <target_path> <output_dir>
# See: contracts/stage-interface.md
set -euo pipefail

# -- Argument validation -------------------------------------------------------
if [ "$#" -ne 2 ]; then
  echo "Usage: $0 <target_path> <output_dir>" >&2
  echo "  target_path: path to the directory containing Dockerfile(s) to scan" >&2
  echo "  output_dir:  directory where iac.sarif will be written" >&2
  exit 2
fi

TARGET_PATH="$1"
OUTPUT_DIR="$2"

if [ ! -e "$TARGET_PATH" ]; then
  echo "ERROR: target_path '$TARGET_PATH' does not exist" >&2
  exit 2
fi

# -- Locate repo root (do not depend on cwd) -----------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# -- Create output and temporary directories ------------------------------------
mkdir -p "$OUTPUT_DIR"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

# -- Tool version constants -----------------------------------------------------
HADOLINT_VERSION="2.12.0"
CHECKOV_VERSION="3.2.405"
HADOLINT_CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/devsecops/hadolint-${HADOLINT_VERSION}"
HADOLINT_BIN_DEFAULT="$HADOLINT_CACHE_DIR/hadolint"
CHECKOV_CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/devsecops/checkov-${CHECKOV_VERSION}"

# -- Allow overrides via environment -------------------------------------------
HADOLINT_BIN="${HADOLINT_PATH:-$HADOLINT_BIN_DEFAULT}"

# -- Determine Python and Checkov invocation -----------------------------------
PYTHON="${PYTHON:-python3}"
if ! command -v "$PYTHON" >/dev/null 2>&1; then PYTHON="python"; fi

# Checkov can be invoked as a Python module (most portable) or via a path override
# If CHECKOV_PATH is set, use it directly; otherwise use python -c checkov invocation
USE_CHECKOV_MODULE=true
if [ -n "${CHECKOV_PATH:-}" ]; then
  USE_CHECKOV_MODULE=false
  CHECKOV_CMD="$CHECKOV_PATH"
fi

# -- Install Hadolint if needed ------------------------------------------------
if [ ! -x "$HADOLINT_BIN" ]; then
  echo "[iac] Installing Hadolint via install.sh..." >&2
  bash "$SCRIPT_DIR/install.sh"
  HADOLINT_BIN="$HADOLINT_BIN_DEFAULT"
fi

if [ ! -x "$HADOLINT_BIN" ]; then
  echo "ERROR: Hadolint binary not executable: $HADOLINT_BIN" >&2
  exit 1
fi

# Verify checkov is importable
if $USE_CHECKOV_MODULE; then
  if ! "$PYTHON" -c "import checkov" 2>/dev/null; then
    echo "[iac] Checkov not found in Python path; installing via install.sh..." >&2
    bash "$SCRIPT_DIR/install.sh"
    # After install, checkov should be available in the venv
    CHECKOV_VENV="$CHECKOV_CACHE_DIR/venv"
    if [ -f "$CHECKOV_VENV/bin/python" ]; then
      PYTHON="$CHECKOV_VENV/bin/python"
    elif [ -f "$CHECKOV_VENV/Scripts/python.exe" ]; then
      PYTHON="$CHECKOV_VENV/Scripts/python.exe"
    fi
    if ! "$PYTHON" -c "import checkov" 2>/dev/null; then
      echo "ERROR: Checkov not importable after install" >&2
      exit 1
    fi
  fi
fi

# -- Determine tool versions ---------------------------------------------------
HADOLINT_TOOL_VERSION="$("$HADOLINT_BIN" --version 2>/dev/null | awk '{print $NF}' | sed 's/^v//' || echo "$HADOLINT_VERSION")"
CHECKOV_TOOL_VERSION="$("$PYTHON" -c "import checkov; v=getattr(getattr(checkov,'version',None),'version',None); print(v or '$CHECKOV_VERSION')" 2>/dev/null || echo "$CHECKOV_VERSION")"
TOOL_VERSIONS="hadolint ${HADOLINT_TOOL_VERSION}; checkov ${CHECKOV_TOOL_VERSION}"

# -- Compute target relative path to repo root ---------------------------------
TARGET_ABS="$(cd "$TARGET_PATH" 2>/dev/null && pwd || echo "$TARGET_PATH")"
TARGET_REL=""
if [ "$TARGET_ABS" != "$REPO_ROOT" ]; then
  TARGET_REL="${TARGET_ABS#$REPO_ROOT/}"
  if [ "$TARGET_REL" = "$TARGET_ABS" ]; then
    TARGET_REL="$TARGET_PATH"
  fi
fi

# -- Find Dockerfile(s) in target ----------------------------------------------
DOCKERFILE=""
if [ -f "$TARGET_PATH/Dockerfile" ]; then
  DOCKERFILE="$TARGET_PATH/Dockerfile"
elif [ -f "$TARGET_PATH" ] && [[ "$TARGET_PATH" == *Dockerfile* ]]; then
  DOCKERFILE="$TARGET_PATH"
else
  # Search recursively for Dockerfile
  DOCKERFILE="$(find "$TARGET_PATH" -maxdepth 3 -name "Dockerfile" | head -1 || true)"
fi

if [ -z "$DOCKERFILE" ]; then
  echo "[iac] No Dockerfile found in $TARGET_PATH - writing zero-result SARIF" >&2
  PYTHON="${PYTHON:-python3}"
  if ! command -v "$PYTHON" >/dev/null 2>&1; then PYTHON="python"; fi
  # Write empty JSON files and produce zero-result SARIF
  echo "[]" > "$TMP_DIR/hadolint.json"
  echo "[]" > "$TMP_DIR/checkov.json"
  if ! "$PYTHON" "$SCRIPT_DIR/to_sarif.py" \
      "$TMP_DIR/hadolint.json" \
      "$TMP_DIR/checkov.json" \
      "$TARGET_REL" \
      "$REPO_ROOT" \
      "$TOOL_VERSIONS" \
      "$OUTPUT_DIR/iac.sarif"; then
    echo "ERROR: Failed to generate zero-result SARIF" >&2
    rm -f "$OUTPUT_DIR/iac.sarif"
    exit 1
  fi
  exit 0
fi

echo "[iac] Scanning Dockerfile: $DOCKERFILE" >&2

# -- Run Hadolint --------------------------------------------------------------
HADOLINT_JSON="$TMP_DIR/hadolint.json"
echo "[iac] Running Hadolint $HADOLINT_TOOL_VERSION..." >&2
if ! "$HADOLINT_BIN" --format json "$DOCKERFILE" > "$HADOLINT_JSON" 2>"$TMP_DIR/hadolint.log"; then
  HL_EC=$?
  # Hadolint exits non-zero when findings are found (1) or on error (>1)
  # Exit code 1 = findings found (not an error); we continue
  if [ "$HL_EC" -gt 1 ]; then
    echo "ERROR: Hadolint failed with exit code $HL_EC:" >&2
    cat "$TMP_DIR/hadolint.log" >&2
    rm -f "$OUTPUT_DIR/iac.sarif"
    exit 1
  fi
  # Exit code 1 is normal (findings found) - check output exists
fi

# If hadolint produced no output (e.g. empty file), set to empty array
if [ ! -s "$HADOLINT_JSON" ]; then
  echo "[]" > "$HADOLINT_JSON"
fi

# -- Run Checkov ---------------------------------------------------------------
CHECKOV_JSON="$TMP_DIR/checkov.json"
echo "[iac] Running Checkov $CHECKOV_TOOL_VERSION..." >&2

# Use run_checkov.py helper for portable execution (avoids .cmd shim on Windows)
if ! "$PYTHON" "$SCRIPT_DIR/run_checkov.py" "$TARGET_PATH" "$CHECKOV_JSON" 2>"$TMP_DIR/checkov.log"; then
  CK_EC=$?
  if [ "$CK_EC" -gt 1 ]; then
    echo "ERROR: Checkov runner failed with exit code $CK_EC:" >&2
    cat "$TMP_DIR/checkov.log" >&2
    rm -f "$OUTPUT_DIR/iac.sarif"
    exit 1
  fi
fi

cat "$TMP_DIR/checkov.log" >&2 2>/dev/null || true

if [ ! -s "$CHECKOV_JSON" ]; then
  echo "[iac] WARNING: Checkov produced no output - using empty result" >&2
  echo "[]" > "$CHECKOV_JSON"
fi

# -- Convert to SARIF ----------------------------------------------------------
PYTHON="${PYTHON:-python3}"
if ! command -v "$PYTHON" >/dev/null 2>&1; then PYTHON="python"; fi

if ! "$PYTHON" "$SCRIPT_DIR/to_sarif.py" \
    "$HADOLINT_JSON" \
    "$CHECKOV_JSON" \
    "$TARGET_REL" \
    "$REPO_ROOT" \
    "$TOOL_VERSIONS" \
    "$OUTPUT_DIR/iac.sarif"; then
  echo "ERROR: Failed to convert to SARIF" >&2
  rm -f "$OUTPUT_DIR/iac.sarif"
  exit 1
fi

# -- Validate generated SARIF --------------------------------------------------
if ! "$PYTHON" "$REPO_ROOT/contracts/validate.py" "$OUTPUT_DIR/iac.sarif" --stage iac; then
  echo "ERROR: Generated iac.sarif failed validation" >&2
  rm -f "$OUTPUT_DIR/iac.sarif"
  exit 1
fi

echo "[iac] Scan complete. Output: $OUTPUT_DIR/iac.sarif" >&2
exit 0
