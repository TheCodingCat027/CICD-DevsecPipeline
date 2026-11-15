#!/usr/bin/env bash
set -euo pipefail

# Argument validation
if [ "$#" -ne 2 ]; then
  echo "Usage: $0 <target_path> <output_dir>" >&2
  exit 2
fi

TARGET_PATH="$1"
OUTPUT_DIR="$2"

if [ ! -e "$TARGET_PATH" ]; then
  echo "ERROR: Target path '$TARGET_PATH' does not exist" >&2
  exit 2
fi

# Locate directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Configuration and environment variables
SEMGREP_VERSION="1.100.0"
CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/devsecops/semgrep-${SEMGREP_VERSION}"
VENV_DIR="$CACHE_DIR/venv"
SEMGREP_BIN="$VENV_DIR/bin/semgrep"

# Support both POSIX (bin) and Windows (Scripts) venv layouts if present
if [ ! -f "$SEMGREP_BIN" ] && [ -f "$VENV_DIR/Scripts/semgrep" ]; then
  SEMGREP_BIN="$VENV_DIR/Scripts/semgrep"
elif [ ! -f "$SEMGREP_BIN" ] && [ -f "$VENV_DIR/Scripts/semgrep.exe" ]; then
  SEMGREP_BIN="$VENV_DIR/Scripts/semgrep.exe"
fi

STAGE_TIMEOUT=${STAGE_TIMEOUT:-600}
SAST_ALLOW_OFFLINE=${SAST_ALLOW_OFFLINE:-0}
SAST_CUSTOM_RULES=${SAST_CUSTOM_RULES:-1}
SAST_REGISTRY_PACKS=${SAST_REGISTRY_PACKS:-"p/python p/flask p/owasp-top-ten"}

# Ensure Semgrep is installed
if [ ! -f "$SEMGREP_BIN" ]; then
  echo "[sast] Installing Semgrep $SEMGREP_VERSION..." >&2
  bash "$SCRIPT_DIR/install.sh" || {
    echo "ERROR: Semgrep installation failed" >&2
    exit 1
  }
  if [ ! -f "$SEMGREP_BIN" ] && [ -f "$VENV_DIR/Scripts/semgrep" ]; then
    SEMGREP_BIN="$VENV_DIR/Scripts/semgrep"
  elif [ ! -f "$SEMGREP_BIN" ] && [ -f "$VENV_DIR/Scripts/semgrep.exe" ]; then
    SEMGREP_BIN="$VENV_DIR/Scripts/semgrep.exe"
  fi
fi

if [ ! -f "$SEMGREP_BIN" ]; then
  echo "ERROR: Semgrep binary not found at $SEMGREP_BIN" >&2
  exit 1
fi

mkdir -p "$OUTPUT_DIR"

# Temporary directory for intermediate files
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

SEMGREP_JSON="$TMP_DIR/semgrep.json"
SEMGREP_LOG="$TMP_DIR/semgrep.log"

# Build config arguments
CONFIG_ARGS=()
if [ "$SAST_CUSTOM_RULES" = "1" ]; then
  CONFIG_ARGS+=(--config "$SCRIPT_DIR/rules/")
fi

if [ -n "$SAST_REGISTRY_PACKS" ]; then
  for pack in $SAST_REGISTRY_PACKS; do
    CONFIG_ARGS+=(--config "$pack")
  done
fi

if [ ${#CONFIG_ARGS[@]} -eq 0 ]; then
  echo "ERROR: No rules configured (SAST_CUSTOM_RULES=0 and empty SAST_REGISTRY_PACKS)" >&2
  exit 1
fi

run_semgrep() {
  local cfg=("$@")
  local ec=0
  if command -v timeout >/dev/null 2>&1; then
    timeout "$STAGE_TIMEOUT" "$SEMGREP_BIN" scan \
      --json --output "$SEMGREP_JSON" \
      --metrics=off --disable-version-check \
      "${cfg[@]}" \
      --exclude "tests" --exclude "__pycache__" --exclude ".venv" --exclude "venv" \
      "$TARGET_PATH" >"$SEMGREP_LOG" 2>&1 || ec=$?
  else
    "$SEMGREP_BIN" scan \
      --json --output "$SEMGREP_JSON" \
      --metrics=off --disable-version-check \
      "${cfg[@]}" \
      --exclude "tests" --exclude "__pycache__" --exclude ".venv" --exclude "venv" \
      "$TARGET_PATH" >"$SEMGREP_LOG" 2>&1 || ec=$?
  fi
  return $ec
}

SCAN_EC=0
run_semgrep "${CONFIG_ARGS[@]}" || SCAN_EC=$?

# Semgrep exit codes:
# 0 = no findings
# 1 = findings found
# 2 = error (or crash/invalid config)
# 124 = timeout

if [ "$SCAN_EC" -eq 124 ]; then
  echo "ERROR: Semgrep timed out after ${STAGE_TIMEOUT}s" >&2
  cat "$SEMGREP_LOG" >&2
  rm -f "$OUTPUT_DIR/sast.sarif"
  exit 1
fi

if [ "$SCAN_EC" -ne 0 ] && [ "$SCAN_EC" -ne 1 ]; then
  REGISTRY_FAILED=0
  if [ -n "$SAST_REGISTRY_PACKS" ]; then
    if grep -Ei "could not reach|network|connection|failed to download|registry|resolve|timed out" "$SEMGREP_LOG" >/dev/null 2>&1; then
      REGISTRY_FAILED=1
    fi
  fi

  if [ "$REGISTRY_FAILED" -eq 1 ]; then
    if [ "$SAST_ALLOW_OFFLINE" = "1" ] && [ "$SAST_CUSTOM_RULES" = "1" ]; then
      echo "WARNING: Semgrep failed to reach registry; falling back to offline custom rules only..." >&2
      SCAN_EC=0
      run_semgrep --config "$SCRIPT_DIR/rules/" || SCAN_EC=$?
      if [ "$SCAN_EC" -ne 0 ] && [ "$SCAN_EC" -ne 1 ]; then
        echo "ERROR: Offline scan failed with exit code $SCAN_EC" >&2
        cat "$SEMGREP_LOG" >&2
        rm -f "$OUTPUT_DIR/sast.sarif"
        exit 1
      fi
    else
      echo "ERROR: Semgrep failed to reach rule registry and SAST_ALLOW_OFFLINE=0 (fail-closed)" >&2
      cat "$SEMGREP_LOG" >&2
      rm -f "$OUTPUT_DIR/sast.sarif"
      exit 1
    fi
  else
    echo "ERROR: Semgrep scanner error (exit code $SCAN_EC)" >&2
    cat "$SEMGREP_LOG" >&2
    rm -f "$OUTPUT_DIR/sast.sarif"
    exit 1
  fi
fi

if [ ! -f "$SEMGREP_JSON" ]; then
  echo "ERROR: Semgrep output JSON not found" >&2
  rm -f "$OUTPUT_DIR/sast.sarif"
  exit 1
fi

# Tool version extraction
TOOL_VERSION=$("$SEMGREP_BIN" --version 2>/dev/null | head -1 | awk '{print $NF}' | tr -d '[:space:]')
if [ -z "$TOOL_VERSION" ]; then
  TOOL_VERSION="$SEMGREP_VERSION"
fi

PYTHON_BIN="${PYTHON:-python3}"
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  if command -v python >/dev/null 2>&1; then
    PYTHON_BIN="python"
  fi
fi

TARGET_REL="$(realpath --relative-to="$REPO_ROOT" "$TARGET_PATH" 2>/dev/null || echo "$TARGET_PATH")"

"$PYTHON_BIN" "$SCRIPT_DIR/to_sarif.py" \
  "$SEMGREP_JSON" \
  "$TARGET_REL" \
  "$REPO_ROOT" \
  "$TOOL_VERSION" \
  "$OUTPUT_DIR/sast.sarif" || {
    echo "ERROR: Failed to convert Semgrep results to SARIF" >&2
    rm -f "$OUTPUT_DIR/sast.sarif"
    exit 1
  }

# Validate generated SARIF
if [ -f "$REPO_ROOT/contracts/validate.py" ]; then
  "$PYTHON_BIN" "$REPO_ROOT/contracts/validate.py" "$OUTPUT_DIR/sast.sarif" --stage sast >&2 || {
    echo "ERROR: SARIF validation against contracts/validate.py failed" >&2
    rm -f "$OUTPUT_DIR/sast.sarif"
    exit 1
  }
fi

echo "[sast] Scan completed successfully. Output written to $OUTPUT_DIR/sast.sarif" >&2
exit 0
