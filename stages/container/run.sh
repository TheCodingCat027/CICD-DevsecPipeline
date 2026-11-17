#!/usr/bin/env bash
# stages/container/run.sh - Trivy image scanning + posture checks
# Owner: P3  Phase: 3
# Interface: stages/<name>/run.sh <target_path> <output_dir>
# See: contracts/stage-interface.md
set -euo pipefail

# -- Argument validation -------------------------------------------------------
if [ "$#" -ne 2 ]; then
  echo "Usage: $0 <target_path> <output_dir>" >&2
  echo "  target_path: path to the directory containing the Dockerfile to build/scan" >&2
  echo "  output_dir:  directory where container.sarif will be written" >&2
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
TRIVY_VERSION="0.58.1"
TRIVY_CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/devsecops/trivy-${TRIVY_VERSION}"
TRIVY_BIN="${TRIVY_PATH:-$TRIVY_CACHE_DIR/trivy}"
TRIVY_DB_CACHE="${XDG_CACHE_HOME:-$HOME/.cache}/devsecops/trivy-db"
STAGE_TIMEOUT="${STAGE_TIMEOUT:-600}"
export TRIVY_NO_PROGRESS=true

# -- Install Trivy if needed ---------------------------------------------------
if [ ! -x "$TRIVY_BIN" ]; then
  echo "[container] Installing Trivy via install.sh..." >&2
  bash "$SCRIPT_DIR/install.sh"
  TRIVY_BIN="$TRIVY_CACHE_DIR/trivy"
fi

if [ ! -x "$TRIVY_BIN" ]; then
  echo "ERROR: Trivy binary not executable: $TRIVY_BIN" >&2
  rm -f "$OUTPUT_DIR/container.sarif"
  exit 1
fi

# -- Determine actual tool version ---------------------------------------------
TOOL_VERSION="$("$TRIVY_BIN" --version 2>/dev/null | head -1 | awk '{print $NF}' | sed 's/^v//' || echo "$TRIVY_VERSION")"
[ -z "$TOOL_VERSION" ] && TOOL_VERSION="$TRIVY_VERSION"

# -- Compute target relative path to repo root ---------------------------------
TARGET_ABS="$(cd "$TARGET_PATH" 2>/dev/null && pwd || echo "$TARGET_PATH")"
TARGET_REL="${TARGET_ABS#$REPO_ROOT/}"
[ "$TARGET_REL" = "$TARGET_ABS" ] && TARGET_REL="$TARGET_PATH"

# -- Find Dockerfile -----------------------------------------------------------
DOCKERFILE=""
if [ -f "$TARGET_PATH/Dockerfile" ]; then
  DOCKERFILE="$TARGET_PATH/Dockerfile"
elif [[ "$TARGET_PATH" == *Dockerfile* ]] && [ -f "$TARGET_PATH" ]; then
  DOCKERFILE="$TARGET_PATH"
else
  DOCKERFILE="$(find "$TARGET_PATH" -maxdepth 3 -name "Dockerfile" | head -1 || true)"
fi

DOCKERFILE_REL=""
if [ -n "$DOCKERFILE" ]; then
  DOCKERFILE_ABS="$(cd "$(dirname "$DOCKERFILE")" && pwd)/$(basename "$DOCKERFILE")"
  DOCKERFILE_REL="${DOCKERFILE_ABS#$REPO_ROOT/}"
  [ "$DOCKERFILE_REL" = "$DOCKERFILE_ABS" ] && DOCKERFILE_REL="Dockerfile"
  DOCKERFILE_REL="${DOCKERFILE_REL//\\//}"
else
  DOCKERFILE_REL="${TARGET_REL}/Dockerfile"
fi

PYTHON="${PYTHON:-python3}"
if ! command -v "$PYTHON" >/dev/null 2>&1; then PYTHON="python"; fi

# -- Posture checks (run before image scan to fail-fast) ----------------------
POSTURE_JSON="$TMP_DIR/posture.json"
# Use run_posture.py helper to avoid heredoc Python path issues on Windows
if [ -n "$DOCKERFILE" ]; then
  if ! "$PYTHON" "$SCRIPT_DIR/run_posture.py" "$DOCKERFILE" "$POSTURE_JSON" 2>&1; then
    echo "[container] WARNING: posture checks failed, using empty result" >&2
    echo "[]" > "$POSTURE_JSON"
  fi
else
  echo "[]" > "$POSTURE_JSON"
  echo "[container/posture] No Dockerfile found - skipping posture checks" >&2
fi

# -- Determine IMAGE_REF -------------------------------------------------------
# Priority: env var IMAGE_REF > build from Dockerfile > filesystem scan fallback
IMAGE_REF="${IMAGE_REF:-}"
BUILT_IMAGE=""
TRIVY_MODE="image"

if [ -z "$IMAGE_REF" ]; then
  if [ -n "$DOCKERFILE" ] && command -v docker >/dev/null 2>&1; then
    # Build a temporary image for scanning
    BUILT_IMAGE="devsecops-container-stage-tmp:$(date +%s)"
    echo "[container] Building temporary image $BUILT_IMAGE from $DOCKERFILE..." >&2
    if ! docker build -t "$BUILT_IMAGE" -f "$DOCKERFILE" "$(dirname "$DOCKERFILE")" >/dev/null 2>&1; then
      echo "[container] WARNING: docker build failed; falling back to filesystem scan" >&2
      BUILT_IMAGE=""
      TRIVY_MODE="fs"
    else
      IMAGE_REF="$BUILT_IMAGE"
    fi
  else
    echo "[container] No IMAGE_REF set and no Docker available; using filesystem scan fallback" >&2
    TRIVY_MODE="fs"
  fi
fi

TRIVY_JSON="$TMP_DIR/trivy.json"
TIMEOUT_CMD=()
if command -v timeout >/dev/null 2>&1; then
  TIMEOUT_CMD=(timeout "$STAGE_TIMEOUT")
fi

# -- Run Trivy (image mode or filesystem fallback) ----------------------------
if [ "$TRIVY_MODE" = "image" ] && [ -n "$IMAGE_REF" ]; then
  echo "[container] Running Trivy $TOOL_VERSION image scan on $IMAGE_REF..." >&2
  SCAN_ARGS=(
    image
    --format json
    --output "$TRIVY_JSON"
    --severity CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN
    --scanners vuln
    --cache-dir "$TRIVY_DB_CACHE"
    --exit-code 0
  )
  if [ -n "${TRIVY_DB_REPOSITORY:-}" ]; then
    SCAN_ARGS+=(--db-repository "$TRIVY_DB_REPOSITORY")
  fi

  SCAN_OK=false
  for attempt in 1 2 3; do
    echo "[container] Trivy image scan attempt $attempt/3..." >&2
    if "${TIMEOUT_CMD[@]}" "$TRIVY_BIN" "${SCAN_ARGS[@]}" "$IMAGE_REF" 2>>"$TMP_DIR/trivy.log"; then
      SCAN_OK=true
      break
    fi
    EC=$?
    echo "WARNING: Trivy attempt $attempt failed (exit $EC)" >&2
    if [ "$attempt" -eq 3 ]; then
      echo "ERROR: Trivy scan failed after 3 attempts" >&2
      [ -n "$BUILT_IMAGE" ] && docker rmi "$BUILT_IMAGE" >/dev/null 2>&1 || true
      rm -f "$OUTPUT_DIR/container.sarif"
      exit 1
    fi
    sleep 5
  done

  # Cleanup temp image
  if [ -n "$BUILT_IMAGE" ]; then
    docker rmi "$BUILT_IMAGE" >/dev/null 2>&1 || true
  fi
else
  # Filesystem fallback
  echo "[container] Running Trivy $TOOL_VERSION filesystem scan on $TARGET_PATH..." >&2
  SCAN_ARGS=(
    filesystem
    --format json
    --output "$TRIVY_JSON"
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

  for attempt in 1 2 3; do
    echo "[container] Trivy fs scan attempt $attempt/3..." >&2
    if "${TIMEOUT_CMD[@]}" "$TRIVY_BIN" "${SCAN_ARGS[@]}" "$TARGET_PATH" 2>>"$TMP_DIR/trivy.log"; then
      break
    fi
    EC=$?
    if [ "$attempt" -eq 3 ]; then
      echo "ERROR: Trivy scan failed after 3 attempts" >&2
      rm -f "$OUTPUT_DIR/container.sarif"
      exit 1
    fi
    sleep 5
  done
fi

if [ ! -f "$TRIVY_JSON" ]; then
  echo "ERROR: Trivy did not produce JSON output" >&2
  rm -f "$OUTPUT_DIR/container.sarif"
  exit 1
fi

# -- Convert to SARIF ----------------------------------------------------------
if ! "$PYTHON" "$SCRIPT_DIR/to_sarif.py" \
    "$TRIVY_JSON" \
    "$POSTURE_JSON" \
    "$DOCKERFILE_REL" \
    "$REPO_ROOT" \
    "$TOOL_VERSION" \
    "$OUTPUT_DIR/container.sarif"; then
  echo "ERROR: Failed to convert to SARIF" >&2
  rm -f "$OUTPUT_DIR/container.sarif"
  exit 1
fi

# -- Validate generated SARIF --------------------------------------------------
if ! "$PYTHON" "$REPO_ROOT/contracts/validate.py" "$OUTPUT_DIR/container.sarif" --stage container; then
  echo "ERROR: Generated container.sarif failed validation" >&2
  rm -f "$OUTPUT_DIR/container.sarif"
  exit 1
fi

echo "[container] Scan complete. Output: $OUTPUT_DIR/container.sarif" >&2
exit 0
