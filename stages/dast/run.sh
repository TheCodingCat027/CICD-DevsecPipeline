#!/usr/bin/env bash
# stages/dast/run.sh - OWASP ZAP baseline DAST scan stage
# Owner: P3  Phase: 3  Status: STRETCH (disabled in stages.json)
# Interface: stages/<name>/run.sh <target_path> <output_dir>
# See: contracts/stage-interface.md, docs/p3-requests-to-p1.md
set -euo pipefail

# -- Argument validation -------------------------------------------------------
if [ "$#" -ne 2 ]; then
  echo "Usage: $0 <target_path> <output_dir>" >&2
  echo "  target_path: path to the directory containing the app to scan" >&2
  echo "  output_dir:  directory where dast.sarif will be written" >&2
  exit 2
fi

TARGET_PATH="$1"
OUTPUT_DIR="$2"

if [ ! -e "$TARGET_PATH" ]; then
  echo "ERROR: target_path '$TARGET_PATH' does not exist" >&2
  exit 2
fi

# -- Locate repo root -----------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

mkdir -p "$OUTPUT_DIR"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

PYTHON="${PYTHON:-python3}"
if ! command -v "$PYTHON" >/dev/null 2>&1; then PYTHON="python"; fi

# -- Configuration -------------------------------------------------------------
ZAP_IMAGE="${ZAP_IMAGE:-ghcr.io/zaproxy/zaproxy:2.15.0}"
TARGET_URL="${DAST_TARGET_URL:-}"
APP_PORT="${DAST_APP_PORT:-5000}"
ZAP_TIMEOUT="${DAST_ZAP_TIMEOUT:-120}"

# -- Check Docker availability -------------------------------------------------
if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: Docker is required for DAST stage but not found" >&2
  rm -f "$OUTPUT_DIR/dast.sarif"
  exit 1
fi

# -- Start application if no TARGET_URL provided ------------------------------
APP_CONTAINER=""
if [ -z "$TARGET_URL" ]; then
  DOCKERFILE=""
  if [ -f "$TARGET_PATH/Dockerfile" ]; then
    DOCKERFILE="$TARGET_PATH/Dockerfile"
  else
    DOCKERFILE="$(find "$TARGET_PATH" -maxdepth 3 -name "Dockerfile" | head -1 || true)"
  fi

  if [ -z "$DOCKERFILE" ]; then
    echo "ERROR: No DAST_TARGET_URL set and no Dockerfile found in $TARGET_PATH" >&2
    rm -f "$OUTPUT_DIR/dast.sarif"
    exit 1
  fi

  DAST_NET="dast-net-$(date +%s)"
  APP_IMAGE="dast-app-$(date +%s)"
  APP_CONTAINER="dast-app-$(date +%s)"

  # Build app image
  echo "[dast] Building app image from $DOCKERFILE..." >&2
  if ! docker build -t "$APP_IMAGE" -f "$DOCKERFILE" "$(dirname "$DOCKERFILE")" >/dev/null 2>&1; then
    echo "ERROR: Failed to build app image for DAST" >&2
    rm -f "$OUTPUT_DIR/dast.sarif"
    exit 1
  fi

  # Create network
  docker network create "$DAST_NET" >/dev/null 2>&1 || true

  # Start app
  echo "[dast] Starting app container..." >&2
  APP_CONTAINER="$(docker run -d --network "$DAST_NET" --name "dast-app" -p "$APP_PORT:$APP_PORT" "$APP_IMAGE")"
  trap '
    docker rm -f "$APP_CONTAINER" >/dev/null 2>&1 || true
    docker rmi "$APP_IMAGE" >/dev/null 2>&1 || true
    docker network rm "$DAST_NET" >/dev/null 2>&1 || true
    rm -rf "$TMP_DIR"
  ' EXIT

  # Wait for app to be ready
  TARGET_URL="http://dast-app:$APP_PORT"
  echo "[dast] Waiting for app at $TARGET_URL ..." >&2
  for i in $(seq 1 15); do
    if docker exec "$APP_CONTAINER" python3 -c "
import urllib.request
try:
    urllib.request.urlopen('http://localhost:$APP_PORT/', timeout=2)
    exit(0)
except:
    exit(1)
" 2>/dev/null; then
      break
    fi
    sleep 2
  done
fi

# -- Pull ZAP image ------------------------------------------------------------
echo "[dast] Pulling ZAP image $ZAP_IMAGE ..." >&2
docker pull --quiet "$ZAP_IMAGE" 2>&1 || {
  echo "ERROR: Failed to pull ZAP image $ZAP_IMAGE" >&2
  rm -f "$OUTPUT_DIR/dast.sarif"
  exit 1
}

# -- Run ZAP baseline scan -----------------------------------------------------
ZAP_REPORT="$TMP_DIR/zap-report.json"
echo "[dast] Running ZAP baseline scan against $TARGET_URL ..." >&2

DOCKER_ARGS=(
  run --rm
  -v "$TMP_DIR:/zap/wrk"
)
if [ -n "$APP_CONTAINER" ]; then
  DOCKER_ARGS+=(--network "$DAST_NET")
fi
DOCKER_ARGS+=(
  "$ZAP_IMAGE"
  zap-baseline.py
  -t "$TARGET_URL"
  -J "zap-report.json"
  -I
  -T "$ZAP_TIMEOUT"
)

# ZAP exits 1 on alerts found (normal), 0 when clean
docker "${DOCKER_ARGS[@]}" 2>"$TMP_DIR/zap.log" && ZAP_EC=0 || ZAP_EC=$?

if [ "$ZAP_EC" -gt 2 ]; then
  echo "ERROR: ZAP failed with exit code $ZAP_EC:" >&2
  cat "$TMP_DIR/zap.log" >&2
  rm -f "$OUTPUT_DIR/dast.sarif"
  exit 1
fi

if [ ! -f "$TMP_DIR/zap-report.json" ]; then
  echo "ERROR: ZAP did not produce report JSON" >&2
  rm -f "$OUTPUT_DIR/dast.sarif"
  exit 1
fi

cp "$TMP_DIR/zap-report.json" "$ZAP_REPORT"

# -- Convert ZAP JSON to SARIF -------------------------------------------------
"$PYTHON" "$SCRIPT_DIR/to_sarif.py" \
    "$ZAP_REPORT" \
    "$TARGET_PATH" \
    "$REPO_ROOT" \
    "$ZAP_IMAGE" \
    "$OUTPUT_DIR/dast.sarif" || {
  echo "ERROR: Failed to convert ZAP report to SARIF" >&2
  rm -f "$OUTPUT_DIR/dast.sarif"
  exit 1
}

# -- Validate ------------------------------------------------------------------
if ! "$PYTHON" "$REPO_ROOT/contracts/validate.py" "$OUTPUT_DIR/dast.sarif" --stage dast; then
  echo "ERROR: Generated dast.sarif failed validation" >&2
  rm -f "$OUTPUT_DIR/dast.sarif"
  exit 1
fi

echo "[dast] Scan complete. Output: $OUTPUT_DIR/dast.sarif" >&2
exit 0
