#!/usr/bin/env bash
# stages/sbom/run.sh - Syft SBOM generation stage
# Owner: P3  Phase: 3
# Interface: stages/<name>/run.sh <target_path> <output_dir>
# See: contracts/stage-interface.md
set -euo pipefail

# -- Argument validation -------------------------------------------------------
if [ "$#" -ne 2 ]; then
  echo "Usage: $0 <target_path> <output_dir>" >&2
  echo "  target_path: path to directory or image to generate SBOM for" >&2
  echo "  output_dir:  directory where sbom.sarif and artifacts/sbom/sbom.cdx.json are written" >&2
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

# -- Create output directories -------------------------------------------------
mkdir -p "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR/artifacts/sbom"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

# -- Tool version constants -----------------------------------------------------
SYFT_VERSION="1.18.1"
SYFT_CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/devsecops/syft-${SYFT_VERSION}"
SYFT_BIN="${SYFT_PATH:-$SYFT_CACHE_DIR/syft}"

# -- Install Syft if needed ----------------------------------------------------
if [ ! -x "$SYFT_BIN" ]; then
  echo "[sbom] Installing Syft via install.sh..." >&2
  bash "$SCRIPT_DIR/install.sh"
  SYFT_BIN="$SYFT_CACHE_DIR/syft"
fi

if [ ! -x "$SYFT_BIN" ]; then
  echo "ERROR: Syft binary not executable: $SYFT_BIN" >&2
  rm -f "$OUTPUT_DIR/sbom.sarif"
  exit 1
fi

# -- Determine actual tool version ---------------------------------------------
TOOL_VERSION="$("$SYFT_BIN" version 2>/dev/null | grep -i 'version' | head -1 | awk '{print $NF}' | sed 's/^v//' || echo "$SYFT_VERSION")"
[ -z "$TOOL_VERSION" ] && TOOL_VERSION="$SYFT_VERSION"

PYTHON="${PYTHON:-python3}"
if ! command -v "$PYTHON" >/dev/null 2>&1; then PYTHON="python"; fi

# -- Determine scan source (IMAGE_REF or directory) ----------------------------
SYFT_SOURCE="${IMAGE_REF:-}"
SYFT_SCHEME="dir"
if [ -n "$SYFT_SOURCE" ]; then
  SYFT_SCHEME="registry"
  echo "[sbom] Using IMAGE_REF: $SYFT_SOURCE" >&2
else
  SYFT_SOURCE="$TARGET_PATH"
  SYFT_SCHEME="dir"
  echo "[sbom] Scanning directory: $SYFT_SOURCE" >&2
fi

# -- Run Syft to generate CycloneDX SBOM --------------------------------------
SBOM_OUTPUT="$OUTPUT_DIR/artifacts/sbom/sbom.cdx.json"
SYFT_ARGS=(
  scan
  -o "cyclonedx-json=$SBOM_OUTPUT"
  --quiet
)

# Add scope if scanning a directory
if [ "$SYFT_SCHEME" = "dir" ]; then
  SYFT_ARGS+=("dir:$SYFT_SOURCE")
else
  SYFT_ARGS+=("$SYFT_SOURCE")
fi

echo "[sbom] Running Syft $TOOL_VERSION..." >&2
if ! "$SYFT_BIN" "${SYFT_ARGS[@]}" 2>"$TMP_DIR/syft.log"; then
  SYFT_EC=$?
  echo "ERROR: Syft failed with exit code $SYFT_EC:" >&2
  cat "$TMP_DIR/syft.log" >&2
  rm -f "$OUTPUT_DIR/sbom.sarif"
  exit 1
fi

if [ ! -f "$SBOM_OUTPUT" ] || [ ! -s "$SBOM_OUTPUT" ]; then
  echo "ERROR: Syft did not produce SBOM output" >&2
  rm -f "$OUTPUT_DIR/sbom.sarif"
  exit 1
fi

# -- Validate the CycloneDX SBOM basic structure --------------------------------
"$PYTHON" - <<SBOM_VALIDATE_PYEOF
import json, sys

sbom_path = """$SBOM_OUTPUT"""
try:
    with open(sbom_path) as f:
        sbom = json.load(f)
except Exception as e:
    print(f"ERROR: Cannot parse SBOM: {e}", file=sys.stderr)
    sys.exit(1)

bom_format = sbom.get("bomFormat", "")
spec_version = sbom.get("specVersion", "")
components = sbom.get("components", [])

if bom_format != "CycloneDX":
    print(f"ERROR: SBOM bomFormat is '{bom_format}', expected 'CycloneDX'", file=sys.stderr)
    sys.exit(1)
if not spec_version:
    print("ERROR: SBOM missing specVersion", file=sys.stderr)
    sys.exit(1)

component_count = len(components)
print(f"[sbom/validate] CycloneDX {spec_version} SBOM: {component_count} component(s)", file=sys.stderr)
SBOM_VALIDATE_PYEOF

# -- Write SBOM summary JSON ---------------------------------------------------
"$PYTHON" - <<SUMMARY_PYEOF
import json, sys
from datetime import datetime, timezone

sbom_path = """$SBOM_OUTPUT"""
summary_path = """$OUTPUT_DIR/artifacts/sbom/sbom-summary.json"""

try:
    with open(sbom_path) as f:
        sbom = json.load(f)
except Exception as e:
    print(f"WARNING: Cannot parse SBOM for summary: {e}", file=sys.stderr)
    sbom = {}

components = sbom.get("components", [])
pkg_names = [c.get("name", "unknown") for c in components]

summary = {
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "tool": "syft",
    "tool_version": """$TOOL_VERSION""",
    "bom_format": sbom.get("bomFormat", "CycloneDX"),
    "spec_version": sbom.get("specVersion", ""),
    "component_count": len(components),
    "packages": pkg_names[:50],  # first 50
}

with open(summary_path, "w") as f:
    json.dump(summary, f, indent=2)

print(f"[sbom] Summary: {len(components)} packages", file=sys.stderr)
SUMMARY_PYEOF

# -- Generate zero-result SARIF ------------------------------------------------
if ! "$PYTHON" "$SCRIPT_DIR/to_sarif.py" \
    "$TOOL_VERSION" \
    "$OUTPUT_DIR/sbom.sarif"; then
  echo "ERROR: Failed to generate SARIF" >&2
  rm -f "$OUTPUT_DIR/sbom.sarif"
  exit 1
fi

# -- Validate generated SARIF --------------------------------------------------
if ! "$PYTHON" "$REPO_ROOT/contracts/validate.py" "$OUTPUT_DIR/sbom.sarif" --stage sbom; then
  echo "ERROR: Generated sbom.sarif failed validation" >&2
  rm -f "$OUTPUT_DIR/sbom.sarif"
  exit 1
fi

echo "[sbom] SBOM generation complete." >&2
echo "[sbom]   SARIF:   $OUTPUT_DIR/sbom.sarif" >&2
echo "[sbom]   CycloneDX: $SBOM_OUTPUT" >&2
exit 0
