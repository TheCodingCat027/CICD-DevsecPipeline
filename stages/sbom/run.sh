#!/usr/bin/env bash
# stages/sbom/run.sh - Stub implementation
# Owner: P3  Phase: 3
# Replace this stub with the real scanner in Phase 3.
# See: contracts/stage-interface.md
set -euo pipefail

# -- Argument validation -------------------------------------------------------
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <target_path> <output_dir>" >&2
    echo "  target_path: path to the directory to scan" >&2
    echo "  output_dir:  directory where sbom.sarif will be written" >&2
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

# -- Create output directory ---------------------------------------------------
mkdir -p "$OUTPUT_DIR"

# -- Stub: copy sample SARIF ---------------------------------------------------
SAMPLE_SARIF="$REPO_ROOT/contracts/samples/sbom.sarif"

if [ ! -f "$SAMPLE_SARIF" ]; then
    echo "ERROR: Sample SARIF not found: $SAMPLE_SARIF" >&2
    exit 1
fi

cp "$SAMPLE_SARIF" "$OUTPUT_DIR/sbom.sarif"
echo "[stub] sbom: replace this stub with the real scanner (owner: P3)" >&2

# SBOM stage also produces a CycloneDX artifact
mkdir -p "$OUTPUT_DIR/artifacts/sbom"
cat > "$OUTPUT_DIR/artifacts/sbom/sbom.cdx.json" << 'CDXEOF'
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "metadata": {
    "timestamp": "2026-11-14T00:00:00Z",
    "tools": [{"name": "syft", "version": "1.18.1"}],
    "component": {"type": "application", "name": "demo-app-stub", "version": "0.0.0-stub"}
  },
  "components": []
}
CDXEOF
echo "[stub] sbom: wrote placeholder CycloneDX artifact" >&2
