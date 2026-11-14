#!/usr/bin/env bash
# stages/sca/run.sh - Stub implementation
# Owner: P2  Phase: 2
# Replace this stub with the real scanner in Phase 2.
# See: contracts/stage-interface.md
set -euo pipefail

# -- Argument validation -------------------------------------------------------
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <target_path> <output_dir>" >&2
    echo "  target_path: path to the directory to scan" >&2
    echo "  output_dir:  directory where sca.sarif will be written" >&2
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
SAMPLE_SARIF="$REPO_ROOT/contracts/samples/sca.sarif"

if [ ! -f "$SAMPLE_SARIF" ]; then
    echo "ERROR: Sample SARIF not found: $SAMPLE_SARIF" >&2
    exit 1
fi

cp "$SAMPLE_SARIF" "$OUTPUT_DIR/sca.sarif"
echo "[stub] sca: replace this stub with the real scanner (owner: P2)" >&2
