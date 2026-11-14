#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PYTHON="${REPO_ROOT}/.venv/Scripts/python.exe"

for s in secrets sast sca iac container sbom; do
    echo "================ Testing stage: $s ================"
    bash "${REPO_ROOT}/stages/$s/tests/run_test.sh"
done
echo "================ All stage tests passed! ================"
