import os

root = r'C:\Users\Admin\Desktop\COLLEGE\TY\EH\EH CP\devsecops-pipeline'

stages = [
  ('secrets', 'P2', '2'),
  ('sast',    'P2', '2'),
  ('sca',     'P2', '2'),
  ('iac',     'P3', '3'),
  ('container','P3','3'),
  ('sbom',    'P3', '3'),
  ('dast',    'P3', '3'),
]

for name, owner, phase in stages:
    stageDir = os.path.join(root, 'stages', name)
    testsDir = os.path.join(stageDir, 'tests')
    os.makedirs(testsDir, exist_ok=True)

    sbom_extra = ''
    if name == 'sbom':
        sbom_extra = '''
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
echo "[stub] sbom: wrote placeholder CycloneDX artifact" >&2'''

    run_sh_lines = [
        '#!/usr/bin/env bash',
        f'# stages/{name}/run.sh - Stub implementation',
        f'# Owner: {owner}  Phase: {phase}',
        f'# Replace this stub with the real scanner in Phase {phase}.',
        '# See: contracts/stage-interface.md',
        'set -euo pipefail',
        '',
        '# -- Argument validation -------------------------------------------------------',
        'if [ "$#" -ne 2 ]; then',
        '    echo "Usage: $0 <target_path> <output_dir>" >&2',
        '    echo "  target_path: path to the directory to scan" >&2',
        f'    echo "  output_dir:  directory where {name}.sarif will be written" >&2',
        '    exit 2',
        'fi',
        '',
        'TARGET_PATH="$1"',
        'OUTPUT_DIR="$2"',
        '',
        'if [ ! -e "$TARGET_PATH" ]; then',
        '    echo "ERROR: target_path \'$TARGET_PATH\' does not exist" >&2',
        '    exit 2',
        'fi',
        '',
        '# -- Locate repo root (do not depend on cwd) -----------------------------------',
        'SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"',
        'REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"',
        '',
        '# -- Create output directory ---------------------------------------------------',
        'mkdir -p "$OUTPUT_DIR"',
        '',
        '# -- Stub: copy sample SARIF ---------------------------------------------------',
        f'SAMPLE_SARIF="$REPO_ROOT/contracts/samples/{name}.sarif"',
        '',
        'if [ ! -f "$SAMPLE_SARIF" ]; then',
        '    echo "ERROR: Sample SARIF not found: $SAMPLE_SARIF" >&2',
        '    exit 1',
        'fi',
        '',
        f'cp "$SAMPLE_SARIF" "$OUTPUT_DIR/{name}.sarif"',
        f'echo "[stub] {name}: replace this stub with the real scanner (owner: {owner})" >&2',
    ]
    if sbom_extra:
        run_sh_lines.append(sbom_extra)

    run_path = os.path.join(stageDir, 'run.sh')
    with open(run_path, 'w', newline='\n', encoding='utf-8') as f:
        f.write('\n'.join(run_sh_lines) + '\n')

    # test script
    sbom_check_lines = []
    if name == 'sbom':
        sbom_check_lines = [
            '',
            '# Assert CycloneDX artifact was written',
            'if [ ! -f "$TMP_DIR/artifacts/sbom/sbom.cdx.json" ]; then',
            '    echo "FAIL: sbom.cdx.json not found in artifacts/sbom/" >&2',
            '    exit 1',
            'fi',
            'echo "PASS: sbom.cdx.json artifact exists"',
        ]

    test_sh_lines = [
        '#!/usr/bin/env bash',
        f'# stages/{name}/tests/run_test.sh',
        f'# Integration test for the {name} stub stage.',
        f'# {owner}: extend this with real known-bad inputs.',
        'set -euo pipefail',
        '',
        'SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"',
        'REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"',
        f'STAGE_SCRIPT="$REPO_ROOT/stages/{name}/run.sh"',
        'PYTHON="${PYTHON:-python3}"',
        '',
        '# Create temp output directory',
        'TMP_DIR="$(mktemp -d)"',
        'trap \'rm -rf "$TMP_DIR"\' EXIT',
        '',
        f'echo "--- Testing stage: {name} ---"',
        '',
        '# Run the stage against the demo-app target',
        'bash "$STAGE_SCRIPT" "$REPO_ROOT/demo-app/vulnerable" "$TMP_DIR"',
        '',
        '# Assert SARIF was written',
        f'if [ ! -f "$TMP_DIR/{name}.sarif" ]; then',
        f'    echo "FAIL: {name}.sarif not found in output directory" >&2',
        '    exit 1',
        'fi',
        f'echo "PASS: {name}.sarif exists"',
        '',
        '# Assert SARIF is valid per the contract',
        f'if "$PYTHON" "$REPO_ROOT/contracts/validate.py" "$TMP_DIR/{name}.sarif" --stage {name}; then',
        f'    echo "PASS: {name}.sarif is valid per contracts/validate.py"',
        'else',
        f'    echo "FAIL: {name}.sarif failed validation" >&2',
        '    exit 1',
        'fi',
    ] + sbom_check_lines + [
        '',
        f'echo "--- Stage {name} test: PASSED ---"',
    ]

    test_path = os.path.join(testsDir, 'run_test.sh')
    with open(test_path, 'w', newline='\n', encoding='utf-8') as f:
        f.write('\n'.join(test_sh_lines) + '\n')

print('All stage scripts written successfully')

