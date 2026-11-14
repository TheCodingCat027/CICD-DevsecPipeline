import os

root = r'C:\Users\Admin\Desktop\COLLEGE\TY\EH\EH CP\devsecops-pipeline'

stage_meta = {
    'secrets':   ('P2', '2', 'Detect hardcoded secrets and credentials in source code', 'Gitleaks', '8.21.2'),
    'sast':      ('P2', '2', 'Static application security testing for code vulnerabilities', 'Semgrep', '1.99.0'),
    'sca':       ('P2', '2', 'Software composition analysis — detect vulnerable dependencies', 'Trivy (filesystem mode)', '0.57.1'),
    'iac':       ('P3', '3', 'Infrastructure as Code security scanning (Dockerfile, Terraform, etc.)', 'Hadolint + Checkov', '2.12.0 / 3.2.0'),
    'container': ('P3', '3', 'Container image vulnerability scanning', 'Trivy (image mode)', '0.57.1'),
    'sbom':      ('P3', '3', 'Software Bill of Materials generation', 'Syft', '1.18.1'),
    'dast':      ('P3', '3', 'Dynamic application security testing (disabled by default)', 'OWASP ZAP', '2.15.0'),
}

for name, (owner, phase, purpose, tool, ver) in stage_meta.items():
    image_note = ''
    if name in ('container', 'dast'):
        image_note = '\n> **Note:** This stage requires a built container image. The image reference is passed via the `IMAGE_REF` environment variable.\n'
    if name == 'sbom':
        image_note = '\n> **Note:** This stage also writes a CycloneDX SBOM to `<output_dir>/artifacts/sbom/sbom.cdx.json`.\n'

    readme = f"""# Stage: `{name}`

**Owner:** {owner}  
**Phase:** Phase {phase} (stub in Phase 1; real implementation in Phase {phase})

## Purpose

{purpose}
{image_note}
## Real Tool

| Property | Value |
|----------|-------|
| Tool | {tool} |
| Pinned version (placeholder) | `{ver}` — {owner} must confirm and pin in their implementation |
| Install | See official {tool} installation docs |

## Interface

This stage implements the **universal stage interface**. See [contracts/stage-interface.md](../../contracts/stage-interface.md).

**Invocation:**
```bash
bash stages/{name}/run.sh <target_path> <output_dir>
```

**Output:**
- `<output_dir>/{name}.sarif` — always written, even with zero findings
- Exit 0 on success, exit 1 on scanner crash, exit 2 on argument error

## Current Stub Status

> ⚠️ This is a **Phase 1 stub**. It copies `contracts/samples/{name}.sarif` to the output
> directory and prints a reminder to stderr. No real scanning is performed.

## How to Replace This Stub (Phase {phase})

1. Install `{tool}` at a pinned version and update this README with the exact version.
2. Edit **only** `stages/{name}/run.sh` — replace the stub copy with real scanner invocation
   that writes `<output_dir>/{name}.sarif`.
3. Run `stages/{name}/tests/run_test.sh` to verify the output is valid SARIF.
4. Run `python contracts/validate.py <output_dir>/{name}.sarif --stage {name}` to confirm
   format compliance.
5. **Do NOT** touch `pipeline.yml`, `stages/stages.json`, or `contracts/` —
   only your stage folder changes.

## Running Tests

```bash
bash stages/{name}/tests/run_test.sh
```

## Ownership

All files inside `stages/{name}/` are owned by **{owner}** (see `CODEOWNERS`).
"""
    readme_path = os.path.join(root, 'stages', name, 'README.md')
    with open(readme_path, 'w', encoding='utf-8') as f:
        f.write(readme)

print('Stage READMEs written')

