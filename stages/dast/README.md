# Stage: `dast`

**Owner:** P3  
**Phase:** Phase 3 (stub in Phase 1; real implementation in Phase 3)

## Purpose

Dynamic application security testing (disabled by default)

> **Note:** This stage requires a built container image. The image reference is passed via the `IMAGE_REF` environment variable.

## Real Tool

| Property | Value |
|----------|-------|
| Tool | OWASP ZAP |
| Pinned version (placeholder) | `2.15.0` — P3 must confirm and pin in their implementation |
| Install | See official OWASP ZAP installation docs |

## Interface

This stage implements the **universal stage interface**. See [contracts/stage-interface.md](../../contracts/stage-interface.md).

**Invocation:**
```bash
bash stages/dast/run.sh <target_path> <output_dir>
```

**Output:**
- `<output_dir>/dast.sarif` — always written, even with zero findings
- Exit 0 on success, exit 1 on scanner crash, exit 2 on argument error

## Current Stub Status

> ⚠️ This is a **Phase 1 stub**. It copies `contracts/samples/dast.sarif` to the output
> directory and prints a reminder to stderr. No real scanning is performed.

## How to Replace This Stub (Phase 3)

1. Install `OWASP ZAP` at a pinned version and update this README with the exact version.
2. Edit **only** `stages/dast/run.sh` — replace the stub copy with real scanner invocation
   that writes `<output_dir>/dast.sarif`.
3. Run `stages/dast/tests/run_test.sh` to verify the output is valid SARIF.
4. Run `python contracts/validate.py <output_dir>/dast.sarif --stage dast` to confirm
   format compliance.
5. **Do NOT** touch `pipeline.yml`, `stages/stages.json`, or `contracts/` —
   only your stage folder changes.

## Running Tests

```bash
bash stages/dast/tests/run_test.sh
```

## Ownership

All files inside `stages/dast/` are owned by **P3** (see `CODEOWNERS`).
