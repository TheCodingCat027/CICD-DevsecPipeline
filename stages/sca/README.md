# Stage: `sca`

**Owner:** P2  
**Phase:** Phase 2 (stub in Phase 1; real implementation in Phase 2)

## Purpose

Software composition analysis — detect vulnerable dependencies

## Real Tool

| Property | Value |
|----------|-------|
| Tool | Trivy (filesystem mode) |
| Pinned version (placeholder) | `0.57.1` — P2 must confirm and pin in their implementation |
| Install | See official Trivy (filesystem mode) installation docs |

## Interface

This stage implements the **universal stage interface**. See [contracts/stage-interface.md](../../contracts/stage-interface.md).

**Invocation:**
```bash
bash stages/sca/run.sh <target_path> <output_dir>
```

**Output:**
- `<output_dir>/sca.sarif` — always written, even with zero findings
- Exit 0 on success, exit 1 on scanner crash, exit 2 on argument error

## Current Stub Status

> ⚠️ This is a **Phase 1 stub**. It copies `contracts/samples/sca.sarif` to the output
> directory and prints a reminder to stderr. No real scanning is performed.

## How to Replace This Stub (Phase 2)

1. Install `Trivy (filesystem mode)` at a pinned version and update this README with the exact version.
2. Edit **only** `stages/sca/run.sh` — replace the stub copy with real scanner invocation
   that writes `<output_dir>/sca.sarif`.
3. Run `stages/sca/tests/run_test.sh` to verify the output is valid SARIF.
4. Run `python contracts/validate.py <output_dir>/sca.sarif --stage sca` to confirm
   format compliance.
5. **Do NOT** touch `pipeline.yml`, `stages/stages.json`, or `contracts/` —
   only your stage folder changes.

## Running Tests

```bash
bash stages/sca/tests/run_test.sh
```

## Ownership

All files inside `stages/sca/` are owned by **P2** (see `CODEOWNERS`).
