# Gate: `run_gate.py`

**Owner:** P4  
**Phase:** Phase 4 (stub in Phase 1; real implementation in Phase 4)

> ⚠️ **STUB** — Real policy evaluation arrives in Phase 4. This file contains a minimal
> stub that validates inputs and always passes unless `GATE_FORCE_FAIL=1`.

## Purpose

The gate is the final decision point before deployment. It:
1. Collects all SARIF reports from the stage jobs
2. Validates them against the contracts
3. Normalizes findings into a canonical format
4. Evaluates them against `security-policy.yaml`
5. Writes `gate-result.json` and `findings.json`
6. Exits with a code that the CI workflow uses to block or allow deployment

## Interface

```
python gate/run_gate.py --reports <dir> --policy <file> --out <dir>
```

| Argument | Description |
|----------|-------------|
| `--reports` | Directory containing stage output subdirectories with `*.sarif` files |
| `--policy` | Path to `security-policy.yaml` |
| `--out` | Output directory for result files |

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Policy satisfied (or `mode: audit`) → deployment may proceed |
| `1` | Policy violated → deployment **MUST NOT** run |
| `2` | Gate/internal error (invalid SARIF, invalid policy) → also blocks deployment |

## Output Files

### `<out>/gate-result.json`

```json
{
  "decision": "pass | fail | error",
  "mode": "enforce | audit",
  "counts": {
    "Critical": 0, "High": 3, "Medium": 5, "Low": 10
  },
  "violations": [],
  "waivers_applied": [],
  "generated_at": "2026-11-14T00:00:00Z",
  "stub": true,
  "note": "Phase 1 stub gate — real policy evaluation in Phase 4"
}
```

### `<out>/findings.json`

Array of normalized findings per `contracts/finding.schema.json`.

## Stub Behavior

The Phase 1 stub:
- Validates all SARIF files and the policy (exits 2 on validation error)
- **Always exits 0** (pass) unless the environment variable `GATE_FORCE_FAIL=1` is set
- With `GATE_FORCE_FAIL=1`: exits 1 with a simulated violation message

This lets the team demo the blocked-deploy path before Phase 4 is complete.

## Demo: Forced Failure

```bash
# Normal run (always passes)
python gate/run_gate.py --reports reports --policy security-policy.yaml --out gate-out

# Simulated failure (for demo)
GATE_FORCE_FAIL=1 python gate/run_gate.py --reports reports --policy security-policy.yaml --out gate-out
```

## Replacing This Stub (Phase 4)

1. Edit **only** `gate/run_gate.py` — replace the stub decision logic with real policy evaluation.
2. Keep the same CLI interface (`--reports`, `--policy`, `--out`) and exit codes.
3. Keep `gate-result.json` and `findings.json` output formats per `contracts/gate-interface.md`.
4. Do NOT touch `pipeline.yml` or `contracts/` — only `gate/run_gate.py` changes.
5. The `validate.extract_findings()` function from `contracts/validate.py` is the stable
   normalizer API — P4 must use it and not replace it.

## See Also

- [contracts/gate-interface.md](../contracts/gate-interface.md) — full interface spec
- [contracts/finding.schema.json](../contracts/finding.schema.json) — finding format
- [security-policy.yaml](../security-policy.yaml) — baseline policy (P4 owns from Phase 4)

