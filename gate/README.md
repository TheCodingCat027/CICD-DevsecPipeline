# Gate: `run_gate.py`

**Owner:** P4  
**Phase:** Phase 4 (real implementation; stub was Phase 1)

## Purpose

The gate is the final decision point before deployment. It:
1. Collects all SARIF reports from the stage jobs
2. Validates them against the contracts
3. Normalizes findings into a canonical format via `contracts/validate.extract_findings()`
4. Applies time-limited, scoped waivers from the policy
5. Evaluates findings against `security-policy.yaml` thresholds
6. Writes `gate-result.json` and `findings.json`
7. Exits with a code that the CI workflow uses to block or allow deployment

## Interface

```
python gate/run_gate.py --reports <dir> --policy <file> --out <dir>
```

| Argument | Description |
|----------|-------------|
| `--reports` | Directory containing stage output subdirectories with `*.sarif` files |
| `--policy` | Path to `security-policy.yaml` |
| `--out` | Output directory for result files |

**Environment variables:**

| Variable | Description |
|----------|-------------|
| `GATE_DEBUG=1` | Enable verbose debug output on stderr |

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
    "Critical": 0, "High": 0, "Medium": 0, "Low": 0
  },
  "violations": [
    {
      "category": "vulnerabilities",
      "severity": "Critical",
      "threshold": 0,
      "actual": 3,
      "message": "Vulnerability threshold exceeded: 3 Critical finding(s), max=0"
    }
  ],
  "waivers_applied": [],
  "generated_at": "2026-11-18T00:00:00Z"
}
```

**Notes:**
- `counts` reflects **unwaived** findings only
- `violations` is empty when `decision == "pass"`
- In `audit` mode: `decision` may be `"fail"` but exit code is always `0`

### `<out>/findings.json`

Array of all normalized findings (waived and unwaived), conforming to
`contracts/finding.schema.json`. Waived findings have `waived: true` and `waiver_id` set.

## Policy Evaluation

The gate evaluates four threshold categories:

| Policy Section | What it checks |
|----------------|----------------|
| `secrets.max_allowed` | Count of `category=="secret"` findings |
| `vulnerabilities.{critical,high,medium,low}` | Count by severity of non-secret findings |
| `container.must_run_as_non_root` | Presence of DSP-IMG-001 container findings |
| `container.banned_base_tags` | Presence of DSP-IMG-002 or banned-tag findings |

## Waivers

Add waivers to `security-policy.yaml`:

```yaml
waivers:
  - id: CVE-2024-12345          # or rule_id or sha256 fingerprint
    reason: "Mitigated by WAF"
    expires: "2027-06-30"
    approved_by: "security-lead"
    scope: "demo-app/vulnerable/*"   # optional glob
```

A waiver covers a finding when its `id` matches the finding's fingerprint, `rule_id`,
or `cve_id`, and the waiver has not expired.

## See Also

- [contracts/gate-interface.md](../contracts/gate-interface.md) — full interface spec
- [contracts/finding.schema.json](../contracts/finding.schema.json) — finding format
- [security-policy.yaml](../security-policy.yaml) — baseline policy
- [docs/p4-assumptions.md](../docs/p4-assumptions.md) — design decisions
- [docs/p4-contract-feedback.md](../docs/p4-contract-feedback.md) — contract observations
- [eval/p4-policy/](../eval/p4-policy/) — evaluation scenarios and results
