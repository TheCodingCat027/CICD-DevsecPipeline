# Phase 4 Handoff to Phase 5 (Integration)

**Author:** P4 | **Date:** 2026-11-18

## 1. What P4 Delivers

### gate/run_gate.py (real implementation)

The gate is fully operational. Invoke it as:

```bash
python gate/run_gate.py \
  --reports <reports-dir> \
  --policy security-policy.yaml \
  --out <output-dir>
```

Outputs:
- `<out>/gate-result.json` — machine-readable decision
- `<out>/findings.json` — all normalized findings with waiver status

### security-policy.yaml (baseline, owned by P4)

Current baseline policy (enforce mode):
- `secrets.max_allowed: 0` — zero secrets tolerated
- `vulnerabilities.critical: 0` — zero Critical vulns tolerated
- `vulnerabilities.high: 3` — up to 3 High vulns before blocking
- `vulnerabilities.medium: null` — unlimited Medium
- `vulnerabilities.low: null` — unlimited Low
- `container.must_run_as_non_root: true` — root containers blocked
- `container.banned_base_tags: [latest]` — floating tags blocked
- `waivers: []` — no waivers by default

## 2. Integration Notes for Phase 5

### 2.1 End-to-End Pipeline

The `.github/workflows/pipeline.yml` already calls the gate via the `gate` job
(last job before deploy). It passes the SARIF report directory from all stage jobs.
No CI changes are needed — the gate just works.

### 2.2 Demo: Blocking a Bad Build

Run with the vulnerable demo app to show the gate block:

```bash
# Run pipeline on vulnerable app → gate exits 1 → deploy is blocked
python gate/run_gate.py --reports tmp/reports-vuln --policy security-policy.yaml --out tmp/gate-out
cat tmp/gate-out/gate-result.json
```

### 2.3 Demo: Passing the Fixed Build

```bash
# Run pipeline on fixed app → gate exits 0 → deploy proceeds
python gate/run_gate.py --reports tmp/reports-fixed --policy security-policy.yaml --out tmp/gate-out
cat tmp/gate-out/gate-result.json
```

### 2.4 Demo: Audit Mode

Change `security-policy.yaml` `mode:` to `audit` to show reporting without blocking:

```bash
# Gate reports violations but exits 0
python gate/run_gate.py --reports tmp/reports-vuln --policy security-policy.yaml --out tmp/gate-out
```

### 2.5 Demo: Waivers

Add a waiver to `security-policy.yaml`:

```yaml
waivers:
  - id: aws-access-token
    reason: "Demo secret — will be removed before production"
    expires: "2027-12-31"
    approved_by: "team-lead"
```

The gate will show 1 waived finding and reduce the secrets violation count to 0.

## 3. Customizing the Policy

Edit `security-policy.yaml` to adjust thresholds:
- Set `mode: audit` for a sprint where you want visibility without blocking
- Set a threshold to `null` to effectively disable it
- Add waivers for known-safe CVEs with business justification and expiry date

The policy file is validated against `contracts/policy.schema.json` on every gate run.

## 4. What Phase 5 (Integration) Should Test

1. Full pipeline run (all 7 stages + gate) on both vulnerable and fixed demo app
2. Gate exit code correctly propagates to CI — deploy step should be skipped when exit=1
3. CI summary job reads `gate-result.json` and renders findings count + violations
4. Waiver workflow: add a waiver to policy, re-run, confirm fewer violations
5. Audit-mode demo: `mode: audit` shows all violations in JSON but doesn't block

## 5. Key File Locations

| File | Purpose |
|------|---------|
| `gate/run_gate.py` | Real policy gate |
| `security-policy.yaml` | Active policy (P4-owned, editable by team) |
| `contracts/gate-interface.md` | Full gate specification |
| `contracts/finding.schema.json` | Normalized finding format |
| `eval/p4-policy/` | Phase 4 evaluation scenarios and outputs |
| `docs/p4-assumptions.md` | Design decisions |
| `docs/p4-contract-feedback.md` | Contract observations for team review |
