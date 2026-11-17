# Phase 4 Implementation Report: Policy Gate

**Author:** P4  
**Date:** 2026-11-18  
**Status:** COMPLETE ✅

---

## 1. Summary

Phase 4 replaces the Phase 1 stub gate (`gate/run_gate.py`) with a fully functional
policy gate implementing the complete `contracts/gate-interface.md` specification.

The gate:
- Validates all SARIF inputs and the policy file (exits 2 on errors)
- Normalizes findings via the stable `contracts/validate.extract_findings()` API
- Applies time-limited, scoped waivers from the policy
- Evaluates four threshold categories: secrets, vulnerabilities (by severity), and
  two container rules (must_run_as_non_root, banned_base_tags)
- Writes `gate-result.json` and `findings.json` to `--out`
- Correctly exits 0 (pass / audit-mode), 1 (policy violated, enforce mode), 2 (error)

---

## 2. Files Modified

| File | Change |
|------|--------|
| `gate/run_gate.py` | **Replaced** stub with real implementation (~330 lines) |
| `gate/README.md` | Updated to reflect Phase 4 (removed stub warning) |
| `docs/p4-assumptions.md` | **New** — 8 documented decisions |
| `docs/p4-contract-feedback.md` | **New** — 4 contract observations / proposed amendments |
| `docs/p4-policy-report.md` | **New** — this report |
| `docs/p4-handoff-to-p5.md` | **New** — integration guidance for Phase 5 |
| `eval/p4-policy/README.md` | **New** — evaluation scenarios and results |
| `eval/p4-policy/reports-vulnerable/` | **New** — 6 SARIFs for full pipeline test |
| `eval/p4-policy/reports-fixed/` | **New** — 3 SARIFs for fixed app test |
| `eval/p4-policy/gate-out-*/` | **New** — gate output for each test scenario |

---

## 3. Gate Behavior: Complete Specification Implemented

### 3.1 Policy Thresholds

| Policy Rule | Implementation |
|-------------|----------------|
| `secrets.max_allowed` | Count findings with `category=="secret"`, unwaived |
| `vulnerabilities.critical` | Count unwaived findings with `severity==Critical` in {sast,sca,iac,container,dast} |
| `vulnerabilities.high` | Same for High |
| `vulnerabilities.medium` | Same for Medium (null=unlimited) |
| `vulnerabilities.low` | Same for Low (null=unlimited) |
| `container.must_run_as_non_root` | Checks for DSP-IMG-001 rule_id in container findings |
| `container.banned_base_tags` | Checks for DSP-IMG-002 rule_id or tag name in description |

### 3.2 Waiver Logic

- Match by `waiver.id` against finding `id` (fingerprint), `rule_id`, or `cve_id`
- Reject expired waivers (`expires < today`)
- Optional `scope` glob-matched against `finding.file`
- Waived findings: `waived: true`, `waiver_id` set in `findings.json`
- Waived findings excluded from threshold counts

### 3.3 Exit Codes

| Scenario | Exit |
|----------|------|
| Policy satisfied, enforce | 0 |
| Policy satisfied, audit | 0 |
| Policy violated, enforce | 1 |
| Policy violated, audit | 0 (decision=fail in JSON) |
| Invalid SARIF | 2 |
| Invalid policy | 2 |
| Unhandled exception | 2 |

---

## 4. Verification Results

### 4.1 Vulnerable App (all 6 stages, enforce mode)
- **Exit:** 1 (BLOCKED) ✅
- **Decision:** fail
- **Total findings:** 30 (Critical=4, High=10, Medium=14, Low=2)
- **Violations:** 5 (secrets, 2×vulns, 2×container)

### 4.2 Fixed App (3 stages post-hardening)
- **Exit:** 0 (ALLOWED) ✅
- **Decision:** pass
- **Total findings:** 7 (Critical=0, High=0, Medium=5, Low=2)
- **Violations:** 0

### 4.3 Audit Mode (vulnerable, mode=audit)
- **Exit:** 0 (not blocked despite violations) ✅
- **Decision:** fail (correctly reported in gate-result.json)

### 4.4 Waiver by rule_id
- **Waiver:** `aws-access-token` (the secrets rule)
- **Result:** 1 finding waived, secrets violation removed, 4 violations remain ✅
- **Exit:** 1 (still blocked due to remaining violations) ✅

---

## 5. Design Decisions (see docs/p4-assumptions.md for full detail)

1. All non-secret categories → `vulnerabilities` threshold group
2. Container posture detected by DSP-IMG-001/002 rule_id
3. Waiver matches by id, rule_id, or cve_id (first match wins)
4. `counts` in output = unwaived only
5. `GATE_FORCE_FAIL` removed (stub-only mechanism)
6. Only `contracts/validate.py` imported (contracts frozen)
7. Violations include threshold/actual for dashboard consumption
8. `datetime.timezone.utc` used (Python 3.12 compatibility)

---

## 6. Known Limitations

- **Container CVE-level posture matching:** The `banned_base_tags` check looks at
  DSP-IMG-002 findings and description strings. If a future stage emits a base-tag
  violation with a different rule_id, the gate may miss it. See CF-004-003.
- **No `counts_total` field:** The gate does not separately report the total (including
  waived) finding count in `gate-result.json`. Downstream tools should use `findings.json`
  with `waived==true` filter. See CF-004-002.
- **No human-readable report:** Phase 4 produces JSON outputs only. A Markdown/HTML
  report generator would be a Phase 5 enhancement.

---

## 7. Contract Gaps (see docs/p4-contract-feedback.md)

| ID | Gap | Workaround |
|----|-----|-----------|
| CF-004-001 | violations[] schema not formally defined | 5-field objects produced consistently |
| CF-004-002 | counts: waived/unwaived ambiguity | Counts exclude waived (documented) |
| CF-004-003 | banned_base_tags matching logic not specified | DSP-IMG-002 rule_id used as indicator |
| CF-004-004 | violation.category enum mismatch with finding.category | Assumption A4-001 |

---

## 8. Acceptance Criteria

| # | Criterion | Status |
|---|-----------|--------|
| AC-1 | Gate exits 0 when policy satisfied | ✅ |
| AC-2 | Gate exits 1 when policy violated, enforce mode | ✅ |
| AC-3 | Gate exits 0 in audit mode regardless of violations | ✅ |
| AC-4 | Gate exits 2 on invalid SARIF | ✅ |
| AC-5 | Gate exits 2 on invalid policy | ✅ |
| AC-6 | gate-result.json written with correct schema | ✅ |
| AC-7 | findings.json written with all normalized findings | ✅ |
| AC-8 | Waivers applied and reflected in counts | ✅ |
| AC-9 | Waived findings marked in findings.json | ✅ |
| AC-10 | Secrets threshold enforced | ✅ |
| AC-11 | Vulnerability thresholds enforced (all severities) | ✅ |
| AC-12 | null threshold = unlimited | ✅ |
| AC-13 | container.must_run_as_non_root enforced | ✅ |
| AC-14 | container.banned_base_tags enforced | ✅ |
| AC-15 | SARIF validation occurs before policy evaluation | ✅ |
| AC-16 | contracts/ not modified | ✅ |
