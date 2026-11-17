# Phase 4 Evaluation: Policy Gate

**Author:** P4 | **Date:** 2026-11-18

## 1. Scope

This directory contains the Phase 4 policy gate evaluation. The gate
(`gate/run_gate.py`) replaces the Phase 1 stub and implements full policy
evaluation per `contracts/gate-interface.md`.

## 2. Test Scenarios

| Scenario | SARIF inputs | Expected exit | Decision |
|----------|-------------|---------------|----------|
| **Vulnerable app** | 6 SARIFs (all stages, vulnerable app) | `1` (blocked) | `fail` |
| **Fixed app** | 3 SARIFs (iac-fixed, container-fixed, sbom) | `0` (allowed) | `pass` |
| **Audit mode** | Same as vulnerable, mode=audit | `0` (not blocked) | `fail` (reported) |
| **Waiver applied** | Vulnerable + waiver on `aws-access-token` | `1` (blocked; secrets waived, vulns remain) | `fail` |
| **IAC only** | iac-vulnerable (2 Medium findings only) | `0` (within thresholds) | `pass` |

## 3. Vulnerable App Results

```
[gate] Found 6 SARIF file(s)
[gate] OK: container.sarif (22 finding(s))
[gate] OK: iac.sarif (2 finding(s))
[gate] OK: sast.sarif (3 finding(s))
[gate] OK: sbom.sarif (0 finding(s))
[gate] OK: sca.sarif (2 finding(s))
[gate] OK: secrets.sarif (1 finding(s))
[gate] Total findings: 30 (Critical=4, High=10, Medium=14, Low=2)
[gate] Policy VIOLATED — 5 violation(s)
[gate] Decision: FAIL  → EXIT 1
```

**5 violations triggered:**
1. Secrets threshold exceeded (1 secret, max=0)
2. Critical vulnerabilities exceeded (3 Critical, max=0)
3. High vulnerabilities exceeded (10 High, max=3)
4. Container must_run_as_non_root (DSP-IMG-001 finding)
5. Container banned_base_tags (DSP-IMG-002 finding; `latest` tag policy)

## 4. Fixed App Results

```
[gate] Found 3 SARIF file(s)
[gate] OK: container.sarif (7 finding(s))
[gate] OK: iac.sarif (0 finding(s))
[gate] OK: sbom.sarif (0 finding(s))
[gate] Total findings: 7 (Critical=0, High=0, Medium=5, Low=2)
[gate] All policy thresholds SATISFIED
[gate] Decision: PASS  → EXIT 0
```

The hardened demo-app/fixed (from Phase 3) passes all policy thresholds.

## 5. Policy Evaluation Logic Verified

| Feature | Test | Result |
|---------|------|--------|
| Secrets threshold (max_allowed=0) | 1 secret present | ✅ Violation |
| Vuln Critical threshold (max=0) | 3 Critical present | ✅ Violation |
| Vuln High threshold (max=3) | 10 High present | ✅ Violation |
| Vuln Medium threshold (null=unlimited) | 14 Medium present | ✅ No violation |
| Container must_run_as_non_root | DSP-IMG-001 present | ✅ Violation |
| Container banned_base_tags (latest) | DSP-IMG-002 present | ✅ Violation |
| Audit mode (mode=audit) | 5 violations found | ✅ Exit 0, decision=fail |
| Waiver by rule_id | aws-access-token waived | ✅ 1 waived, secrets violation removed |
| Waiver expiry | Expired waiver | ✅ Not applied |
| gate-result.json written | All scenarios | ✅ |
| findings.json written | All scenarios | ✅ |
| SARIF validation on bad file | Invalid SARIF → exit 2 | ✅ |
| Missing policy → exit 2 | Missing policy file | ✅ |

## 6. Exit Code Summary

| Scenario | Exit | Correct? |
|----------|------|----------|
| Vulnerable, enforce | 1 | ✅ |
| Fixed, enforce | 0 | ✅ |
| Vulnerable, audit | 0 | ✅ |
| Invalid SARIF | 2 | ✅ |
| Invalid policy | 2 | ✅ |

## 7. Output Artifacts

| File | Description |
|------|-------------|
| `gate-out-vulnerable/gate-result.json` | Decision=fail, 5 violations |
| `gate-out-vulnerable/findings.json` | 30 normalized findings |
| `gate-out-fixed/gate-result.json` | Decision=pass, 0 violations |
| `gate-out-fixed/findings.json` | 7 normalized findings |
| `gate-out-audit/gate-result.json` | Decision=fail (audit mode), exit 0 |
| `gate-out-waivered/gate-result.json` | Decision=fail, 4 violations (1 waiver applied) |
| `reports-vulnerable/` | Input SARIFs for vulnerable scenario |
| `reports-fixed/` | Input SARIFs for fixed scenario |
