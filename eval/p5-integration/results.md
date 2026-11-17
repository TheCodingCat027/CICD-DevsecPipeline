# Phase 5 Integration Test Report

**Author:** P4 (gate integration)  
**Date:** 2026-11-18  
**Status:** COMPLETE ✅ — 4/4 tests passed

---

## 1. Overview

This report documents the Phase 5 end-to-end integration test of the full DevSecOps
pipeline. The test feeds real SARIF outputs from all pipeline stages (Phases 2 and 3)
directly to the Phase 4 policy gate and verifies the pipeline's decision contract
under four scenarios.

**Test runner:** `eval/p5-integration/run_integration.py`

---

## 2. Test Scenarios & Results

### Test 1: Vulnerable App — Enforce Mode (expect BLOCKED)

| Item | Value |
|------|-------|
| Stages | secrets, sast, sca, iac, container, sbom |
| Total findings | 30 (Critical=4, High=10, Medium=14, Low=2) |
| Violations | 5 |
| Gate exit | **1** (BLOCKED) ✅ |
| Decision | `fail` |

**Violations triggered:**
1. `[SECRETS]` 1 secret found, max_allowed=0
2. `[VULNERABILITIES]` 3 Critical, max=0
3. `[VULNERABILITIES]` 10 High, max=3
4. `[CONTAINER]` DSP-IMG-001 root execution
5. `[CONTAINER]` DSP-IMG-002 banned base tag

---

### Test 2: Fixed App — Enforce Mode (expect ALLOWED)

| Item | Value |
|------|-------|
| Stages | iac-fixed, container-fixed, sbom |
| Total findings | 7 (Critical=0, High=0, Medium=5, Low=2) |
| Violations | 0 |
| Gate exit | **0** (ALLOWED) ✅ |
| Decision | `pass` |

The hardened demo-app/fixed (Phase 3) passes all policy thresholds. The 7 remaining
findings are all Medium/Low CVEs in container scan — within policy limits.

---

### Test 3: Vulnerable App — Audit Mode (expect exit 0 despite violations)

| Item | Value |
|------|-------|
| Stages | Same as Test 1 |
| Violations | 5 (same) |
| Gate exit | **0** (not blocked) ✅ |
| Decision | `fail` (reported, not enforced) |

The gate correctly reports violations in `gate-result.json` with `decision: fail`
but exits 0, allowing deployment to proceed in audit mode.

---

### Test 4: Vulnerable App + Waiver on `aws-access-token`

| Item | Value |
|------|-------|
| Waiver | `id: aws-access-token`, expires 2027-12-31 |
| Findings waived | 1 (the secrets finding) |
| Remaining violations | 4 (secrets violation removed) |
| Gate exit | **1** (still blocked) ✅ |
| Decision | `fail` |

The waiver correctly removes the secrets violation. Deployment remains blocked due
to the 4 remaining vulnerability/container violations.

---

## 3. Pipeline Stage Detection Summary

| Stage | Findings | Scanner | Phase |
|-------|----------|---------|-------|
| secrets | 1 Critical | Gitleaks 8.21.2 | P2 |
| sast | 3 (High/Medium) | Semgrep 1.185.0 | P2 |
| sca | 2 (Critical/High) | Trivy 0.76.2 | P2 |
| iac | 2 Medium | Hadolint+Checkov | P3 |
| container | 22 (Critical to Low) | Trivy + posture | P3 |
| sbom | 0 (inventory only) | Syft 1.18.1 | P3 |
| **Total** | **30** | — | P2+P3 |

---

## 4. Before / After Comparison

| Metric | Vulnerable App | Fixed App |
|--------|---------------|-----------|
| Findings | 30 | 7 |
| Critical | 4 | 0 |
| High | 10 | 0 |
| Medium | 14 | 5 |
| Low | 2 | 2 |
| Violations | 5 | 0 |
| Gate decision | FAIL | PASS |
| Deploy | BLOCKED | ALLOWED |

---

## 5. Full Pipeline Contract Verification

| Contract Requirement | Verified |
|---------------------|---------|
| Stage exits 0 on findings | ✅ (all stages) |
| Stage exits 1 on scanner crash | ✅ (tested in stage tests) |
| Stage exits 2 on bad args | ✅ (tested in stage tests) |
| Gate exits 0 on policy pass | ✅ T2 |
| Gate exits 1 on policy violated, enforce | ✅ T1 |
| Gate exits 0 on policy violated, audit | ✅ T3 |
| Gate exits 2 on invalid SARIF | ✅ (P4 unit tests) |
| Waivers reduce violation count | ✅ T4 |
| `gate-result.json` schema correct | ✅ all tests |
| `findings.json` contains all findings | ✅ all tests |
| Contracts (SARIF) never modified | ✅ |
| Ownership boundaries respected | ✅ |
