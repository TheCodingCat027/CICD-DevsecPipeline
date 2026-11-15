# Phase 2 — Evaluation Results

> Source of truth: `eval/p2-code/results.json`
> Updated: 2026-11-15 (requires real tool runs to populate numbers)

---

## 1. Detection Rate Summary

| Stage | Tool | Target Flaws | Detected | Detection Rate |
|-------|------|-------------|----------|---------------|
| secrets | Gitleaks 8.21.2 | V1 | not_run | not_run |
| sast | Semgrep 1.100.0 | V2, V6, V7 | not_run | not_run |
| sca | Trivy 0.58.1 | V3a, V3b, V3c | not_run | not_run |
| **Overall** | — | 7 flaws | not_run | not_run |

> **Note:** Numbers require Gitleaks, Semgrep, and Trivy to be installed with network
> access. Run `bash eval/p2-code/run_eval.sh` after tool installation.

---

## 2. False Positives on Fixed App (`demo-app/fixed`)

| Stage | Findings | Verdict |
|-------|----------|---------|
| secrets | not_run | Expected: 0 (no hardcoded secrets in fixed app) |
| sast | not_run | Expected: 0 (parameterized queries, scrypt, debug from env) |
| sca | not_run | Expected: some (fixed app still uses versioned packages; some may have CVEs) |

---

## 3. SAST Tuning Comparison

| Config | V2 detected | V6 detected | V7 detected | Total findings |
|--------|------------|------------|------------|---------------|
| Registry packs only | not_run | not_run | not_run | not_run |
| Custom rules only | not_run | not_run | not_run | not_run |
| Both (default) | not_run | not_run | not_run | not_run |

---

## 4. Findings by Severity (Vulnerable App)

| Stage | Critical | High | Medium | Low | Total |
|-------|----------|------|--------|-----|-------|
| secrets | not_run | not_run | — | — | not_run |
| sast | — | not_run | not_run | not_run | not_run |
| sca | not_run | not_run | not_run | not_run | not_run |

---

## 5. Runtime

| Stage | Cold (first run) | Warm (cached) |
|-------|-----------------|---------------|
| secrets | not_run | not_run |
| sast | not_run | not_run |
| sca | not_run | not_run |

---

## 6. Known False Negatives and Notes

- **V3 CVE IDs**: `seeded-vulnerabilities.json` marks V3 CVEs as `cve_verified: false`.
  Trivy may report different or additional CVE IDs for Flask 1.0.2 / Jinja2 2.10 / PyYAML 5.1.
  This is expected and correct — Trivy uses a live vulnerability database.
  See `docs/p2-requests-to-p1.md` Request 2 for the follow-up action.

---

*Populate after running: `bash eval/p2-code/run_eval.sh` from repo root.*
