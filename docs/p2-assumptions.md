# Phase 2 — Assumptions and Design Decisions

> Owner: P2 | Phase: 2

This document records every decision Phase 2 made that the master prompt did not fully dictate.

---

## 1. Tool Versions

| Tool | Pinned Version | Rationale |
|------|---------------|-----------|
| Gitleaks | 8.21.2 | Latest stable at time of implementation |
| Semgrep | 1.100.0 | Latest stable open-source CLI |
| Trivy | 0.58.1 | Latest stable at time of implementation |

**Decision:** Binary checksums verified at install time by default.
`GITLEAKS_SKIP_VERIFY=1` and `TRIVY_SKIP_VERIFY=1` allow offline bypass for local dev
(install.sh still downloads and installs, but skips SHA256 check).

---

## 2. Branching Strategy

The master prompt says to create one branch per stage (`p2/secrets-gitleaks`, etc.).
In this implementation, all three stages were developed simultaneously in the shared
workspace (the prompt's alternative when independent branching is impractical in the
agent environment). Each stage is committed separately with its own conventional commit
message so they can be cherry-picked into individual branches for review.

**Risk:** minor — the diff per stage is clean because each stage touches only its own folder.

---

## 3. Secrets Stage — History Scan Scope

The master prompt asks to scan git history when the target is inside a git repository.
Gitleaks history scan (`--log-opts "--all"`) scans the **whole repository**, not just the
target subdirectory. This is documented in `stages/secrets/README.md` as a known limitation.

**Decision:** Keep this behaviour deliberate (the whole-repo scan is safer; it catches secrets
committed outside the target but still in the same repo). History-only findings are labelled
in message.text but not filtered out.

---

## 4. Secrets Redaction

Gitleaks is called with `--redact` so the tool itself replaces the secret value with `REDACTED`
in its JSON output. `to_sarif.py` additionally never copies the `Secret` or `Match` JSON fields
into SARIF output. The message text says `[REDACTED]` explicitly.

---

## 5. SAST — Semgrep Registry Packs

Default registry packs: `p/python`, `p/flask`, `p/owasp-top-ten`.

**Fail-closed decision:** If Semgrep cannot reach the registry and `SAST_ALLOW_OFFLINE=0`
(the default), `run.sh` exits 1. This was chosen over silent degradation. Rationale:
producing a SARIF with only custom rules but presenting it as a full scan would create
false confidence. The trade-off is documented in `stages/sast/README.md`.

---

## 6. SAST — Semgrep Exit Codes

Semgrep uses three exit codes: 0 = no findings, 1 = findings found, 2 = error.
Both 0 and 1 are treated as success from `run.sh`'s perspective (stage exits 0).
Only semgrep exit code 2 (or timeout) causes stage exit 1 (fail closed).

---

## 7. SCA — Trivy Scanners Restriction

Trivy filesystem mode is run with `--scanners vuln --vuln-type library` only.
Secret and misconfiguration scanners are disabled to avoid duplicate findings
with the `secrets` stage (Gitleaks) and P3's `iac` stage (Checkov/Hadolint).

---

## 8. SCA — V3 CVE IDs

The seeded-vulnerabilities.json marks V3 CVEs as `cve_verified: false`. Actual CVE IDs
reported by Trivy for Flask 1.0.2, Jinja2 2.10, PyYAML 5.1 may differ from or expand
upon the seeded list. This is documented in `stages/sca/README.md` and in
`docs/p2-requests-to-p1.md`.

---

## 9. SARIF $schema URI

Secrets and SAST to_sarif.py use the raw GitHub schema URI instead of the schemastore URI
used in the Phase 1 samples. The validator does not check this URI value, so both are valid.
No change to contracts needed.

---

## 10. `informationUri` in tool.driver

The secrets stage adds `informationUri` to `tool.driver`. This is a standard SARIF field
(not in result.properties) and does not conflict with `additionalProperties: false` on
result.properties. Confirmed by reading contracts/validate.py.

---

## 11. Evaluation — Deferred Pending Tool Installation

The evaluation script (`eval/p2-code/run_eval.sh`) requires Gitleaks, Semgrep, and Trivy
to be installed (network required). Numbers in `eval/p2-code/results.json` will be updated
after real runs. Tables in `docs/p2-implementation-report.md` are populated with structural
placeholders where real runs could not be performed.

---

*Last updated: Phase 2 implementation — 2026-11-15*
