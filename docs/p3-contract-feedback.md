# Phase 3 Contract Feedback

**Author:** P3 | **Date:** 2026-11-18

## CF-001: IAC Stage — Single driver for two tools

**Problem:** `contracts/sarif-profile.md` requires exactly one `tool.driver` per SARIF run,
but the IAC stage must run both Hadolint and Checkov to cover all three seeded vulnerabilities
(V4, V5, V8). Using two separate runs would require two SARIF files, which the stage interface
does not support (one SARIF file per stage, named `iac.sarif`).

**Current workaround:** We use a combined driver:
```json
{
  "name": "hadolint+checkov",
  "version": "hadolint 2.12.0; checkov 3.2.405"
}
```
The `validate.py` `extract_findings` function uses `tool.driver.name` for the finding `tool` field,
so all IAC findings will have `tool: "hadolint+checkov"`. P4 (normalizer) must be aware of this.

**Proposed Amendment (CF-001):**
> Allow IAC stage to report `tool.driver.name` as a compound string `"hadolint+checkov"`.
> The normalizer should split on `+` and attribute findings to the appropriate tool
> based on ruleId prefix (`DL*/SC*` → hadolint, `CKV_*` → checkov).
> Alternatively, allow multiple runs in the SARIF for the IAC stage only.

---

## CF-002: Container stage — CVE location is file-level, not line-level

**Problem:** Trivy image scan reports vulnerabilities in OS/library packages but does
not map them back to specific Dockerfile lines. The contract requires `line` to be an
integer ≥ 0, with 0 meaning "file-level". We use `startLine: 1` for Dockerfile-level
CVE findings, which is not strictly accurate but satisfies the validator.

**Proposed Amendment (CF-002):**
> Clarify that for container-stage CVE findings, `line: 1` is acceptable as a convention
> meaning "derived from the base image at the FROM instruction". Alternatively, allow
> `startLine` to be absent when the finding is image-level (not file-level).

---

## CF-003: DAST stage — URI format for web endpoints

**Problem:** DAST findings have URLs (e.g. `http://app:5000/login`) as their location,
not file paths. The contract expects `uri` to be a repo-relative path. Using a web URL
in the `uri` field may confuse P4's normalizer.

**Proposed Amendment (CF-003):**
> For DAST findings, allow `uri` to be an HTTP/HTTPS URL in the `artifactLocation.uri` field.
> The finding's `file` field (derived by `extract_findings`) would then be the URL.
> Alternatively, add a separate `endpoint_url` property to the allowed properties list.
