# Phase 3 Handoff to P4

**Author:** P3 | **Date:** 2026-11-18

## 1. New Stages Delivered

| Stage | SARIF Output | Category | Tool Driver Name |
|-------|-------------|----------|------------------|
| `iac` | `iac.sarif` | `iac` | `hadolint+checkov` |
| `container` | `container.sarif` | `container` | `trivy` |
| `sbom` | `sbom.sarif` (zero results) | — | `syft` |
| `dast` | `dast.sarif` (disabled) | `dast` | `zap` |

## 2. Important Notes for P4 Normalizer

### 2.1 IAC Stage — Combined Tool Name

The `iac` stage SARIF has `tool.driver.name = "hadolint+checkov"`. When
`extract_findings` extracts the `tool` field, all IAC findings will have
`tool: "hadolint+checkov"`. To split them by actual scanner:
- `ruleId` starting with `DL` or `SC`: Hadolint
- `ruleId` starting with `CKV_`: Checkov

See `docs/p3-contract-feedback.md` CF-001 for the amendment proposal.

### 2.2 Container Stage — Dedup Keys

For container CVE findings, the natural dedup key is `(cve_id, package, installed_version)`.
DSP-IMG-001 and DSP-IMG-002 are unique per Dockerfile and don't need deduplication.

### 2.3 SBOM Stage — Zero Findings

The SBOM SARIF always has `results: []`. P4 should not expect any findings from this stage.
The CycloneDX artifact is at `<output_dir>/artifacts/sbom/sbom.cdx.json`.
A human-readable summary is at `<output_dir>/artifacts/sbom/sbom-summary.json`.

### 2.4 Container Stage Fallback Mode

If the container stage ran in filesystem fallback mode (no Docker), CVEs reported are
from application dependencies (similar to SCA), not OS-layer CVEs. The SARIF `category`
is still `container`. P4 may want to note this in reports.

## 3. Finding Categories Used

| Stage | Category |
|-------|----------|
| `iac` | `iac` |
| `container` (Trivy CVEs) | `container` |
| `container` (DSP-IMG-001/002) | `container` |
| `sbom` | (none — zero results) |
| `dast` | `dast` |

## 4. Policy Recommendations for P4

| Rule | Suggested Policy |
|------|-----------------|
| DSP-IMG-001 (root user) | BLOCK — severity: High |
| DSP-IMG-002 (untagged base) | WARN — severity: Medium |
| Hadolint DL3002 | BLOCK — severity: High |
| Hadolint DL3007 | WARN — severity: Medium |
| Checkov CKV_DOCKER_28 | WARN — severity: Medium |
| Trivy container CRITICAL | BLOCK |
| Trivy container HIGH | BLOCK (threshold: count > 0) |

## 5. Eval Results Reference

See `eval/p3-container/` for detection rates, before/after comparison,
false positive analysis, and raw SARIF copies.
