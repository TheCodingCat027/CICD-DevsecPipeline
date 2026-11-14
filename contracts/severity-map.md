# Severity Mapping Reference

> **⚠️ FROZEN DOCUMENT**
> This file is part of the Phase 1 contracts. It is frozen after Phase 1 sign-off.
> Do not modify without following the amendment process in `contracts/CHANGELOG.md`.
> Any change requires a numbered CHANGELOG entry and approval from all four team members.

---

## 1. Introduction

Each security scanner in the pipeline uses its own severity labelling scheme.
This document is the **single authoritative mapping** that normalizes all tool-specific
severity labels to the four canonical values used by the policy gate and
`NormalizedFinding` schema:

| Canonical Value | Meaning |
|-----------------|---------|
| `Critical` | Immediate exploitation risk; deploy MUST be blocked (unless waived) |
| `High` | Serious risk; subject to policy threshold |
| `Medium` | Moderate risk; subject to policy threshold |
| `Low` | Minor risk; informational in most policies |

The normalizer in `contracts/validate.py` applies this map when converting
raw SARIF output to `NormalizedFinding` objects. Stages must preserve the
original label in `properties.raw_severity` so it is available for auditing.

**Fallback rule:** Any label not listed in this document maps to `Low`.

---

## 2. Severity Mapping Table

| Tool | Source Label | Maps To | Notes |
|------|-------------|---------|-------|
| Semgrep | `ERROR` | `High` | |
| Semgrep | `WARNING` | `Medium` | |
| Semgrep | `INFO` | `Low` | |
| Gitleaks | *(any secret)* | `High` | Cloud-provider credentials (AWS, GCP, Azure): `Critical` |
| Trivy | `CRITICAL` | `Critical` | |
| Trivy | `HIGH` | `High` | |
| Trivy | `MEDIUM` | `Medium` | |
| Trivy | `LOW` | `Low` | |
| Trivy | `UNKNOWN` | `Low` | |
| Hadolint | `error` | `High` | |
| Hadolint | `warning` | `Medium` | |
| Hadolint | `info` | `Low` | |
| Hadolint | `style` | `Low` | |
| Checkov | `CRITICAL` | `Critical` | If severity field present |
| Checkov | `HIGH` | `High` | If severity field present |
| Checkov | `MEDIUM` | `Medium` | If severity field present; default when no severity |
| Checkov | `LOW` | `Low` | If severity field present |
| ZAP | `High` | `High` | |
| ZAP | `Medium` | `Medium` | |
| ZAP | `Low` | `Low` | |
| ZAP | `Informational` | `Low` | |
| Syft | n/a | n/a | Inventory only; emits no findings |
| *(any/unknown)* | *(any unknown label)* | `Low` | Fallback rule |

---

## 3. Tool-Specific Notes

### 3.1 Semgrep

Semgrep uses a three-level SARIF `level` field: `error`, `warning`, `info`.
These map to the SARIF-level equivalents above. Semgrep rules may also carry
a `severity` metadata field — if present, it takes precedence over the SARIF
`level` for normalization. The normalizer checks `properties.severity` first
(already normalized by the stage script) then falls back to `level`.

### 3.2 Gitleaks

Gitleaks does not distinguish between different secret types in its severity
output — all detections are treated as the same level by the tool itself.
The pipeline stage script **must** post-process detections:

- Findings matching cloud-provider credential patterns (AWS access keys, GCP
  service account JSON, Azure client secrets, etc.) are promoted to **Critical**.
- All other secrets remain **High**.

The rule IDs from Gitleaks (e.g. `aws-access-token`, `gcp-service-account`,
`azure-client-secret`) must be used to drive this classification. When in
doubt, classify as **High** and document the rationale in the stage README.

### 3.3 Trivy

Trivy provides a consistent five-level severity schema that maps directly:
`CRITICAL → Critical`, `HIGH → High`, `MEDIUM → Medium`, `LOW → Low`,
`UNKNOWN → Low`. The `UNKNOWN` downgrade to `Low` reflects that unrated
vulnerabilities typically lack confirmed exploit code and are conservatively
treated as lower risk — but they still appear in the findings list for
tracking purposes.

Trivy is used in two stages:
- **SCA stage:** scans application dependencies (filesystem mode)
- **Container stage:** scans the built Docker image (image mode)

Both uses follow the same severity mapping.

### 3.4 Hadolint

Hadolint uses four severity levels: `error`, `warning`, `info`, `style`.
Both `info` and `style` map to `Low` since they represent best-practice
guidance rather than exploitable vulnerabilities. Hadolint's rule IDs
(e.g. `DL3008`, `SC2086`) serve as `rule_id` in `NormalizedFinding`.

### 3.5 Checkov

Checkov severity is **optional** in its output — older versions may omit it.
The normalization rules are:
1. If a `severity` field is present in the Checkov result, use the mapping above.
2. If the `severity` field is absent, default to **Medium**.

This conservative default ensures that unrated IaC misconfigurations are not
silently dropped below the policy threshold.

### 3.6 OWASP ZAP

ZAP uses a four-level risk rating: `High`, `Medium`, `Low`, `Informational`.
These map directly with `Informational → Low`. Note that ZAP findings are
DAST findings and are only emitted when the DAST stage is enabled
(`"enabled": true` in `stages/stages.json`). The DAST stage is disabled by
default in Phase 1.

### 3.7 Syft

Syft is a pure **inventory** tool — it generates a Software Bill of Materials
(SBOM) in CycloneDX format but emits no vulnerability findings of its own.
The SBOM artifact is placed at `<output_dir>/artifacts/sbom/sbom.cdx.json`
and is not validated against `finding.schema.json`. Syft's SARIF output
(if enabled) will have an empty `results` array.

---

## 4. The `raw_severity` Field

Every stage script **must** preserve the original tool severity label in
`properties.raw_severity` within the SARIF result. This enables:

- Auditors to verify that the normalization was applied correctly.
- Future amendments to this map to be validated against historical findings.
- Debugging when a finding appears at an unexpected severity level.

Example:
```json
{
  "properties": {
    "severity": "High",
    "raw_severity": "ERROR"
  }
}
```

---

## 5. Canonical Severity Values — Exact Casing

The four canonical values are case-sensitive. The gate and schema reject any
other casing:

| ✅ Accepted | ❌ Rejected |
|------------|------------|
| `Critical` | `CRITICAL`, `critical`, `crit` |
| `High` | `HIGH`, `high`, `hi` |
| `Medium` | `MEDIUM`, `medium`, `med` |
| `Low` | `LOW`, `low` |

---

*Last updated: 2026-11-14 — Frozen at Phase 1 sign-off.*
