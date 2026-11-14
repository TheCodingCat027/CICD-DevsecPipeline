# SARIF 2.1.0 Profile — DevSecOps Pipeline Contract

> **⚠️ FROZEN DOCUMENT**
> This file is part of the Phase 1 contracts. It is frozen after Phase 1 sign-off.
> Do not modify without following the amendment process in `contracts/CHANGELOG.md`.
> Any change requires a numbered CHANGELOG entry and approval from all four team members.

---

## 1. Overview

Every pipeline stage in this project **must** emit output conforming to the
[SARIF 2.1.0 specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
(OASIS Standard, 27 March 2020). This profile defines the **minimum required
fields** that all stages must populate, the **optional fields** that the
normalizer understands, and the **field mapping** from SARIF paths to
`NormalizedFinding` fields (see `finding.schema.json`).

SARIF is the lingua franca for static analysis results. By standardising on
it across all seven stages (secrets, sast, sca, iac, container, sbom, dast)
we keep the gate (`gate/run_gate.py`) and the normalizer (`contracts/validate.py`)
completely tool-agnostic: they consume the same schema regardless of whether
the underlying scanner is Gitleaks, Semgrep, Trivy, Hadolint, Checkov, or ZAP.

**Scope of this profile:**
- All seven stage `run.sh` scripts must write a `.sarif` file to `<output_dir>/<stage>.sarif`.
- The gate reads those SARIF files and passes each `result` through the normalizer.
- Non-SARIF artifacts (e.g. CycloneDX SBOM from Syft) are placed in
  `<output_dir>/artifacts/<stage>/` and are **not** validated against this profile.

---

## 2. Required Top-Level Structure

```json
{
  "version": "2.1.0",
  "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
  "runs": [ /* exactly one element */ ]
}
```

| Field | Type | Requirement | Notes |
|-------|------|-------------|-------|
| `version` | string | **Required** | Must be exactly `"2.1.0"` |
| `$schema` | string | Recommended | The OASIS schema URI above |
| `runs` | array | **Required** | Must contain **exactly one** run object |

The gate rejects files where `version != "2.1.0"` or where `runs` has zero or
more than one element (exit code 2 — internal error).

---

## 3. Required Run Fields

Each run object inside `runs[]` must contain:

```json
{
  "tool": {
    "driver": {
      "name": "<non-empty string>",
      "version": "<non-empty string>"
    }
  },
  "results": [ /* zero or more result objects — see §4 */ ]
}
```

### 3.1 `tool.driver.name`

- **Type:** non-empty string
- **Required:** Yes
- **Purpose:** Identifies the scanner. Used directly as the `tool` field in
  `NormalizedFinding`. Must match the tool name in `contracts/severity-map.md`
  so that severity normalization works correctly.
- **Examples:** `"gitleaks"`, `"semgrep"`, `"trivy"`, `"hadolint"`, `"checkov"`, `"zap"`, `"syft"`

### 3.2 `tool.driver.version`

- **Type:** non-empty string
- **Required:** Yes
- **Purpose:** Enforces the pipeline's requirement for pinned tool versions.
  Reviewers check that the version committed in `stages/<name>/README.md`
  matches the value emitted at runtime. Stubs may use `"stub"` as a placeholder,
  but real stage implementations must emit the actual installed version.
- **Examples:** `"8.18.4"`, `"1.91.0"`, `"0.57.1"`, `"2.12.0"`

### 3.3 `results`

- **Type:** array
- **Required:** Yes (but may be empty — see §5)
- **Contents:** Zero or more result objects conforming to §4.

---

## 4. Required Result Fields

Every element of `results[]` must contain the following fields:

```json
{
  "ruleId": "<string>",
  "level": "error | warning | note",
  "message": {
    "text": "<non-empty string>"
  },
  "locations": [
    {
      "physicalLocation": {
        "artifactLocation": {
          "uri": "<repo-relative path>"
        }
      }
    }
  ],
  "properties": {
    "severity": "Critical | High | Medium | Low",
    "category": "secret | sast | sca | iac | container | dast"
  }
}
```

### 4.1 `ruleId`

- **Type:** string
- **Required:** Yes
- **Purpose:** Tool-specific rule or check identifier. Maps to `rule_id` in `NormalizedFinding`.
- **Examples:** `"generic-api-key"`, `"javascript.lang.security.audit.sqli.node-mssql-sqli.node-mssql-sqli"`, `"CVE-2021-23337"`, `"DL3008"`, `"CKV_DOCKER_2"`

### 4.2 `level`

- **Type:** string enum
- **Required:** Yes
- **Allowed values:** `"error"`, `"warning"`, `"note"`
- **Purpose:** SARIF standard severity level. The normalizer uses this in
  combination with `properties.severity` for validation. If `properties.severity`
  is present it takes precedence for policy evaluation; `level` is kept for
  SARIF standard conformance.
- **Mapping guidance:** Use `"error"` for Critical/High, `"warning"` for Medium,
  `"note"` for Low and informational findings.

### 4.3 `message.text`

- **Type:** non-empty string
- **Required:** Yes
- **Purpose:** Human-readable description of the finding. Maps to `description`
  in `NormalizedFinding`.

### 4.4 `locations[0].physicalLocation.artifactLocation.uri`

- **Type:** string
- **Required:** Yes
- **Purpose:** Repo-relative path to the affected file. Maps to `file` in
  `NormalizedFinding`. Must be a forward-slash-separated path relative to the
  repository root (not an absolute path, not a `file://` URI).
- **Examples:** `"demo-app/vulnerable/app.py"`, `"Dockerfile"`, `"k8s/deployment.yaml"`

### 4.5 `properties.severity`

- **Type:** string enum
- **Required:** Yes (in `properties`)
- **Allowed values:** `"Critical"`, `"High"`, `"Medium"`, `"Low"` (exact casing)
- **Purpose:** Normalized severity used by the policy gate. Must be derived
  using the mapping table in `contracts/severity-map.md`. The original tool
  label should be preserved in `properties.raw_severity`.

### 4.6 `properties.category`

- **Type:** string enum
- **Required:** Yes (in `properties`)
- **Allowed values:** `"secret"`, `"sast"`, `"sca"`, `"iac"`, `"container"`, `"dast"`
- **Purpose:** Finding category for policy evaluation. Maps to `category` in
  `NormalizedFinding`. Each stage typically emits only one category, but
  cross-category findings (rare) are permitted.

---

## 5. Zero Results Is Valid

A SARIF file with an empty `results` array is **fully valid** under this profile:

```json
{
  "version": "2.1.0",
  "runs": [{
    "tool": {"driver": {"name": "semgrep", "version": "1.91.0"}},
    "results": []
  }]
}
```

Stages must always write their SARIF file, even when no findings are detected.
Absence of the SARIF file is treated as a scanner crash (exit code 1) and
blocks the pipeline.

---

## 6. Optional Result Properties

The following fields are understood by the normalizer and, when present, are
mapped into `NormalizedFinding`. All are placed inside `result.properties`
unless otherwise noted.

| SARIF Property Path | NormalizedFinding Field | Type | Notes |
|---------------------|------------------------|------|-------|
| `properties.fix` | `fix` | string \| null | Remediation advice |
| `properties.cve_id` | `cve_id` | string | e.g. `"CVE-2021-23337"` |
| `properties.cwe` | `cwe` | string | e.g. `"CWE-89"` |
| `properties.package` | `package` | string | SCA findings |
| `properties.installed_version` | `installed_version` | string | SCA findings |
| `properties.fixed_version` | `fixed_version` | string | SCA findings |
| `properties.fix_available` | `fix_available` | boolean | Whether a fix exists |
| `properties.confidence` | `confidence` | string | `"high"` \| `"medium"` \| `"low"` |
| `properties.raw_severity` | `raw_severity` | string | Original tool label |
| `locations[0].physicalLocation.region.startLine` | `line` | integer | Line number; 0 if absent |

If `locations[0].physicalLocation.region.startLine` is absent, the normalizer
defaults `line` to `0` (file-level finding).

If `properties.fix` is absent or `null`, the normalizer sets `fix` to `null`
in `NormalizedFinding`.

---

## 7. Field Mapping Table (Complete)

The table below documents the full mapping from SARIF result fields to
`NormalizedFinding` fields. This is the authoritative reference for anyone
implementing a stage or modifying the normalizer.

| `NormalizedFinding` Field | Required in Finding | Source SARIF Path | Transform |
|---------------------------|--------------------|--------------------|-----------|
| `tool` | Yes | `run.tool.driver.name` | Direct copy |
| `stage` | Yes | Injected by normalizer | Derived from filename `<stage>.sarif` |
| `category` | Yes | `result.properties.category` | Direct copy |
| `rule_id` | Yes | `result.ruleId` | Direct copy |
| `severity` | Yes | `result.properties.severity` | Must be Critical/High/Medium/Low |
| `file` | Yes | `result.locations[0].physicalLocation.artifactLocation.uri` | Direct copy |
| `line` | Yes | `result.locations[0].physicalLocation.region.startLine` | Default 0 if absent |
| `description` | Yes | `result.message.text` | Direct copy |
| `fix` | Yes | `result.properties.fix` | null if absent |
| `id` | No | Computed by normalizer | sha256 hex of `tool\|rule_id\|file\|line` |
| `cve_id` | No | `result.properties.cve_id` | Direct copy |
| `cwe` | No | `result.properties.cwe` | Direct copy |
| `package` | No | `result.properties.package` | Direct copy |
| `installed_version` | No | `result.properties.installed_version` | Direct copy |
| `fixed_version` | No | `result.properties.fixed_version` | Direct copy |
| `fix_available` | No | `result.properties.fix_available` | Direct copy |
| `confidence` | No | `result.properties.confidence` | Direct copy |
| `help_uri` | No | `result.properties.help_uri` | Direct copy |
| `raw_severity` | No | `result.properties.raw_severity` | Direct copy |
| `waived` | No | Set by gate only | Never set by stages |
| `waiver_id` | No | Set by gate only | Never set by stages |

---

## 8. Non-SARIF Artifacts

Some stages produce additional artifacts beyond their SARIF file:

- **sbom stage (Syft):** Produces a CycloneDX JSON SBOM at
  `<output_dir>/artifacts/sbom/sbom.cdx.json`. This is an inventory, not a
  findings file, and is **not** validated against this SARIF profile.
- **dast stage (ZAP):** May produce an HTML report at
  `<output_dir>/artifacts/dast/report.html` in addition to `dast.sarif`.

Non-SARIF artifacts go in `<output_dir>/artifacts/<stage>/` and must not be
placed at the root of `<output_dir>` where they might be confused with SARIF
files.

---

## 9. Validation

The normalizer in `contracts/validate.py` validates all SARIF files against
this profile before the gate evaluates policy. Validation failures cause the
gate to exit with code 2 (internal error), which blocks deployment regardless
of `mode`.

To validate a directory of SARIF samples manually:

```bash
python contracts/validate.py contracts/samples
```

To validate a single SARIF file:

```bash
python contracts/validate.py path/to/stage.sarif
```

---

## 10. Sample Conformant SARIF

```json
{
  "version": "2.1.0",
  "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "semgrep",
          "version": "1.91.0",
          "rules": [
            {
              "id": "python.django.security.injection.tainted-sql-string",
              "name": "SQL Injection",
              "shortDescription": {"text": "Unsanitized input passed to SQL query"}
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "python.django.security.injection.tainted-sql-string",
          "level": "error",
          "message": {
            "text": "Unsanitized user input is passed directly to a SQL query, risking SQL injection."
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "demo-app/vulnerable/app.py"
                },
                "region": {
                  "startLine": 42
                }
              }
            }
          ],
          "properties": {
            "severity": "High",
            "category": "sast",
            "cwe": "CWE-89",
            "confidence": "high",
            "raw_severity": "ERROR",
            "fix": "Use parameterized queries or an ORM instead of string concatenation.",
            "fix_available": true
          }
        }
      ]
    }
  ]
}
```

---

*Last updated: 2026-11-14 — Frozen at Phase 1 sign-off.*
