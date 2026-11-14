# Stage Interface Contract

> **⚠️ FROZEN DOCUMENT**
> This file is part of the Phase 1 contracts. It is frozen after Phase 1 sign-off.
> Do not modify without following the amendment process in `contracts/CHANGELOG.md`.
> Any change requires a numbered CHANGELOG entry and approval from all four team members.

---

## 1. Overview

Every pipeline stage is a self-contained shell script that accepts a standard
set of arguments, writes output to a designated directory, and exits with a
well-defined code. This contract defines that universal interface so that:

- The orchestrator (`scripts/run-pipeline.sh`) can invoke any stage the same way.
- Stage authors (P2, P3) know exactly what their script must implement.
- The gate (`gate/run_gate.py`) knows exactly where to find SARIF output.
- CI workflows (`.github/workflows/`) can remain tool-agnostic.

---

## 2. Universal Invocation

```bash
stages/<name>/run.sh <target_path> <output_dir>
```

| Argument | Description |
|----------|-------------|
| `<target_path>` | Absolute or repo-relative path to the directory being scanned (the repository root in most cases) |
| `<output_dir>` | Absolute path where the stage must write all its output |

**Example calls:**

```bash
stages/secrets/run.sh   /repo /tmp/reports
stages/sast/run.sh      /repo /tmp/reports
stages/sca/run.sh       /repo /tmp/reports
stages/iac/run.sh       /repo /tmp/reports
stages/container/run.sh /repo /tmp/reports    # requires IMAGE_REF env var
stages/sbom/run.sh      /repo /tmp/reports    # IMAGE_REF optional
stages/dast/run.sh      /repo /tmp/reports    # requires IMAGE_REF env var
```

---

## 3. Output Specification

### 3.1 Primary SARIF Output (Mandatory)

Every stage **must** write exactly one SARIF 2.1.0 file:

```
<output_dir>/<stage_name>.sarif
```

This file must conform to `contracts/sarif-profile.md`. It must always be
written — even when the scan finds zero issues. Absence of the SARIF file is
treated as a scanner crash (exit code 1).

Examples:
- `secrets.sarif`
- `sast.sarif`
- `sca.sarif`
- `iac.sarif`
- `container.sarif`
- `sbom.sarif`
- `dast.sarif`

### 3.2 Non-SARIF Artifacts (Optional)

Stages may write additional artifacts that are not SARIF files. These must go
into a stage-specific subdirectory:

```
<output_dir>/artifacts/<stage_name>/
```

Examples:
- `<output_dir>/artifacts/sbom/sbom.cdx.json` — CycloneDX SBOM from Syft
- `<output_dir>/artifacts/dast/report.html` — ZAP HTML report

Non-SARIF artifacts are **not** validated by the normalizer and do not affect
gate decisions directly. They are preserved for auditing and reporting purposes.

> **Important:** Do not place non-SARIF artifacts at the root of `<output_dir>`.
> The gate scans `<output_dir>` for `*.sarif` files; unexpected files there
> may cause validation errors (gate exit code 2).

---

## 4. Exit Codes

| Exit Code | Meaning | Gate Behavior |
|-----------|---------|---------------|
| `0` | Scan completed successfully (regardless of findings) | Gate proceeds to read the SARIF file |
| `1` | Scanner crashed or failed (tool not installed, licence error, unhandled exception) | Gate treats this as a pipeline failure and blocks deployment |
| `2` | Usage error (wrong number of arguments, unreadable target path) | Gate treats this as a configuration error and blocks deployment |

**Critical distinction:** Exit code 0 does not mean "no findings found". It
means "the scanner ran successfully and produced a SARIF file". The number of
findings is determined by reading the SARIF file, not by the exit code.

Stages must **not** exit non-zero merely because findings were detected.
Policy evaluation (whether findings block deployment) is the gate's job.

---

## 5. Idempotency

Every stage script **must** be idempotent:

- Running the same stage twice on the same input must produce equivalent output.
- The script must **not** modify `<target_path>` or any files within it.
- The script should overwrite any existing files in `<output_dir>` rather than
  appending to them.
- Running with an empty `<output_dir>` or a pre-populated `<output_dir>` must
  produce the same result.

---

## 6. Logging and I/O

| Stream | Usage |
|--------|-------|
| **stderr** | All log output: tool invocation commands, progress messages, warnings, error details |
| **stdout** | Must remain empty (or contain only the SARIF file content if the tool writes to stdout and cannot be redirected) |

Keeping stdout quiet ensures that CI systems that capture stdout do not
accidentally ingest diagnostic messages. The orchestrator and CI workflow
redirect stderr to log files for debugging.

---

## 7. Per-Stage Folder Requirements

Each stage folder (`stages/<name>/`) must contain:

### 7.1 `README.md` (required)

Must document:
- The scanner tool being used (name and pinned version)
- Installation method (pip, npm, binary download, Docker image — must be pinned)
- Brief description of what the stage scans
- Known limitations or caveats

Example:
```markdown
# Secrets Stage

**Tool:** Gitleaks v8.18.4
**Install:** `curl -sSfL https://github.com/gitleaks/gitleaks/releases/download/v8.18.4/gitleaks_8.18.4_linux_x64.tar.gz | tar -xz`

Scans the entire repository for hardcoded secrets, tokens, and credentials
using Gitleaks pattern rules.
```

### 7.2 `run.sh` (required)

The main stage script. Must be executable (`chmod +x`). Must implement the
universal invocation interface defined in §2.

### 7.3 `tests/` (required)

Must contain:
- At least one "known-bad" input file (a file that will produce at least one
  finding when scanned)
- A file documenting the expected finding count for the known-bad input
  (e.g. `expected.txt` or inline assertions in a test script)

These are used by the stage's test suite to verify the scanner is working
correctly. They should use clearly fake / obviously synthetic values to avoid
triggering real security alerts.

### 7.4 Pinned Install Method

Tool versions must be pinned — not `latest`, not `>=x.y.z`. The pinned
version must appear in:
- `README.md`
- The install command within `run.sh`
- `tool.driver.version` in emitted SARIF

---

## 8. Special Environment Variables

Some stages require a Docker image reference because they scan a built
container rather than (or in addition to) the source tree.

| Environment Variable | Required By | Description |
|----------------------|-------------|-------------|
| `IMAGE_REF` | `container`, `dast` | Full Docker image reference including tag, e.g. `myapp:abc1234` |
| `IMAGE_REF` | `sbom` (optional) | If set, Syft scans the image; if unset, Syft scans the filesystem |

If `IMAGE_REF` is required but not set, the stage must exit with code 2
(usage error) and print a descriptive message to stderr.

```bash
# Example guard in run.sh
if [[ -z "${IMAGE_REF:-}" ]]; then
  echo "ERROR: IMAGE_REF must be set for the container stage" >&2
  exit 2
fi
```

---

## 9. Python Module Interface

The normalizer function in `contracts/validate.py` exposes a stable Python
API that stage authors and P4 may import:

```python
from contracts.validate import extract_findings

findings: list[dict] = extract_findings(sarif_dict)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `sarif_dict` | `dict` | Parsed SARIF JSON (top-level object) |

| Return value | Type | Description |
|--------------|------|-------------|
| `findings` | `list[dict]` | List of `NormalizedFinding` dicts conforming to `finding.schema.json` |

This function:
1. Validates the SARIF against the profile in `sarif-profile.md`.
2. Extracts each result and maps its fields to `NormalizedFinding`.
3. Computes the `id` fingerprint (`sha256` of `tool|rule_id|file|line`).
4. Applies severity normalization per `severity-map.md`.
5. Raises `ValueError` on schema violations (gate catches this and exits 2).

**P4's normalizer reuses this function.** Do not change its signature or
semantics without following the amendment process. Adding optional keyword
arguments with defaults is acceptable without an amendment.

---

## 10. Stub vs. Real Implementation

### Phase 1 Stubs

During Phase 1, all stage `run.sh` scripts are stubs. A stub:
- Copies the reference sample SARIF from `contracts/samples/<stage>.sarif`
  to `<output_dir>/<stage>.sarif`.
- Exits 0.
- Does not invoke any external tool.

Stubs allow the full pipeline to run end-to-end for integration testing
without requiring any scanners to be installed.

### Real Implementations (Phase 2 and Phase 3)

P2 replaces stubs for `secrets`, `sast`, and `sca` in Phase 2.
P3 replaces stubs for `iac`, `container`, `sbom`, and `dast` in Phase 3.

Real implementations invoke the actual scanner and convert its output to
SARIF. They must comply with all requirements in this document.

---

## 11. Stage Summary Table

| Stage | Owner | Tool | needs_image | Phase |
|-------|-------|------|-------------|-------|
| `secrets` | P2 | Gitleaks | No | 2 |
| `sast` | P2 | Semgrep | No | 2 |
| `sca` | P2 | Trivy (filesystem) | No | 2 |
| `iac` | P3 | Checkov | No | 3 |
| `container` | P3 | Trivy (image) + Hadolint | Yes | 3 |
| `sbom` | P3 | Syft | Optional | 3 |
| `dast` | P3 | OWASP ZAP | Yes | 3 |

---

*Last updated: 2026-11-14 — Frozen at Phase 1 sign-off.*
