# Phase 3 Assumptions

**Author:** P3 | **Date:** 2026-11-18

## A1: Combined IAC Driver Name

The IAC stage combines Hadolint and Checkov into one SARIF run. Per `contracts/sarif-profile.md`,
one run has one `tool.driver`. We use `name: "hadolint+checkov"` with
`version: "hadolint X.Y.Z; checkov A.B.C"`. See `docs/p3-contract-feedback.md` for the amendment proposal.

## A2: Hadolint and Checkov Exit Codes

- **Hadolint** exits 0 when no issues, 1 when issues found, >1 on error. We treat exit 1 as "findings found" (not an error).
- **Checkov** exits 0 when all pass, 1 when checks fail. We treat exit 1 as "findings found" (not an error).
- Both follow the stage contract: scanners report, gate decides.

## A3: Container Stage Fallback

If `IMAGE_REF` is not set and Docker is unavailable, the container stage falls back to
a filesystem Trivy scan for CVEs. Posture checks (DSP-IMG-001, DSP-IMG-002) always run
from Dockerfile inspection and do not require Docker. This was chosen to allow the stage
to produce meaningful output even without a container runtime.

## A4: Posture Check IDs

Custom posture checks DSP-IMG-001 and DSP-IMG-002 are defined by P3 (not from any tool).
These are assigned IDs using the `DSP-IMG-` prefix to distinguish them from tool-generated rules.
Both use `category: "container"` per `contracts/validate.py` `STAGE_CATEGORIES["container"]`.

## A5: SBOM Stage: Directory Scan Default

When `IMAGE_REF` is not set, Syft scans the target directory for packages.
This produces a SBOM from source manifests (`requirements.txt` etc.) rather than
the actual container image. For production use, `IMAGE_REF` should be set by CI.

## A6: DAST Stage: Disabled in stages.json

The DAST stage is implemented but left `enabled: false` in `stages/stages.json`
(which we do not edit, per ownership rules). The implementation is complete and
tested manually. A request to enable it is recorded in `docs/p3-requests-to-p1.md`.

## A7: Checkov Version

Checkov 3.2.405 was selected as it is a recent stable release compatible with Python 3.11.
Checkov's pip install is cached in a venv at `~/.cache/devsecops/checkov-<version>/venv/`.

## A8: Syft Version

Syft 1.18.1 was selected to match the version referenced in `contracts/samples/sbom.sarif`.

## A9: ZAP Image Version

ZAP `ghcr.io/zaproxy/zaproxy:2.15.0` is pinned. This is the current stable ZAP release
at time of implementation.

## A10: Dockerfile Line References in Container Stage

Since Trivy image mode does not report specific source file/line, all CVE findings from
image scanning reference the Dockerfile at line 1 (file-level). Posture checks reference
the FROM instruction line. This is a known limitation documented in `docs/p3-contract-feedback.md`.

## A11: Fixed Dockerfile Uses Multi-Stage Build

The hardened `demo-app/fixed/Dockerfile` uses a multi-stage build (builder + runtime stages)
to minimize the attack surface. This exceeds the minimum requirements but is a security
best practice and helps demonstrate the before/after improvement.

## A12: Checkov Run Mode

Checkov is run with `--framework dockerfile` to scope it to Dockerfile checks only.
Running `--directory` scan finds Dockerfile(s) automatically. The `--output json`
flag is used for machine-readable output. `--quiet --compact` suppress progress output.
