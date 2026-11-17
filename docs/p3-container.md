# Phase 3 Academic Report: Container & Infrastructure Security Scanning

**Authors:** P3 Team  
**Phase:** 3 — Container & Infrastructure Stages  
**Date:** 2026-11-18

---

## Abstract

This report describes the implementation of Phase 3 of an automated DevSecOps CI/CD pipeline
for a university project. Phase 3 adds Dockerfile/IaC scanning (Hadolint + Checkov), container
image vulnerability scanning (Trivy), and SBOM generation (Syft), along with posture checks
that detect insecure base images and root-user containers. All three seeded vulnerabilities
in the demo application's Dockerfile were successfully detected, achieving a **100% detection
rate** for Phase 3's target findings.

---

## 1. Introduction

### 1.1 Background

Modern software supply chains introduce security risks at multiple layers: the application code
(addressed in Phase 2), and the infrastructure around it — Dockerfiles, base images, and the
software composition of the container image itself. "Shift-left" security practices require these
risks to be caught during development, not in production.

### 1.2 Phase 3 Goals

1. Implement real Dockerfile/IaC scanning replacing the Phase 1 stubs
2. Implement container image vulnerability scanning
3. Implement SBOM generation
4. Implement DAST baseline scanning (stretch goal — left disabled)
5. Harden the demo application's Dockerfile
6. Measure detection effectiveness across all Phase 3 targets

---

## 2. Tool Selection

### 2.1 Hadolint (v2.12.0)
Hadolint is a Dockerfile linter that parses Dockerfile ASTs and applies shell script linting
(via ShellCheck) for `RUN` instructions. It is widely used in CI pipelines and supports JSON
output for integration. Rule DL3002 (last USER should not be root) and DL3007 (use latest is
best avoided) are relevant to this project's seeded vulnerabilities.

### 2.2 Checkov (v3.2.405)
Checkov is a static analysis tool for IaC files supporting over 1000 built-in policies.
For Dockerfiles, it checks security misconfigurations such as missing HEALTHCHECK (CKV_DOCKER_2),
missing non-root USER (CKV_DOCKER_3), and exposed sensitive ports. Checkov complements Hadolint
by catching policy violations that Hadolint's lint rules do not cover.

### 2.3 Trivy (v0.76.2)
Trivy is a comprehensive vulnerability scanner that supports OS packages, language-specific
dependencies, and container images. The container stage uses Trivy in image mode (falling back
to filesystem mode when Docker is unavailable) to surface CVEs in both OS-layer and application
dependencies.

### 2.4 Syft (v1.18.1)
Syft is an SBOM generation tool from Anchore that produces CycloneDX and SPDX artifacts.
Per the contract (severity-map.md §3.7), Syft is an inventory tool and emits no findings;
its SARIF output has an empty `results` array.

### 2.5 OWASP ZAP (v2.15.0, stretch)
ZAP is the leading open-source DAST tool. The DAST stage implementation is complete but left
disabled in `stages/stages.json` pending P1 approval (see `docs/p3-requests-to-p1.md`).

---

## 3. Implementation Architecture

### 3.1 IAC Stage

The IAC stage combines Hadolint and Checkov into a single SARIF file. This introduces a design
tension (noted in `docs/p3-contract-feedback.md`): the SARIF profile requires one `tool.driver`
per run, but two tools are used. We resolved this by using `name: "hadolint+checkov"` with a
compound version string. P4's normalizer can distinguish the tools by rule ID prefix
(`DL*/SC*` → Hadolint, `CKV_*` → Checkov).

Hadolint is downloaded as a static binary; Checkov is invoked via Python module to avoid
`.cmd` shim issues on Windows.

### 3.2 Container Stage

The container stage runs in two modes:
- **Image mode** (preferred): `trivy image <IMAGE_REF>` scans the full container layer stack
- **Filesystem fallback**: `trivy filesystem <dir>` scans application manifests when Docker
  is unavailable

Two custom posture checks run independently of Trivy via Dockerfile inspection:
- **DSP-IMG-001**: No non-root USER instruction (severity: High)
- **DSP-IMG-002**: Base image uses `:latest` or insufficient version pinning (severity: Medium)

### 3.3 SBOM Stage

Syft scans either an image or directory and produces a CycloneDX 1.6 JSON SBOM alongside a
zero-result SARIF. A human-readable summary JSON is also written for P4 integration.

---

## 4. Hardened Dockerfile

The fixed Dockerfile (`demo-app/fixed/Dockerfile`) addresses all three seeded vulnerabilities:

| Vulnerability | Fix Applied |
|--------------|-------------|
| V4: Root user (DL3002/CKV_DOCKER_3) | `RUN useradd --uid 1000 appuser && USER appuser` |
| V5: Unpinned base image (DL3007/DSP-IMG-002) | `FROM python:3.11.11-slim-bookworm` (patch-pinned) |
| V8: No HEALTHCHECK (CKV_DOCKER_2) | `HEALTHCHECK --interval=30s ...` via urllib |

Additional hardening:
- Multi-stage build (builder + runtime) to minimize attack surface
- `--no-cache-dir` for pip, `PYTHONDONTWRITEBYTECODE`, `PYTHONUNBUFFERED`
- Exec-form CMD for proper signal handling
- `--chown=appuser:appuser` for copied files

---

## 5. Evaluation Results

| Metric | Value |
|--------|-------|
| Seeded vulnerability detection rate | **100%** (3/3) |
| IAC findings (vulnerable) | 2 |
| IAC findings (fixed) | 0 |
| Container findings (vulnerable) | 22 |
| Container findings (fixed) | 7 |
| SBOM components detected | 7 |

### 5.1 Note on V5 Detection

V5 (unpinned base image `python:3.11-slim`) is detected by **DSP-IMG-002** (custom posture check)
because the tag `3.11-slim` lacks a patch version. Hadolint DL3007 fires only for `:latest` and
Checkov CKV_DOCKER_7 behavior varies by version. The DSP-IMG-002 heuristic (fewer than 3 version
segments → unpinned) catches this common real-world pattern.

---

## 6. Limitations

1. **No image-mode scanning locally**: Docker Desktop was available but `docker build` failed
   in the CI sandbox, so the container stage fell back to filesystem scanning. OS-layer CVEs
   (from the base image) are only visible in full image-mode scanning.
2. **DAST disabled**: The DAST stage requires a running application which requires network
   access not available in the standard sandbox.
3. **Checkov Windows invocation**: Checkov's `.cmd` entry point doesn't work correctly on
   Windows; we use a Python module invocation via `run_checkov.py` helper.

---

## 7. Future Work

- Enable image-mode scanning in CI by ensuring `IMAGE_REF` is passed to the container stage
- Enable DAST stage after P1 approval
- Add digest pinning check to DSP-IMG-002 for comprehensive supply chain security
- Integrate SBOM with vulnerability databases via `grype` for runtime SCA
