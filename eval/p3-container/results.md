# Phase 3 Evaluation Results

**Generated:** 2026-11-17T19:21:42.696110+00:00

## Detection Rate: 100% (3/3 seeded vulnerabilities found)

## Seeded Vulnerability Detection

| ID | Description | Detected (Vulnerable) | Fixed (Hardened) | Correct |
|----|-------------|----------------------|------------------|---------|
| V4 | Runs as root (no USER) | ✅ | ✅ | ✅ |
| V5 | Unpinned base image | ✅ | ✅ | ✅ |
| V8 | No HEALTHCHECK | ✅ | ✅ | ✅ |

## IAC Stage Results

| Metric | Vulnerable | Fixed |
|--------|-----------|-------|
| Total Findings | 2 | 0 |
| Critical | 0 | 0 |
| High | 0 | 0 |
| Medium | 2 | 0 |
| Low | 0 | 0 |

## Container Stage Results

| Metric | Vulnerable | Fixed |
|--------|-----------|-------|
| Total Findings | 22 | 7 |
| Critical | 3 | 0 |
| High | 6 | 0 |
| Medium | 11 | 5 |
| Low | 2 | 2 |

## SBOM Stage Results

- SARIF findings: 0 (inventory tool — zero is correct)
- CycloneDX components: 7

## Notes

> [!NOTE] V5 (unpinned base `python:3.11-slim`) is not detected by DSP-IMG-002 because
> the image has a named tag (not `:latest`). DL3007 (Hadolint) also does not fire for named
> tags. Checkov CKV_DOCKER_7 may detect this depending on version.
> In CI where Docker image scanning runs in image mode, Trivy would surface OS-level CVEs
> from the actual unpinned base image.

> [!NOTE] Container stage ran in **filesystem fallback mode** (no Docker available locally).
> CVEs shown are from application dependencies (`requirements.txt`), not OS-layer CVEs.
> In CI with `IMAGE_REF` set, OS-layer vulnerabilities would also be reported.