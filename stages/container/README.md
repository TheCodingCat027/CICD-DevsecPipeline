# Container Stage — Trivy Image Scan + Posture Checks

**Owner:** P3 | **Phase:** 3

Scans a container image for OS/library CVEs using Trivy, and applies two
custom posture checks (DSP-IMG-001, DSP-IMG-002) derived from Dockerfile inspection.

## Interface

```bash
stages/container/run.sh <target_path> <output_dir>
```

Optionally set `IMAGE_REF` environment variable to scan a pre-built image.

Outputs `<output_dir>/container.sarif`.

## Posture Checks

| Rule ID | Severity | Description |
|---------|----------|-------------|
| DSP-IMG-001 | High | No non-root USER instruction found (runs as root) |
| DSP-IMG-002 | Medium | Base image uses `latest` tag or no version pin |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Scanner crash / install failure |
| 2 | Usage error |

## Fallback Behavior

If Docker is not available or `IMAGE_REF` is not set, the stage falls back to
a filesystem scan (`trivy filesystem`) for library CVEs. Posture checks always
run from Dockerfile inspection.
