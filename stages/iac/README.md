# IAC Stage — Hadolint + Checkov

**Owner:** P3 | **Phase:** 3

Scans Dockerfile(s) for infrastructure-as-code misconfigurations using two complementary tools:

- **Hadolint** (v2.12.0): Dockerfile linter (DL3002, DL3007, etc.)
- **Checkov** (v3.2.405): IaC policy scanner (CKV_DOCKER_*)

## Interface

```bash
stages/iac/run.sh <target_path> <output_dir>
```

Outputs `<output_dir>/iac.sarif` — a SARIF 2.1.0 file passing `contracts/validate.py --stage iac`.

## Seeded Vulnerabilities Detected

| ID | Rule | Description |
|----|------|-------------|
| V4 | DL3002 / CKV_DOCKER_8 | Runs as root (no USER instruction) |
| V5 | DL3007 | Unpinned base image tag |
| V8 | CKV_DOCKER_28 | No HEALTHCHECK instruction |

## Tool Versions

| Tool | Version | Cache Location |
|------|---------|----------------|
| Hadolint | 2.12.0 | `~/.cache/devsecops/hadolint-2.12.0/hadolint` |
| Checkov | 3.2.405 | `~/.cache/devsecops/checkov-3.2.405/venv/bin/checkov` |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success (findings do NOT cause non-zero exit) |
| 1 | Scanner crash / install failure |
| 2 | Usage error (wrong arguments, missing target) |

## Design Notes

- Both tools run on every Dockerfile found in `<target_path>` (up to 3 dirs deep).
- Results are merged into a single SARIF run with `tool.driver.name = "hadolint+checkov"`.
- See `docs/p3-contract-feedback.md` for the rationale on the combined driver name.
- Fail-closed: on any scanner error, the partial SARIF is deleted before exit 1.
