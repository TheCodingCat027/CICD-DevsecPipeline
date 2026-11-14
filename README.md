# DevSecOps Pipeline — Automated Security Integration for CI/CD

> **Phase 1 — Foundation & Contracts** | University Project

This repository implements a CI/CD pipeline extension that automatically runs security scans at every build stage and applies a configurable policy that **blocks non-compliant deployments** before production ("shift-left" / DevSecOps).

## Quick Start

```bash
# 1. Enter the project directory
cd devsecops-pipeline

# 2. Set up virtual environment and install dependencies
make setup

# 3. Run the full local pipeline against the vulnerable demo app
make pipeline-local
# → prints WOULD DEPLOY on success

# 4. Test the blocked-deploy path
make pipeline-local-fail
# → prints DEPLOY BLOCKED (exit 1)

# 5. Run all tests
make test
```

## What Gets Scanned

| Stage | Tool (Phase 1: stub) | Finds | Owner |
|-------|----------------------|-------|-------|
| `secrets` | Gitleaks | Hardcoded credentials | P2 |
| `sast` | Semgrep | Code vulnerabilities | P2 |
| `sca` | Trivy (fs) | Vulnerable dependencies | P2 |
| `iac` | Hadolint + Checkov | Dockerfile / IaC issues | P3 |
| `container` | Trivy (image) | Container CVEs | P3 |
| `sbom` | Syft | Software Bill of Materials | P3 |
| `dast` | OWASP ZAP | Runtime vulnerabilities | P3 (disabled in Phase 1) |

## Repository Layout

```
devsecops-pipeline/
├── contracts/          # FROZEN schemas and interface specs (all four approve)
├── stages/             # One folder per scanner stage
├── gate/               # Policy gate stub (P4)
├── demo-app/           # Vulnerable & fixed Flask app for testing
├── .github/workflows/  # pipeline.yml (P1 only)
├── scripts/            # Local pipeline runner
├── eval/               # Evaluation data per phase
└── docs/               # Architecture, contributing, assumptions
```

## Ownership

| Folder(s) | Owner | Phase |
|-----------|-------|-------|
| `contracts/`, `security-policy.yaml`, `gate/`, `eval/p4-policy/` | P4 (contracts: all four) | 1→4 |
| `stages/secrets/`, `stages/sast/`, `stages/sca/`, `eval/p2-code/` | P2 | 2 |
| `stages/iac/`, `stages/container/`, `stages/sbom/`, `stages/dast/`, `eval/p3-container/`, `demo-app/fixed/Dockerfile` | P3 | 3 |
| `demo-app/`, `.github/`, `scripts/`, `Makefile`, `eval/p1-performance/` | P1 | 1 |

## Documentation

| Doc | Description |
|-----|-------------|
| [docs/p1-architecture.md](docs/p1-architecture.md) | Pipeline architecture and design |
| [docs/p1-assumptions.md](docs/p1-assumptions.md) | Decisions made in Phase 1 |
| [docs/p1-implementation-report.md](docs/p1-implementation-report.md) | Full implementation report (H1–H10) |
| [docs/contributing.md](docs/contributing.md) | Branch naming, review rotation, how to replace a stub |
| [docs/branch-protection.md](docs/branch-protection.md) | Branch protection settings for `main` |
| [docs/team-signoff.md](docs/team-signoff.md) | Sign-off checklist for contracts v1.0.0 |
| [contracts/stage-interface.md](contracts/stage-interface.md) | Stage invocation contract |
| [contracts/gate-interface.md](contracts/gate-interface.md) | Gate invocation contract |
| [demo-app/seeded-vulnerabilities.md](demo-app/seeded-vulnerabilities.md) | Ground truth for Phase 5 evaluation |

## ⚠️ Security Warning

The `demo-app/vulnerable/` directory contains **intentional security vulnerabilities** for
testing purposes. It must **never** be deployed to any real environment.
See [demo-app/README.md](demo-app/README.md) for details.

