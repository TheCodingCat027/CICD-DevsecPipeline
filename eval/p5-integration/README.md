# Phase 5 Integration

**Owner:** All team members (P1–P4)

This directory contains the Phase 5 end-to-end integration test.

## Running the Integration Test

```bash
# From repo root (Windows):
.venv\Scripts\python.exe eval\p5-integration\run_integration.py

# From repo root (Linux/macOS):
.venv/bin/python eval/p5-integration/run_integration.py
```

## Test Scenarios

| # | Description | Expected exit |
|---|-------------|--------------|
| T1 | Vulnerable app, enforce mode | 1 (BLOCKED) |
| T2 | Fixed app, enforce mode | 0 (ALLOWED) |
| T3 | Vulnerable app, audit mode | 0 (not blocked) |
| T4 | Vulnerable + secrets waiver | 1 (blocked; other violations remain) |

## Results

See [results.md](results.md) for the full integration test report.

## Full Local Pipeline

To run all stages end-to-end (requires Linux or Git Bash with tool binaries in PATH):

```bash
# Vulnerable app — expects gate to BLOCK
bash scripts/run-local-pipeline.sh demo-app/vulnerable

# Fixed app — expects gate to ALLOW
bash scripts/run-local-pipeline.sh demo-app/fixed
```

Required environment variables for pre-cached tools:
```bash
export GITLEAKS_PATH=~/.cache/devsecops/gitleaks-*/gitleaks
export HADOLINT_PATH=~/.cache/devsecops/hadolint-*/hadolint
export TRIVY_PATH=~/.cache/devsecops/trivy-bin/trivy
export SYFT_PATH=~/.cache/devsecops/syft-*/syft
```
