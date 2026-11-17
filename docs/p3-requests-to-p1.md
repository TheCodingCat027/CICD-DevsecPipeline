# Phase 3 Requests to P1

**Author:** P3 | **Date:** 2026-11-18

## R-001: Enable DAST Stage in stages.json

**What:** Set `"enabled": true` for the `dast` stage in `stages/stages.json`.

**Why:** The DAST stage is fully implemented and tested (see `stages/dast/`).
It is currently disabled as a stretch goal per Phase 1 design. Enabling it in
Phase 5 integration would validate DAST coverage.

**Proposed diff:**
```diff
-  { "name": "dast", "enabled": false, "run": "stages/dast/run.sh" }
+  { "name": "dast", "enabled": true,  "run": "stages/dast/run.sh" }
```

---

## R-002: Add .dockerignore to demo-app

**What:** Add `demo-app/vulnerable/.dockerignore` and `demo-app/fixed/.dockerignore`
to exclude `.git`, `*.pyc`, `__pycache__`, `.venv` from the build context.

**Why:** Without `.dockerignore`, Docker builds include unnecessary files, causing
Hadolint and Checkov to report false issues and slowing builds.

**Proposed content:**
```
.git
__pycache__
*.pyc
*.pyo
.venv
venv
*.egg-info
```

---

## R-003: Cache Trivy DB in CI

**What:** Add a step in `.github/workflows/pipeline.yml` to cache the Trivy vulnerability
database between runs using `actions/cache`.

**Why:** Trivy downloads the full vulnerability DB (~40MB) on every run, adding ~2 minutes
to CI time. Caching it in `~/.cache/devsecops/trivy-db` would speed up all stages.

**Proposed step (before `run-stage` actions):**
```yaml
- name: Cache Trivy DB
  uses: actions/cache@v4
  with:
    path: ~/.cache/devsecops/trivy-db
    key: trivy-db-${{ runner.os }}-${{ hashFiles('**/*.txt') }}
    restore-keys: trivy-db-${{ runner.os }}-
```

---

## R-004: Add Checkov venv cache in CI

**What:** Cache the Checkov Python venv in CI to avoid reinstalling on every run.

**Why:** Checkov install takes ~90 seconds in CI due to its dependency tree.
Caching `~/.cache/devsecops/checkov-<version>/venv` by version hash would eliminate this.

**Proposed step:**
```yaml
- name: Cache Checkov venv
  uses: actions/cache@v4
  with:
    path: ~/.cache/devsecops/checkov-3.2.405
    key: checkov-3.2.405-${{ runner.os }}
```
