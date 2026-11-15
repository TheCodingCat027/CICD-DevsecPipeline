# Phase 2 — Requests to P1 (Pipeline Maintainer)

> Owner: P2 | Phase: 2

The following changes are requested from P1, who owns `.github/`, `Makefile`, `scripts/`,
and `stages/stages.json`. P2 must NOT make these changes directly.

---

## Request 1 — CI Caching for Gitleaks, Semgrep, and Trivy

**What:** Add `actions/cache` steps for the binary and venv cache directories used by the
three P2 stages, so GitHub Actions does not re-download 60–200 MB on every run.

**Why:** Each stage's `install.sh` downloads the tool binary (or installs a venv) on every
cold CI runner. Without caching, `contracts-and-tests` and the `stage` matrix jobs slow
down significantly.

**Cache paths to add:**

| Stage | Key env var | Default path |
|-------|------------|--------------|
| secrets | XDG_CACHE_HOME | `~/.cache/devsecops/gitleaks-8.21.2/` |
| sast | XDG_CACHE_HOME | `~/.cache/devsecops/semgrep-1.100.0/` |
| sca binary | XDG_CACHE_HOME | `~/.cache/devsecops/trivy-0.58.1/` |
| sca db | XDG_CACHE_HOME | `~/.cache/devsecops/trivy-db/` |

**Proposed diff** (in `.github/actions/run-stage/action.yml`):
```yaml
    - name: Cache security tool binaries
      uses: actions/cache@v4
      with:
        path: ~/.cache/devsecops
        key: ${{ runner.os }}-devsecops-tools-${{ hashFiles('stages/secrets/install.sh', 'stages/sast/install.sh', 'stages/sca/install.sh') }}
        restore-keys: |
          ${{ runner.os }}-devsecops-tools-
```

---

## Request 2 — SCA V3 CVE Verification in Seeded Vulnerabilities

**What:** The CVE IDs for V3 in `demo-app/seeded-vulnerabilities.json` are marked
`cve_verified: false`. When Trivy is run against `demo-app/vulnerable/requirements.txt`
(Flask==1.0.2, Jinja2==2.10, PyYAML==5.1), the actual reported CVEs may differ.

**Why:** The seeded expected_rule_id (`CVE-2019-10906`) may not be the only or primary CVE
Trivy reports. The evaluation is blocked from producing accurate detection rates until this
is confirmed.

**Requested action:** After real Trivy runs are possible, update `seeded-vulnerabilities.json`
with verified CVE IDs (or add an amendment to `contracts/CHANGELOG.md` per the amendment
process, since demo-app is P1's territory).

---

## Request 3 — Stage Test Runner in CI

**What:** Add a step in the GitHub Actions `contracts-and-tests` job (or a new job) that
runs `bash scripts/run-stage-tests.sh`, so stage unit tests run in CI.

**Why:** Currently only pytest (Python tests) run in CI. The stage shell test scripts
(`stages/*/tests/run_test.sh`) are not executed in GitHub Actions, meaning scanner
integration is never CI-verified.

**Note:** This may require the stage tools to be cached first (see Request 1).

---

*Last updated: Phase 2 implementation — 2026-11-15*
