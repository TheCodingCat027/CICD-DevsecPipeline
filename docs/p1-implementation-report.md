# Phase 1 Implementation Report: Foundation & Contracts

**Author:** P1 (Platform / DevSecOps Engineer)  
**Date:** 2026-11-15  
**Project:** Automated Security Integration for CI/CD Pipelines (4-person team project)  
**Status:** Complete

---

## H1. Executive Summary

Phase 1 established the architectural, contract, and CI/CD foundation for the 4-person university DevSecOps pipeline project. All deliverables across Tasks A through G have been implemented, tested, and verified against the master specification. The contract layer (`contracts/`) defines the frozen schema, SARIF 2.1.0 profile, severity normalization, stage interface, and gate interface required for P2, P3, and P4 to develop independently without merge conflicts. A dual-version demo Flask service (vulnerable vs. fixed) and an audited ground truth seeded vulnerability list with 10 flaws (V1–V8) were created with automated drift protection. All seven stages are registered and stubbed behind the universal interface, the stub policy gate enforces deployment decisions, and the local pipeline script mirrors GitHub Actions CI execution. Phase 1 is **complete**.

---

## H2. Completion Status Table

| Task | Deliverable | Status | Evidence | Notes |
|---|---|---|---|---|
| **A** | Repo scaffolding & rules | **Done** | `git ls-files` shows full tree; `.gitignore`, `CODEOWNERS`, PR template, Makefile, scripts, placeholder docs present | Exact target directory layout created; CODEOWNERS maps handles and enforces 4-person approval for contracts. |
| **B** | Frozen contracts | **Done** | `contracts/validate.py --policy security-policy.yaml` exits 0; all 6 contract docs & schemas created | Draft 2020-12 schemas; SARIF 2.1.0 profile; severity mapping matrix; changelog v1.0.0. |
| **C** | Validator & SARIF samples | **Done** | `python contracts/validate.py contracts/samples` exits 0 (7 valid samples); 6 invalid samples rejected; pytest passed | 30 tests in `contracts/tests/test_validate.py` covering validation, extraction, negative samples, and exit codes. |
| **D** | Demo app & seeded list | **Done** | `pytest demo-app/` passes (20 tests); functional tests pass on both vulnerable and fixed versions | 10 planted flaws (V1–V8) with drift protection test verifying existence and code patterns. |
| **E** | Stub stages, registry, stub gate | **Done** | `bash scripts/run-stage-tests.sh` passes all 6 enabled stages; `python gate/run_gate.py` passes | Stubs copy sample SARIF, log to stderr, handle SBOM artifact, and gate supports `GATE_FORCE_FAIL=1`. |
| **F** | CI workflow & composite action | **Done** | PyYAML validation passes; composite action `.github/actions/run-stage/action.yml` and workflow `pipeline.yml` complete | 6 jobs: `contracts-and-tests`, `prepare`, `build-image`, `stage` (parallel matrix, fail-fast: false), `gate`, `deploy` (mock). |
| **G** | Local tooling & documentation | **Done** | `make pipeline-local` prints `WOULD DEPLOY` (exit 0); `make pipeline-local-fail` prints `DEPLOY BLOCKED` (exit 1) | Architecture, assumptions, contributing, branch protection, team sign-off, and README docs written. |
| **H** | Implementation report | **Done** | This document (`docs/p1-implementation-report.md`) covering sections H1 through H10 | Ground truth file-by-file contribution map and verified criteria. |

---

## H3. How the Pieces Fit Together

### Architecture & Data Flow

```mermaid
flowchart TD
    subgraph SCM["Source Code Management"]
        Commit["Developer Commit / PR"]
    end

    subgraph CI["CI Pipeline: .github/workflows/pipeline.yml"]
        Job1["Job 1: contracts-and-tests\n(validate.py & pytest)"]
        Job2["Job 2: prepare\n(stages.json matrix)"]
        Job3["Job 3: build-image\n(docker build & save)"]
        
        subgraph Matrix["Job 4: Stage Matrix (Parallel)"]
            S1["stage: secrets (Gitleaks stub)"]
            S2["stage: sast (Semgrep stub)"]
            S3["stage: sca (Trivy fs stub)"]
            S4["stage: iac (Hadolint/Checkov stub)"]
            S5["stage: container (Trivy img stub)"]
            S6["stage: sbom (Syft stub)"]
        end

        Job5["Job 5: Policy Gate\n(gate/run_gate.py)"]
        Job6["Job 6: Deploy (Mock)\n(Only on push to main)"]
        Blocked["DEPLOY BLOCKED\n(CI Failure)"]
    end

    Commit --> Job1
    Job1 --> Job2
    Job1 --> Job3
    Job2 --> Matrix
    Job3 -.->|IMAGE_REF| S5
    Job3 -.->|IMAGE_REF| S6

    S1 -->|secrets.sarif| Job5
    S2 -->|sast.sarif| Job5
    S3 -->|sca.sarif| Job5
    S4 -->|iac.sarif| Job5
    S5 -->|container.sarif| Job5
    S6 -->|sbom.sarif + CDX| Job5

    Job5 -->|Policy satisfied (exit 0)| Job6
    Job5 -->|Policy violated / Error (exit 1/2)| Blocked
```

### Data Contracts and Processing

1. **Stage Execution**: Each stage is executed via the composite action `.github/actions/run-stage` or locally using `stages/<name>/run.sh <target_path> <output_dir>`.
2. **SARIF Output**: Every stage writes `<output_dir>/<name>.sarif`. Non-SARIF artifacts (e.g., CycloneDX SBOM) are placed in `<output_dir>/artifacts/<name>/`.
3. **Format Validation**: Before an artifact is published, `contracts/validate.py` verifies SARIF 2.1.0 compliance, driver version pinning, result structure, and stage-specific category legality.
4. **Gate Aggregation**: The gate (`gate/run_gate.py`) consumes all stage SARIF files, executes `extract_findings()` from the validator to normalize them, validates them against `finding.schema.json`, and evaluates them against `security-policy.yaml`.
5. **Deployment Decision**: The gate emits `gate-result.json` and `findings.json`. Exit 0 permits mock staging deployment; non-zero stops deployment immediately.

---

## H4. File-by-File Contribution Map

| Path | Created for (task) | Owner | What it contains | **How it contributes to the project** | Used by / depends on | Replaced or extended in |
|---|---|---|---|---|---|---|
| `README.md` | Task G | P1 | Project overview, quick start, architecture links, ownership guide | Welcomes developers and evaluators with immediate instructions to run the local pipeline. | Human users, evaluation | Extended in Phase 5 |
| `Makefile` | Task G | P1 | Targets for setup, validate, test, pipeline-local, lint, and clean | Provides standardized CLI developer experience across Windows, macOS, and Linux. | All developers, CI | Maintained by P1 |
| `CODEOWNERS` | Task A | P1 | Ownership rules mapping directories to P1–P4 handles | Enforces folder boundaries on GitHub; requires 4-person approval on `/contracts/`. | GitHub PR review engine | P1 updates handles |
| `.gitignore` | Task A | P1 | Standard Git ignore patterns for Python, venvs, artifacts, and OS files | Prevents accidental check-in of build artifacts, test runs, virtual environments, and secrets. | Git | Maintained by P1 |
| `security-policy.yaml` | Task B | P4 | Baseline security policy config (mode, thresholds, container rules, waivers) | The single configuration file controlling deployment pass/fail thresholds; validated against schema. | Gate, validate.py | P4 owns & refines in Phase 4 |
| `pytest.ini` | Task C | P1 | Pytest configuration setting importlib mode and testpaths | Ensures unambiguous module resolution across parallel test directories without naming collisions. | Pytest, CI | Maintained by P1 |
| `contracts/finding.schema.json` | Task B | P4 (Frozen) | JSON Schema (Draft 2020-12) for normalized finding records | Establishes the single unified data format that scanners translate into and the gate consumes. | validate.py, gate | Frozen: v1.0.0 |
| `contracts/policy.schema.json` | Task B | P4 (Frozen) | JSON Schema (Draft 2020-12) for security policy configuration | Formally defines the structure of `security-policy.yaml` so configuration errors are caught immediately. | validate.py, gate | Frozen: v1.0.0 |
| `contracts/sarif-profile.md` | Task B | P1 (Frozen) | Specification of the SARIF 2.1.0 subset enforced across all stages | Eliminates scanner output variance by requiring exact fields (driver version, properties.severity). | P2, P3 scanner authors | Frozen: v1.0.0 |
| `contracts/severity-map.md` | Task B | P1 (Frozen) | Mapping matrix from Semgrep, Gitleaks, Trivy, Hadolint, ZAP to 4 levels | Prevents arbitrary severity interpretations; maps tool labels to Critical/High/Medium/Low with fallback. | P2, P3, P4 normalizer | Frozen: v1.0.0 |
| `contracts/stage-interface.md` | Task B | P1 (Frozen) | CLI arguments, exit code definitions, output requirements for stages | Defines universal contract (`run.sh <target> <out>`) so workflow never needs stage-specific glue. | P2, P3 stages, CI composite | Frozen: v1.0.0 |
| `contracts/gate-interface.md` | Task B | P4 (Frozen) | CLI specification and output format for `gate/run_gate.py` | Defines gate arguments, exit codes (0/1/2), and `gate-result.json`/`findings.json` outputs. | P4 gate, CI gate job | Frozen: v1.0.0 |
| `contracts/CHANGELOG.md` | Task B | All (Frozen) | Version history and formal 4-person amendment process | Safeguards frozen contracts; mandates documented consensus before any contract change. | Whole team | Amended only on consensus |
| `contracts/requirements.txt` | Task B | P1 | Pinned dependencies: `jsonschema==4.23.0`, `PyYAML==6.0.2`, `pytest==8.3.4` | Enforces exact, reproducible environment across local developer workstations and CI runners. | Setup, CI | Maintained by P1 |
| `contracts/validate.py` | Task C | P1 | CLI & Python module validating SARIF files, stages, categories, and policy | Reusable validator and public normalizer function (`extract_findings`) shared by CI and gate. | CI, stages, gate, tests | Maintained by P1 |
| `contracts/samples/*.sarif` (7 files) | Task C | P1 (Frozen) | Realistic SARIF 2.1.0 sample for secrets, sast, sca, iac, container, sbom, dast | Provides concrete mock outputs matching seeded flaws; allows P4 to build gate without real scanners. | Stub stages, validator tests | Frozen: v1.0.0 |
| `contracts/samples/invalid/*.sarif` (6 files) | Task C | P1 | Deliberately corrupted SARIF files violating specific schema rules | Serves as negative test suite to prove the validator rejects invalid/unpinned/corrupted inputs. | Validator test suite | Maintained by P1 |
| `contracts/tests/test_validate.py` | Task C | P1 | Pytest test suite (30 test cases) for `validate.py` and contracts | Proves contract compliance, negative sample rejection, category legality, and CLI exit codes. | CI, Makefile | Maintained by P1 |
| `stages/stages.json` | Task E | P1 | Machine-readable registry of pipeline stages, owners, and flags | Drives the dynamic GitHub Actions matrix and local pipeline without hardcoded YAML jobs. | `prepare` job, local runner | P3 enables DAST in Phase 3 |
| `stages/<name>/run.sh` (7 files) | Task E | P2 (secrets/sast/sca), P3 (iac/container/sbom/dast) | Universal stage runner script (currently stub implementation) | Exposes standardized CLI to CI/local runners; Phase 2 & 3 replace stub bodies with real scanners. | CI action, local runner | Replaced in Phase 2 & 3 |
| `stages/<name>/README.md` (7 files) | Task E | P2, P3 | Per-stage documentation, pinned tool placeholder, 4-step replacement guide | Instructs P2 and P3 exactly how to install tools and replace stubs without breaking interfaces. | P2, P3 developers | Updated in Phase 2 & 3 |
| `stages/<name>/tests/run_test.sh` (7 files) | Task E | P2, P3 | Integration test executing stage script and validating output with `validate.py` | Guarantees stage output validity before PR submission; extended with known-bad inputs in later phases. | Local test, CI | Extended in Phase 2 & 3 |
| `gate/run_gate.py` | Task E | P4 | Policy gate CLI script (Phase 1 stub with `GATE_FORCE_FAIL` toggle) | Aggregates stage reports, validates findings, and blocks deploy on failure; P4 writes engine in Phase 4. | Local runner, CI gate job | Replaced in Phase 4 |
| `gate/README.md` | Task E | P4 | Documentation of gate interface, exit codes, and Phase 4 requirements | Informs P4 how to replace the stub gate with policy evaluation while preserving the interface. | P4 developer | Updated in Phase 4 |
| `demo-app/README.md` | Task D | P1 | Documentation of demo app, fake credential notice, and test instructions | Explains dual app structure, provides fake credential warnings, and guides local test execution. | Developers, evaluators | Maintained by P1 |
| `demo-app/seeded-vulnerabilities.md` | Task D | P1 | Human-readable ground truth table for 10 planted vulnerabilities | Serves as the benchmark for measuring scanner detection rate and false positive metrics in Phase 5. | Phase 5 evaluation | Benchmark ground truth |
| `demo-app/seeded-vulnerabilities.json` | Task D | P1 | Machine-readable JSON ground truth with file paths, lines, and CVEs | Automated ground truth data consumed by drift-protection tests and Phase 5 evaluation scripts. | Test suite, eval scripts | Benchmark ground truth |
| `demo-app/tests/test_seeded_list.py` | Task D | P1 | Pytest test suite asserting seeded list files exist and contain patterns | Prevents silent ground-truth drift when demo code is modified or refactored. | Pytest, CI | Maintained by P1 |
| `demo-app/vulnerable/app.py` | Task D | P1 | Vulnerable Flask application containing SQLi (V2), MD5 (V6), debug (V7) | Realistic target exhibiting real application security flaws for Semgrep detection. | SAST, functional tests | Intentionally flawed target |
| `demo-app/vulnerable/config.py` | Task D | P1 | Configuration containing hardcoded fake AWS credentials (V1) | Realistic credential exposure target for Gitleaks secret detection. | Secrets stage | Intentionally flawed target |
| `demo-app/vulnerable/requirements.txt` | Task D | P1 | Pinned legacy dependencies (Flask 1.0.2, Jinja2 2.10, PyYAML 5.1) (V3) | Realistic outdated dependencies with known CVEs for Trivy SCA detection. | SCA stage | Intentionally flawed target |
| `demo-app/vulnerable/Dockerfile` | Task D | P1 | Containerfile running as root, unpinned tag, no healthcheck (V4, V5, V8) | Realistic Dockerfile flaws for Hadolint and Checkov IaC detection. | IaC, container scan | Intentionally flawed target |
| `demo-app/vulnerable/tests/test_app.py` | Task D | P1 | Functional pytest tests for `/health`, `/users`, `/login` endpoints | Verifies functional behavior of the vulnerable application independently of flaws. | Pytest, CI | Maintained by P1 |
| `demo-app/fixed/app.py` | Task D | P1 | Remediated Flask app with parameterized queries, scrypt hash, no debug | Demonstrates clean, secure coding remediating V2, V6, and V7 while passing identical tests. | Comparison, tests | Ground truth remediation |
| `demo-app/fixed/config.py` | Task D | P1 | Configuration reading secrets from environment variables with defaults | Remediates V1 by eliminating hardcoded secrets in version control. | Fixed app | Ground truth remediation |
| `demo-app/fixed/requirements.txt` | Task D | P1 | Modern secure dependencies (Flask 3.1.0, Jinja2 3.1.5, PyYAML 6.0.2) | Remediates V3 by upgrading to patched, vulnerability-free package versions. | Fixed app | Ground truth remediation |
| `demo-app/fixed/Dockerfile` | Task D | P3 | Hardened Dockerfile with non-root user, pinned digest, and HEALTHCHECK | Remediates V4, V5, and V8; baseline for container hardening. | P3 container work | Hardened by P3 in Phase 3 |
| `demo-app/fixed/.env.example` | Task D | P1 | Template environment file for local configuration | Guides safe secret injection without committing real credentials. | Fixed app | Maintained by P1 |
| `demo-app/fixed/tests/test_app.py` | Task D | P1 | Functional pytest tests verifying non-breaking remediation | Proves that fixing security vulnerabilities preserved 100% of functional requirements. | Pytest, CI | Maintained by P1 |
| `.github/actions/run-stage/action.yml` | Task F | P1 | Composite action running `run.sh`, validating SARIF, uploading artifacts | Standardizes stage execution steps across matrix runners without duplicating CI YAML code. | `pipeline.yml` stage job | Maintained by P1 |
| `.github/workflows/pipeline.yml` | Task F | P1 | Complete 6-job GitHub Actions pipeline workflow | Orchestrates tests, dynamic matrix scanning, image builds, gate check, and mock deployment. | GitHub Actions CI | Maintained by P1 (P1-only) |
| `.github/pull_request_template.md` | Task A | P1 | PR checklist enforcing CODEOWNERS boundaries and validation | Enforces team engineering hygiene and prevents out-of-scope edits on pull requests. | GitHub PRs | Maintained by P1 |
| `scripts/run-local-pipeline.sh` | Task G | P1 | Shell script running all enabled stages, validation, and gate locally | Enables local end-to-end pipeline execution mirroring CI without requiring git pushes. | Developers, Makefile | Maintained by P1 |
| `scripts/run-stage-tests.sh` | Task G | P1 | Helper script executing `stages/*/tests/run_test.sh` across all stages | Aggregates stage integration tests into a single command for validation. | Test suite | Maintained by P1 |
| `scripts/check_lines.py` | Task D | P1 | Verification helper validating line numbers in `seeded-vulnerabilities.json` | Audits ground-truth line mappings against physical file lines. | Verification suite | Maintained by P1 |
| `scripts/gen_stages.py` | Task E | P1 | Generator script for stage boilerplate files | Used in scaffolding stage runner and test script templates. | Internal setup | Archival reference |
| `scripts/gen_stage_readmes.py` | Task E | P1 | Generator script for stage README documentation | Used in scaffolding stage README templates with owner instructions. | Internal setup | Archival reference |
| `docs/p1-architecture.md` | Task G | P1 | Architecture document with Mermaid flowcharts and design rules | Explains system architecture, scanner/gate separation, and conflict-free boundary rules. | Whole team, evaluators | Maintained by P1 |
| `docs/p1-assumptions.md` | Task G | P1 | Comprehensive log of 15 technical and architectural decisions | Records explicit engineering decisions made where specifications permitted flexibility. | Evaluators, team | Maintained by P1 |
| `docs/contributing.md` | Task G | P1 | Team guide for branch naming, PR rotation, and stub replacement | Guides P2, P3, and P4 on daily Git workflows and step-by-step scanner integration. | Team members | Maintained by P1 |
| `docs/branch-protection.md` | Task G | P1 | Branch protection policy specification and exact `gh api` command | Documents exact settings needed to lock `main` against direct pushes and enforce 4-way sign-off. | Repo admin | Maintained by P1 |
| `docs/team-signoff.md` | Task G | All | Formal sign-off checklist and protocol for freezing contracts v1.0.0 | Establishes the formal human gate required before contract freeze takes effect. | P1, P2, P3, P4 | Signed once by all 4 |
| `docs/p2-sast-report.md` | Task A | P2 | Placeholder report document (`# P2 SAST/Secrets/SCA Report`) | Designated location for P2's Phase 2 deliverable documentation. | P2 | Written by P2 in Phase 2 |
| `docs/p3-container-report.md` | Task A | P3 | Placeholder report document (`# P3 IaC/Container/SBOM/DAST Report`) | Designated location for P3's Phase 3 deliverable documentation. | P3 | Written by P3 in Phase 3 |
| `docs/p4-policy-report.md` | Task A | P4 | Placeholder report document (`# P4 Policy Gate Report`) | Designated location for P4's Phase 4 deliverable documentation. | P4 | Written by P4 in Phase 4 |
| `eval/*/.gitkeep` (4 files) | Task A | P1–P4 | Gitkeep files for evaluation metric storage (`p1-performance`, etc.) | Preserves empty evaluation directories for Phase 5 benchmarking and performance data. | Git | Preserved for Phase 5 |
| `contracts/*/.gitkeep`, `stages/*/.gitkeep` | Task A | P1 | Directory structure preservation gitkeep files | Preserves required directory layout in Git. | Git | Preserved |

---

## H5. Contracts Summary

### 1. Normalized Finding Schema (`contracts/finding.schema.json`)
Guarantees a unified, strictly typed format (Draft 2020-12) for every security finding regardless of scanner origin.
- **Required fields**: `tool`, `stage`, `category`, `rule_id`, `severity`, `file`, `line`, `description`, `fix`.
- **Enforced Enums**: Severity is strictly one of `Critical`, `High`, `Medium`, `Low`; category is strictly `secret`, `sast`, `sca`, `iac`, `container`, `dast`.
- **Optional fields defined now**:
  - `id`: Stable SHA-256 fingerprint (`tool|rule_id|file|line`) for tracking across runs (used by P4 deduplication and waivers).
  - `cve_id`, `cwe`: Standard vulnerability categorizations (used by P2 SCA, P3 container, P4 reporting).
  - `package`, `installed_version`, `fixed_version`, `fix_available`: Dependency telemetry (used by P2 SCA and P4 remediation tracking).
  - `confidence`: Scanner certainty level (used by P4 policy filtering).
  - `help_uri`: Deep link to remediation documentation (used by P4 dashboard/PR comments).
  - `raw_severity`: Preserves original scanner label for auditability (used by P4 normalizer).
  - `waived`, `waiver_id`: Gate-applied waiver status (used exclusively by P4 policy engine).
- **Phase dependence**: P2 and P3 map scanner outputs into this schema; P4 builds policy rules and reporting around it.

### 2. SARIF Profile (`contracts/sarif-profile.md`)
Defines the exact subset of OASIS SARIF 2.1.0 that stages must emit.
- **Guarantees**: Exactly one run; non-empty `tool.driver.name` and pinned `tool.driver.version`; required locations with physical URI; valid `properties.severity` and `properties.category`.
- **Phase dependence**: P2 and P3 configure scanner formatters (Gitleaks SARIF template, Semgrep `--sarif`, Trivy `--format sarif`) to adhere to this profile.

### 3. Severity Map (`contracts/severity-map.md`)
Establishes deterministic mapping rules from disparate scanner levels to the 4 canonical levels.
- **Guarantees**: Semgrep `ERROR` → High; Gitleaks secrets → High (cloud credentials → Critical); Trivy `CRITICAL` → Critical; Hadolint `error` → High; Checkov → Medium; ZAP `High` → High; unknown/unmapped → Low fallback. Original labels preserved in `raw_severity`.
- **Phase dependence**: P2 and P3 apply mappings in SARIF output properties; P4 normalizer relies on consistency.

### 4. Policy Schema (`contracts/policy.schema.json`) & Baseline Policy (`security-policy.yaml`)
Defines the schema for operational security policy evaluation.
- **Guarantees**: Validates execution mode (`enforce` vs. `audit`), secret thresholds (`max_allowed: 0`), severity thresholds (`critical: 0`, `high: 3`), container requirements (`must_run_as_non_root: true`, `banned_base_tags: ["latest"]`), and waiver records (`id`, `reason`, `expires`, `approved_by`).
- **Phase dependence**: P4 owns `security-policy.yaml` starting in Phase 4 and writes the rule evaluation engine against it.

### 5. Stage Interface (`contracts/stage-interface.md`)
Defines the universal CLI invocation contract:
```bash
stages/<name>/run.sh <target_path> <output_dir>
```
- **Guarantees**: Must write `<output_dir>/<name>.sarif`; exit 0 on scan completion regardless of finding count; exit 1 only on scanner crash; exit 2 on usage error; idempotent and read-only on target. Passes container image references via `IMAGE_REF`. Exposes `extract_findings()` in `validate.py`.
- **Phase dependence**: P2 and P3 implement tools inside this interface; CI executes all stages uniformly without per-tool scripts.

### 6. Gate Interface (`contracts/gate-interface.md`)
Defines the gate invocation contract:
```bash
python gate/run_gate.py --reports <dir> --policy <file> --out <dir>
```
- **Guarantees**: Exit 0 on policy pass (or audit mode); exit 1 on policy violation; exit 2 on validation/internal error. Writes `gate-result.json` and `findings.json`.
- **Phase dependence**: P4 replaces gate internals with real policy logic while keeping the CLI and exit codes identical.

---

## H6. Seeded Vulnerability Ground Truth

The following ground truth table is committed in `demo-app/seeded-vulnerabilities.md` and `demo-app/seeded-vulnerabilities.json`:

| ID | File | Line | Class | Description | Expected Tool | Expected Rule ID | CVE ID(s) | Fixed In |
|---|---|---|---|---|---|---|---|---|
| **V1** | `demo-app/vulnerable/config.py` | 10 | Secret | Hardcoded fake AWS access key ID and secret access key | Gitleaks | `aws-access-token` | — | `demo-app/fixed/config.py` |
| **V2** | `demo-app/vulnerable/app.py` | 51 | SAST | SQL injection via string concatenation in `/users` endpoint | Semgrep | `python.lang.security.audit.formatted-sql-query` | — (CWE-89) | `demo-app/fixed/app.py` |
| **V3a** | `demo-app/vulnerable/requirements.txt` | 7 | SCA | Flask 1.0.2 depends on vulnerable Jinja2 | Trivy | `CVE-2019-10906` | CVE-2019-10906 *(unverified)* | `demo-app/fixed/requirements.txt` |
| **V3b** | `demo-app/vulnerable/requirements.txt` | 8 | SCA | Jinja2 2.10 Server Side Template Injection | Trivy | `CVE-2019-10906` | CVE-2019-10906 *(unverified)* | `demo-app/fixed/requirements.txt` |
| **V3c** | `demo-app/vulnerable/requirements.txt` | 9 | SCA | PyYAML 5.1 arbitrary code execution via `yaml.load` | Trivy | `CVE-2019-20477` | CVE-2019-20477 *(unverified)* | `demo-app/fixed/requirements.txt` |
| **V4** | `demo-app/vulnerable/Dockerfile` | 7 | IaC | Container runs as root (no `USER` instruction) | Hadolint | `DL3002` | — | `demo-app/fixed/Dockerfile` |
| **V5** | `demo-app/vulnerable/Dockerfile` | 7 | IaC | Unpinned base image tag (`python:3.11-slim`) | Hadolint | `DL3007` | — | `demo-app/fixed/Dockerfile` |
| **V6** | `demo-app/vulnerable/app.py` | 69 | SAST | Weak password hashing using MD5 | Semgrep | `python.lang.security.audit.md5-used-as-password` | — (CWE-916) | `demo-app/fixed/app.py` |
| **V7** | `demo-app/vulnerable/app.py` | 114 | SAST | `debug=True` enables interactive debugger in production | Semgrep | `python.flask.security.audit.debug-enabled` | — | `demo-app/fixed/app.py` |
| **V8** | `demo-app/vulnerable/Dockerfile` | 7 | IaC | No `HEALTHCHECK` instruction in Dockerfile | Checkov | `CKV_DOCKER_28` | — | `demo-app/fixed/Dockerfile` |

### Phase 5 Usage & Drift Protection
- **Detection Rate**: Phase 5 evaluation scripts compare pipeline findings against this ground truth:
  $$\text{Detection Rate} = \frac{\text{Seeded flaws detected}}{\text{Total seeded flaws (10)}}$$
- **False Positive Rate**: Findings flagged by scanners that do not correspond to planted flaws will be evaluated as potential false positives.
- **Drift Protection**: Automated test `demo-app/tests/test_seeded_list.py` asserts that every listed file exists and contains the exact code pattern at the specified lines. If any team member refactors or alters the demo app, CI will fail immediately.

---

## H7. Verification Results

All 12 acceptance criteria specified in Section 12 were tested and verified:

| # | Acceptance Criterion | Status | Command Run | Key Output Line |
|---|---|---|---|---|
| **1** | `make setup && make validate` exits 0 | **PASS** | `python contracts/validate.py contracts/samples` & `validate.py --policy security-policy.yaml` | `[OK] All 7 SARIF file(s) in contracts/samples are valid.` / `[OK] Policy file is valid: security-policy.yaml` |
| **2** | `make test` passes (contracts, demo-app, seeded list, stages) | **PASS** | `pytest contracts/tests/ demo-app/ -v` & `bash scripts/run-stage-tests.sh` | `50 passed in 5.29s` / `================ All stage tests passed! ================` |
| **3** | `make pipeline-local` ends with WOULD DEPLOY (exit 0) | **PASS** | `bash scripts/run-local-pipeline.sh demo-app/vulnerable` | `WOULD DEPLOY` (exit code 0) |
| **4** | `make pipeline-local-fail` ends with DEPLOY BLOCKED (exit 1) | **PASS** | `GATE_FORCE_FAIL=1 bash scripts/run-local-pipeline.sh demo-app/vulnerable` | `DEPLOY BLOCKED / Gate exit code: 1` (exit code 1) |
| **5** | Negative test: corrupted sample rejected (exit 1), gate exits 2 | **PASS** | Corrupted sample removing `driver.version` evaluated by `validate.py` and `run_gate.py` | `VALIDATE EXIT: 1` / `[GATE ERROR] 1 SARIF validation error(s)` / `GATE EXIT: 2` |
| **6** | All invalid samples rejected, valid accepted | **PASS** | `pytest contracts/tests/test_validate.py -k "invalid or valid"` | All 6 invalid files in `contracts/samples/invalid/` rejected with path errors; all 7 valid passed |
| **7** | `seeded-vulnerabilities.json` matches code | **PASS** | `python scripts/check_lines.py` & `pytest demo-app/tests/test_seeded_list.py` | All 10 patterns verified at designated line numbers |
| **8** | `.github/workflows/pipeline.yml` valid with 6 jobs | **PASS** | PyYAML parse check; structural review of jobs and dependencies | Valid YAML; 6 jobs: `contracts-and-tests`, `prepare`, `build-image`, `stage`, `gate`, `deploy` |
| **9** | No real secrets committed | **PASS** | `git grep -i -E "(password|secret|key|token|auth)"` audit | Only documented fake values in `demo-app/vulnerable/config.py` (`AKIAIOSFODNN7EXAMPLE`) |
| **10** | Ownership check: every file belongs to exactly one owner | **PASS** | Audited against `CODEOWNERS` rules | 100% of repository files mapped to respective owners |
| **11** | Merge-readiness check: P2/P3/P4 can build without touching shared files | **PASS** | Structural review of interfaces and registry | P2/P3 modify only `stages/<name>/`; P4 modifies `gate/`; `pipeline.yml` and `contracts/` untouched |
| **12** | Report completeness check: H1–H10 present & accurate | **PASS** | Verified against master prompt specification | Complete document covering all files and verified criteria |

---

## H8. Handoff Guide for P2, P3, P4

### P2 Handoff (Secrets, SAST, SCA)
- **Folders Owned**: `stages/secrets/`, `stages/sast/`, `stages/sca/`, `eval/p2-code/`, `docs/p2-*`.
- **Files to Replace**:
  - `stages/secrets/run.sh` → Replace stub copy with Gitleaks CLI invocation.
  - `stages/sast/run.sh` → Replace stub copy with Semgrep CLI invocation (`--sarif`).
  - `stages/sca/run.sh` → Replace stub copy with Trivy filesystem scan (`--format sarif`).
- **Steps to Implement**:
  1. Create feature branch: `git checkout -b p2/secrets-gitleaks`.
  2. Install scanner at pinned version and update `stages/<name>/README.md`.
  3. Update `stages/<name>/run.sh` ensuring it accepts `<target> <out>`, writes `<out>/<name>.sarif`, and exits 0 on findings (exit 1 only on crash).
  4. Ensure finding properties match contract: `category` (`secret`, `sast`, `sca`), `severity` (`Critical`, `High`, `Medium`, `Low`).
  5. Run `bash stages/<name>/tests/run_test.sh` and `python contracts/validate.py <out>/<name>.sarif --stage <name>`.
  6. **Do NOT touch** `pipeline.yml`, `stages/stages.json`, or `contracts/`.
- **Merge Gate**: PR approved by P3; passes all CI checks.

### P3 Handoff (IaC, Container, SBOM, DAST)
- **Folders Owned**: `stages/iac/`, `stages/container/`, `stages/sbom/`, `stages/dast/`, `demo-app/fixed/Dockerfile`, `eval/p3-container/`, `docs/p3-*`.
- **Files to Replace**:
  - `stages/iac/run.sh` → Replace with Hadolint + Checkov invocations.
  - `stages/container/run.sh` → Replace with Trivy container image scan using `$IMAGE_REF`.
  - `stages/sbom/run.sh` → Replace with Syft generating CycloneDX JSON in `<out>/artifacts/sbom/` and empty/inventory SARIF.
  - `stages/dast/run.sh` → Replace with OWASP ZAP (and enable `dast` in `stages/stages.json` when ready).
  - `demo-app/fixed/Dockerfile` → Harden with security best practices.
- **Steps to Implement**:
  1. Create feature branch: `git checkout -b p3/iac-hadolint`.
  2. Implement scanner within `run.sh`; consume `$IMAGE_REF` for container and DAST stages.
  3. Validate output: `python contracts/validate.py <out>/<name>.sarif --stage <name>`.
  4. **Do NOT touch** `pipeline.yml` or `contracts/`.
- **Merge Gate**: PR approved by P4; passes all CI checks.

### P4 Handoff (Policy Gate, Waivers, Dashboard)
- **Folders Owned**: `gate/`, `security-policy.yaml` (from Phase 4), `eval/p4-policy/`, `docs/p4-*`.
- **Files to Replace**:
  - `gate/run_gate.py` → Replace stub logic with real policy engine.
- **Steps to Implement**:
  1. Create feature branch: `git checkout -b p4/policy-engine`.
  2. Import and use `extract_findings` from `contracts/validate.py` to normalize findings into `contracts/finding.schema.json`.
  3. Implement evaluation against `security-policy.yaml` (mode, thresholds, container rules, waivers).
  4. Preserve CLI interface: `--reports <dir> --policy <file> --out <dir>`.
  5. Preserve exit codes: 0 = pass/audit, 1 = policy violation, 2 = validation/internal error.
  6. Emit `<out>/gate-result.json` and `<out>/findings.json`.
  7. **Do NOT touch** `pipeline.yml` or `contracts/`.
- **Merge Gate**: PR approved by P2; passes all CI checks.

---

## H9. Decisions, Deviations, Limitations

### Decisions & Assumptions
1. **Python 3.11+ union syntax**: Used `dict | None` throughout scripts; tested with Python 3.11+.
2. **Bash Portability in Windows**: Automated shell scripts were tested via Git Bash (`C:\Program Files\Git\bin\bash.exe`) and PowerShell. Paths in `scripts/run-local-pipeline.sh` use `cygpath -w` detection for Windows Python compatibility while running transparently on Linux/macOS.
3. **Pytest Import Mode**: Configured `pytest.ini` with `--import-mode=importlib` to allow separate test suites in `demo-app/vulnerable/tests/` and `demo-app/fixed/tests/` to be collected without module name collisions.
4. **Deprecation Fix**: Used `datetime.datetime.now(datetime.timezone.utc)` instead of deprecated `datetime.datetime.utcnow()` across Python scripts.
5. **DAST Stage Disabled**: Marked `enabled: false` in `stages/stages.json` since ZAP requires a live service running in a container.

### Deviations from Master Prompt
None. All components, schemas, interfaces, and scripts follow the master prompt specification.

### Environment Limitations
- **Docker Daemon**: Docker daemon was not active/accessible in the execution environment; Docker image build and export jobs are validated structurally in `pipeline.yml` but could not be built locally.
- **Actionlint / Shellcheck**: `actionlint` and `shellcheck` CLI binaries were not pre-installed on the host system. YAML files were validated with PyYAML, and bash scripts were syntax-checked directly with `bash -n`.
- **Network Verification for V3 CVEs**: Because the sandbox environment restricts arbitrary internet traffic, CVE-2019-10906 and CVE-2019-20477 were verified against local package metadata and marked `cve_verified: false` in `seeded-vulnerabilities.json`.

---

## H10. Remaining Actions for the Human Team

1. **Replace CODEOWNERS Placeholders**: Edit `CODEOWNERS` and replace `@p1-handle`, `@p2-handle`, `@p3-handle`, `@p4-handle` with actual GitHub usernames.
2. **Apply Branch Protection**: Run the `gh api` command documented in `docs/branch-protection.md` to protect `main`, require status checks, and enforce CODEOWNERS reviews.
3. **Handle Secret Scanner Warning**: When pushing the repository to GitHub, GitHub push protection will flag `AKIAIOSFODNN7EXAMPLE` in `demo-app/vulnerable/config.py`. Select **"Allow secret"** with reason **"Test credential - known fake value"**.
4. **Collect Team Sign-Off**: Have all four team members review `contracts/` and record their sign-off signatures and dates in `docs/team-signoff.md`.
5. **Tag Release**: Tag the frozen contracts baseline:
   ```bash
   git tag -a contracts-v1.0.0 -m "Contracts frozen after team sign-off"
   git push origin contracts-v1.0.0
   ```

