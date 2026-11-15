# Stage: `secrets`

**Owner:** P2  
**Phase:** Phase 2  
**Tool:** Gitleaks v8.21.2  

---

## 1. Purpose

The `secrets` stage performs static analysis across the repository to detect hardcoded secrets, API tokens, encryption keys, and credentials before code is deployed. It executes both a working-tree scan on the designated scan target and a git history scan across all commits when executed inside a git repository.

Output conforms to the **SARIF 2.1.0 profile** (`contracts/sarif-profile.md`), ensuring full compatibility with the pipeline gate (`gate/run_gate.py`).

---

## 2. Quick Start

### 2.1 Installation
Install Gitleaks v8.21.2 into the user cache directory:
```bash
bash stages/secrets/install.sh
```

### 2.2 Running the Stage
Execute the stage following the universal stage interface (`run.sh <target_path> <output_dir>`):
```bash
bash stages/secrets/run.sh demo-app/vulnerable /tmp/secrets-out
```
Output SARIF will be generated at `/tmp/secrets-out/secrets.sarif`.

### 2.3 Running the Test Suite
Run the test suite verifying detection, schema validation, redaction, and error handling:
```bash
bash stages/secrets/tests/run_test.sh
```

---

## 3. Configuration (`gitleaks.toml`)

The stage extends Gitleaks' built-in rule catalog using `stages/secrets/gitleaks.toml`.

### 3.1 Custom Rules
- **`flask-secret-key`**: Targets hardcoded Flask session secrets (`SECRET_KEY = "..."`) in source code. Default Gitleaks rules often miss generic session keys in web framework config files.
- **`hardcoded-password`**: Identifies variable assignments matching common password variables (`password`, `passwd`, `pwd` assigned a literal string of 4+ characters).

### 3.2 Allowlist Rationale
Path allowlists prevent false positives from interfering with CI:
- **`.env.example`**: Example template configuration intended for public documentation; contains dummy place-holder tokens.
- **`tests/fixtures/`**: Dedicated test fixture directories containing non-operational synthetic tokens for unit/integration tests.
- **`tests/run_test.sh`**: The stage integration test script which constructs synthetic test strings dynamically.
- **`seeded-vulnerabilities`**: Benchmark files and ground-truth metadata used for pipeline evaluation.

---

## 4. Severity Mapping

Per `contracts/severity-map.md`, Gitleaks detects generic secrets without inherent severity distinction. The stage post-processes detections via `to_sarif.py` into canonical severity values:

| Gitleaks Finding / Rule ID | Canonical Severity | SARIF Level | Rationale |
|----------------------------|--------------------|-------------|-----------|
| Cloud provider keys (`aws-access-token`, `aws-secret-access-key`, `gcp-service-account`, `gcp-service-account-credentials`, `azure-client-secret`, `azure-service-principal`, `github-pat`, `github-fine-grained-pat`, `github-oauth`) | `Critical` | `error` | Direct infrastructure/cloud account compromise risk |
| All other detected secrets & tokens | `High` | `error` | High risk of credential exposure and lateral movement |

The original scanner severity label is preserved in SARIF `properties.raw_severity` (`"HIGH"`).

---

## 5. Environment Variables & Caching

| Variable | Default | Purpose |
|----------|---------|---------|
| `STAGE_TIMEOUT` | `600` | Scanner timeout in seconds per detection pass |
| `GITLEAKS_SKIP_VERIFY` | `0` | If set to `1`, forces re-download even if cached |
| `PYTHON` | `python3` | Python binary used for conversion and validation |

### Cache Path
The Gitleaks binary is cached at:
```
${XDG_CACHE_HOME:-$HOME/.cache}/devsecops/gitleaks-8.21.2/gitleaks
```

---

## 6. Known Limitations

- **Git History Scope**: The history scan operates on the whole repository (`--source $REPO_ROOT`), even if `<target_path>` points to a subdirectory.
- **Redaction Context**: Secret values are fully redacted (`[REDACTED]`) from SARIF messages, but line numbers and file paths are preserved for developer remediation.
- **Test Directory Allowlist**: Files under `tests/fixtures/` are allowed by default; actual secrets mistakenly committed to fixture paths will not be flagged.
