# Stage: `sca` (Software Composition Analysis)

**Owner:** P2  
**Phase:** Phase 2 (Implemented)  
**Tool:** Aqua Security Trivy (filesystem mode)  
**Pinned Version:** `0.58.1`  

---

## 1. Purpose

The `sca` stage performs Software Composition Analysis across the repository's source tree and package manifests (e.g. `requirements.txt`, `package.json`, `go.mod`, `pom.xml`, etc.). It identifies known vulnerabilities (CVEs) in third-party libraries and direct/transitive dependencies, producing standard-compliant SARIF 2.1.0 output for policy gating.

### Scanners Enabled: `--scanners vuln --vuln-type library`
This stage runs Trivy in filesystem mode restricted strictly to vulnerability scanning for language packages and libraries:
- **Secrets scanning is disabled here**: Secrets are handled dedicatedly in `stages/secrets/` via Gitleaks.
- **Misconfiguration/IaC scanning is disabled here**: Infrastructure-as-Code and container configuration issues are handled in `stages/iac/` and `stages/container/`.
- Keeping scanners orthogonal prevents duplicate findings across pipeline stages and ensures compliance with `contracts/finding.schema.json`.

---

## 2. Quick Start

### Installation
Trivy v0.58.1 is automatically downloaded and verified by `install.sh` when `run.sh` is executed. You can also run the installer standalone:

```bash
bash stages/sca/install.sh
```

### Running the Stage
The stage complies with the universal stage interface (`contracts/stage-interface.md`):

```bash
bash stages/sca/run.sh <target_path> <output_dir>
```

**Example:**
```bash
bash stages/sca/run.sh demo-app/vulnerable reports/sca
```

**Output:**
- `reports/sca/sca.sarif`: SARIF 2.1.0 report containing normalized SCA findings.
- **Exit codes:**
  - `0`: Scan completed successfully (even if vulnerabilities were detected).
  - `1`: Scanner crashed, timed out, or vulnerability database download failed.
  - `2`: Invalid arguments or target path does not exist.

---

## 3. Severity Mapping

Per `contracts/severity-map.md`, Trivy severity levels are normalized to the four canonical policy severities:

| Trivy Source Label | Canonical Severity | SARIF Level | Notes |
|--------------------|--------------------|-------------|-------|
| `CRITICAL`         | `Critical`         | `error`     | Immediate remediation required |
| `HIGH`             | `High`             | `error`     | Significant risk |
| `MEDIUM`           | `Medium`           | `warning`   | Moderate risk |
| `LOW`              | `Low`              | `note`      | Minor risk |
| `UNKNOWN`          | `Low`              | `note`      | Unrated vulnerabilities conservatively mapped to Low |

The original scanner label is preserved in `properties.raw_severity`.

---

## 4. V3 Seeded Vulnerabilities Verification Note

In `demo-app/seeded-vulnerabilities.json`, the SCA test vulnerabilities are listed with `cve_verified: false`:
- **V3a**: `Flask==1.0.2` (depends on Jinja2 < 2.10.1)
- **V3b**: `Jinja2==2.10` (seeded as `CVE-2019-10906`)
- **V3c**: `PyYAML==5.1` (seeded as `CVE-2019-20477`)

### Actual Scanner Behavior:
- Real vulnerability databases (GitHub Advisory Database, NVD, Aqua Vulnerability DB) are continuously updated.
- Trivy may report `CVE-2019-10906`, `CVE-2019-20477`, or different / additional advisory identifiers (such as `GHSA-xxx` or other CVE IDs) for these exact package versions.
- If Trivy reports different or additional CVEs for `Flask 1.0.2`, `Jinja2 2.10`, or `PyYAML 5.1`, **this is expected and correct behavior**. The stage faithfully reflects the actual scanner findings rather than fabricating hardcoded IDs.

---

## 5. Environment Variables & Configuration

| Variable | Default | Purpose |
|----------|---------|---------|
| `STAGE_TIMEOUT` | `600` | Maximum time in seconds for the scan before timing out |
| `TRIVY_BIN` / `TRIVY_PATH` | (cached path) | Override path to custom or pre-installed Trivy executable |
| `TRIVY_DB_CACHE` | `$HOME/.cache/devsecops/trivy-db` | Directory where Trivy vulnerability database is cached |
| `TRIVY_DB_REPOSITORY` | *(empty)* | Custom OCI registry for downloading the vulnerability DB |
| `TRIVY_SKIP_VERIFY` | `0` | If set to `1`, forces re-download in `install.sh` |
| `TRIVY_NO_PROGRESS` | `true` | Suppresses interactive progress bars in CI logs |
| `PYTHON` | `python3` (or `python`) | Python interpreter used for `to_sarif.py` conversion |

---

## 6. Cache Paths

To avoid redundant downloads in CI/CD environments and minimize execution time:
- **Trivy Binary:** `${XDG_CACHE_HOME:-$HOME/.cache}/devsecops/trivy-0.58.1/trivy`
- **Vulnerability Database:** `${XDG_CACHE_HOME:-$HOME/.cache}/devsecops/trivy-db`

In CI workflows (such as GitHub Actions), caching `${HOME}/.cache/devsecops` significantly accelerates pipeline runtime.

---

## 7. Network Requirements

Trivy requires outbound network access during the initial run to download its vulnerability database from GitHub / OCI (`ghcr.io/aquasecurity/trivy-db`). In air-gapped or restricted CI environments:
1. Pre-seed the cache at `$HOME/.cache/devsecops/trivy-db`.
2. Or configure an internal mirror using `TRIVY_DB_REPOSITORY`.

---

## 8. Known Limitations

- **Manifest Scanning vs Lockfiles**: Scans against unpinned manifests (e.g. `requirements.txt` with loose ranges) only detect vulnerabilities in explicitly declared packages. Using lockfiles (`poetry.lock`, `Pipfile.lock`, `package-lock.json`) provides full transitive dependency visibility.
- **Line Number Resolution**: For `requirements.txt`, `to_sarif.py` searches for package declarations to report exact 1-based line numbers. For binary or non-textual manifests, line numbers default to `0` (file-level finding).
- **Scanner Output**: Trivy filesystem scan only scans packages discovered on disk or in recognized manifest formats; non-standard dependency layouts may require specific manifest paths.

---

## 9. Running Tests

To execute the stage integration test suite:

```bash
bash stages/sca/tests/run_test.sh
```

Tests verify:
- **Test A:** Detection of vulnerabilities in `demo-app/vulnerable/`, SARIF schema validity, and finding counts.
- **Test B:** Zero findings on an empty directory.
- **Test C:** Exit code `2` on wrong argument count.
- **Test D:** Exit code `2` on nonexistent target path.
- **Test E:** Fail closed (exit code `1`, no SARIF file) on scanner failure.
