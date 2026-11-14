# Seeded Vulnerabilities Ground Truth

This document and `seeded-vulnerabilities.json` serve as the **ground truth** for
Phase 5 detection-rate and false-positive evaluation. Every vulnerability listed below
has been deliberately planted in `demo-app/vulnerable/`.

The drift-protection test in `demo-app/tests/test_seeded_list.py` verifies that every
listed file exists and contains the expected planted pattern.

## Vulnerability Table

| ID | File | Line | Class | Description | Expected Tool | Expected Rule ID | CVE ID(s) | Fixed In |
|---|---|---|---|---|---|---|---|---|
| **V1** | `demo-app/vulnerable/config.py` | 10 | Secret | Hardcoded fake AWS access key ID and secret access key | Gitleaks | `aws-access-token` | — | `demo-app/fixed/config.py` (read from env) |
| **V2** | `demo-app/vulnerable/app.py` | 51 | SAST | SQL injection via string concatenation in `/users` endpoint | Semgrep | `python.lang.security.audit.formatted-sql-query` | — (CWE-89) | `demo-app/fixed/app.py` (parameterized query) |
| **V3a** | `demo-app/vulnerable/requirements.txt` | 7 | SCA | Flask 1.0.2 depends on vulnerable Jinja2 | Trivy | `CVE-2019-10906` | CVE-2019-10906 *(unverified)* | `demo-app/fixed/requirements.txt` (Flask==3.1.0) |
| **V3b** | `demo-app/vulnerable/requirements.txt` | 8 | SCA | Jinja2 2.10 Server Side Template Injection via `str.format_map` | Trivy | `CVE-2019-10906` | CVE-2019-10906 *(unverified)* | `demo-app/fixed/requirements.txt` (Jinja2==3.1.5) |
| **V3c** | `demo-app/vulnerable/requirements.txt` | 9 | SCA | PyYAML 5.1 arbitrary code execution via `yaml.load` | Trivy | `CVE-2019-20477` | CVE-2019-20477 *(unverified)* | `demo-app/fixed/requirements.txt` (PyYAML==6.0.2) |
| **V4** | `demo-app/vulnerable/Dockerfile` | 7 | IaC | Container runs as root (no `USER` instruction) | Hadolint | `DL3002` | — | `demo-app/fixed/Dockerfile` (`USER appuser`) |
| **V5** | `demo-app/vulnerable/Dockerfile` | 7 | IaC | Unpinned base image tag (`python:3.11-slim` without digest) | Hadolint | `DL3007` | — | `demo-app/fixed/Dockerfile` (`python:3.11.11-slim`) |
| **V6** | `demo-app/vulnerable/app.py` | 69 | SAST | Weak password hashing using MD5 | Semgrep | `python.lang.security.audit.md5-used-as-password` | — (CWE-916) | `demo-app/fixed/app.py` (`hashlib.scrypt`) |
| **V7** | `demo-app/vulnerable/app.py` | 114 | SAST | `debug=True` enables interactive Werkzeug debugger in production | Semgrep | `python.flask.security.audit.debug-enabled` | — | `demo-app/fixed/app.py` (`debug=DEBUG` from env) |
| **V8** | `demo-app/vulnerable/Dockerfile` | 7 | IaC | No `HEALTHCHECK` instruction in Dockerfile | Checkov | `CKV_DOCKER_28` | — | `demo-app/fixed/Dockerfile` (`HEALTHCHECK` added) |

> **Note on V3 CVEs:** Network verification against the NVD/OSV database could not be
> performed during Phase 1 due to sandboxed environment restrictions. These CVEs are marked
> `cve_verified: false` in `seeded-vulnerabilities.json` and must be confirmed in Phase 2.
