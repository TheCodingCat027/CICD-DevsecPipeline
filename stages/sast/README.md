# Stage: `sast`

**Owner:** P2  
**Phase:** Phase 2 (Implemented)  

## Purpose

The `sast` stage provides Static Application Security Testing (SAST) for source code across the repository. It analyzes application code for security anti-patterns, injection vulnerabilities, insecure cryptographic usage, and dangerous configuration parameters.

## Scanner & Pinned Version

- **Tool:** [Semgrep](https://semgrep.dev/)
- **Pinned Version:** `1.100.0`
- **Installation:** Managed automatically via `install.sh` into a dedicated virtual environment:
  `${XDG_CACHE_HOME:-$HOME/.cache}/devsecops/semgrep-1.100.0/venv`

## Quick Start

### 1. Install Semgrep
```bash
bash stages/sast/install.sh
```

### 2. Run Scan
```bash
bash stages/sast/run.sh <target_path> <output_dir>
# Example:
bash stages/sast/run.sh demo-app/vulnerable/ reports/
```

### 3. Run Integration Tests
```bash
bash stages/sast/tests/run_test.sh
```

## Interface & Exit Codes

Complies with [contracts/stage-interface.md](../../contracts/stage-interface.md):

- `run.sh <target_path> <output_dir>` writes `<output_dir>/sast.sarif`
- **Exit Code 0:** Scan completed successfully (findings are documented in the SARIF file, not indicated via exit code)
- **Exit Code 1:** Scanner error, timeout, or crash (fails closed; deletes any incomplete SARIF)
- **Exit Code 2:** Usage error (invalid argument count or missing target path)

## Custom Rules

In addition to standard Semgrep registry rulesets, this stage includes three purpose-built rules in `stages/sast/rules/`:

### 1. `p2-sql-injection-string-concat` (`rules/sql-injection.yaml`)
- **Gap It Fills:** Generic community rules often assume specific ORMs (Django, SQLAlchemy). This rule targets direct raw SQL query string formatting (via `%`, `.format()`, f-strings, or `+` concatenation) assigned or passed to SQLite and DB-API `cursor.execute(...)` calls.
- **Target:** Seeded vulnerability `V2` in `demo-app/vulnerable/app.py`.
- **False-Positive Risk:** Low. Parameterized queries using tuples (`conn.execute("...", (param,))`) or lists are explicitly matched as clean (`# ok`).

### 2. `p2-weak-password-hash` (`rules/weak-hashing.yaml`)
- **Gap It Fills:** Standard crypto rules often flag MD5/SHA-1 purely as generic weak hashes. This rule specifically flags `hashlib.md5(...)` and `hashlib.sha1(...)` invocations within user registration and authentication workflows, enforcing secure password hashing alternatives (e.g. `hashlib.scrypt`, `argon2-cffi`, or `bcrypt`).
- **Target:** Seeded vulnerability `V6` in `demo-app/vulnerable/app.py`.
- **False-Positive Risk:** Low. Non-security usage of MD5 (such as checksumming) should use explicit SHA-256 or be isolated; authentication logic must never use MD5.

### 3. `p2-flask-debug-enabled` (`rules/flask-debug.yaml`)
- **Gap It Fills:** Detects `debug=True` in Flask `app.run(...)` calls across all argument positions (`host`, `port`, keyword args). In production, `debug=True` exposes the interactive Werkzeug PIN debugger, leading directly to Remote Code Execution (RCE).
- **Target:** Seeded vulnerability `V7` in `demo-app/vulnerable/app.py`.
- **False-Positive Risk:** Low. Production deployments should always control debugging via environment variables (e.g., `os.environ.get('FLASK_DEBUG') == 'true'`) or a WSGI application server (Gunicorn/uWSGI).

## Severity Mapping

Per [contracts/severity-map.md](../../contracts/severity-map.md), Semgrep severity values are mapped to canonical pipeline values:

| Semgrep Severity | SARIF `level` | Normalized Severity | Pipeline Action |
|:-----------------|:--------------|:--------------------|:----------------|
| `ERROR`          | `error`       | `High`              | Gate-evaluated threshold |
| `WARNING`        | `warning`     | `Medium`            | Gate-evaluated threshold |
| `INFO`           | `note`        | `Low`               | Informational |
| *(fallback)*     | `note`        | `Low`               | Fallback default |

The original Semgrep severity is preserved in `properties.raw_severity`.

## Environment Variables

| Variable | Default | Purpose |
|:---------|:--------|:--------|
| `STAGE_TIMEOUT` | `600` | Scanner timeout in seconds before failing closed (exit 1). |
| `SAST_ALLOW_OFFLINE` | `0` | Fail closed (`0`) if registry packs cannot be fetched, or allow offline fallback (`1`) using local custom rules. |
| `SAST_CUSTOM_RULES` | `1` | Enable local custom rules in `stages/sast/rules/` (`1` enabled, `0` disabled). |
| `SAST_REGISTRY_PACKS` | `"p/python p/flask p/owasp-top-ten"` | Space-separated list of Semgrep registry packs to scan with. Set to `""` to scan offline with custom rules only. |

## Cache Paths

- **Semgrep Binary & Virtualenv:** `${XDG_CACHE_HOME:-$HOME/.cache}/devsecops/semgrep-1.100.0/venv`
- Intermediate JSON and log files are created inside isolated temporary directories (`mktemp -d`) and cleaned up on exit.

## Known Limitations

1. **Registry Network Dependency:** Downloading registry packs (`p/python`, `p/flask`, `p/owasp-top-ten`) requires outbound HTTPS access. In airgapped or offline environments, set `SAST_ALLOW_OFFLINE=1` or `SAST_REGISTRY_PACKS=""` to rely exclusively on local custom rules.
2. **Dynamic / Metaprogrammed Execution:** Pure static pattern matching cannot track dynamic runtime `eval()` or un-annotated string interpolations executed outside lexical scope.
