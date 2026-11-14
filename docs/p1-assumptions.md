# Phase 1 Assumptions and Decisions

> **P1 owns this document.** Updated as decisions are made.

## Decisions Made (prompt did not dictate)

1. **Python 3.11+ `str | None` union syntax** used throughout; requires Python ≥ 3.10.
   Documented here because CI uses `python-version: "3.11"`.

2. **Windows compatibility for shell scripts:** `run.sh` files use `#!/usr/bin/env bash` and
   are designed for Linux/macOS/CI (ubuntu-latest). On Windows, use Git Bash or WSL.
   The Makefile's `test` target for running stage test scripts uses `bash`, not `sh`.

3. **Git line endings:** Files are committed with Unix line endings (LF). Git on Windows
   may show CRLF warnings; this is cosmetic. Added `* text=auto` could normalize but
   was not added to avoid interfering with existing git config.

4. **SARIF `$schema` field:** Included in samples but not enforced by the validator
   (the official schema URL may be inaccessible in sandboxed CI). The validator checks
   structural correctness, not against the upstream SARIF JSON Schema.

5. **Demo app test isolation:** Tests use an in-memory SQLite database via monkey-patching
   `get_db`. This is simpler than a fixture-based approach and avoids file permission issues.

6. **CVE IDs for V3 marked "unverified":** Network access was not available to verify
   CVE-2019-10906, CVE-2019-20477 against OSV or NVD. They are plausible CVEs for
   the stated package versions but are marked `"cve_verified": false` in the JSON.

7. **Stage `dast` disabled by default** (`enabled: false` in stages.json): ZAP requires a
   running application and is expensive; disabled until Phase 3 wires it up.

8. **`GATE_FORCE_FAIL` env var:** Used instead of a `--force-fail` CLI flag to keep the
   gate interface stable (P4 replaces only the internals, not the CLI signature).

9. **`contracts/samples/invalid/` not recursed into by directory validator:** The
   `validate_directory()` function uses `glob("*.sarif")` (non-recursive) to avoid
   accidentally validating invalid samples as if they were valid ones.

10. **Stage test scripts use `python3`** (or `$PYTHON` env var override) to allow teams
    with non-standard Python installations to run tests.

11. **No `conftest.py` added:** pytest discovers `contracts/tests/` and `demo-app/` without
    a conftest because the test files add their own paths to `sys.path`.

12. **`scripts/gen_stages.py` and `gen_stage_readmes.py`:** These are helper scripts used
    during Phase 1 setup to generate repetitive stage files. They are committed as
    documentation of how the stage templates were generated but are not part of the pipeline.

13. **Makefile uses `python3` on Linux/Mac and `python` on Windows** (detected via `OS`
    environment variable). Both `pip` and `pytest` are accessed through the venv path.

14. **`gate/.gitkeep` removed:** The gate directory now contains `run_gate.py` and `README.md`,
    so `.gitkeep` was superseded.

15. **No top-level `conftest.py`:** pytest is run with explicit paths (`contracts/tests/`,
    `demo-app/`) to avoid collecting test files from unexpected locations.

