# Contributing Guide

## Branch Naming

Use the convention `<phase>/<stage>-<tool>`:

| Example | Meaning |
|---------|---------|
| `p2/secrets-gitleaks` | P2 implementing Gitleaks in the secrets stage |
| `p2/sast-semgrep` | P2 implementing Semgrep |
| `p2/sca-trivy` | P2 implementing Trivy SCA |
| `p3/iac-hadolint` | P3 implementing Hadolint |
| `p3/container-trivy` | P3 implementing Trivy image scan |
| `p3/sbom-syft` | P3 implementing Syft |
| `p3/dast-zap` | P3 implementing ZAP |
| `p4/gate-policy` | P4 implementing the policy engine |

## Small, Frequent PRs

- Each PR should cover **one stage** or **one logical change**.
- Target: < 400 lines changed per PR.
- Include tests that demonstrate the new behavior.
- Run `make test` and `make validate` before opening a PR.

## Reviewer Rotation

| Who opens the PR | Who reviews |
|-----------------|-------------|
| P2 | P3 reviews P2 |
| P3 | P4 reviews P3 |
| P4 | P2 reviews P4 |
| Any PR touching `pipeline.yml` | P1 reviews additionally |
| Any PR touching `contracts/` | All four members must approve |

## Definition of "Merge-Ready"

A PR is merge-ready when:
- [ ] All required CI checks pass (see `docs/branch-protection.md`)
- [ ] Required reviewer(s) have approved
- [ ] The PR checklist in `.github/pull_request_template.md` is complete
- [ ] No unresolved review comments
- [ ] Branch is up-to-date with `main`

## How to Replace a Stub with a Real Stage

This is the core workflow for P2 and P3. Follow these steps exactly:

1. **Branch** off `main` using the naming convention above, e.g.:
   ```bash
   git checkout -b p2/secrets-gitleaks
   ```

2. **Install the real tool** at a pinned version. Record the exact version in
   `stages/<name>/README.md`.

3. **Edit `stages/<name>/run.sh`** — replace only the stub section (the `cp` command)
   with real scanner invocation that writes `<output_dir>/<name>.sarif`.
   - The script must still accept exactly two arguments: `<target_path> <output_dir>`
   - It must still exit 0 on success (even if findings exist), 1 on scanner crash, 2 on bad args
   - It must still write `<output_dir>/<name>.sarif`

4. **Extend `stages/<name>/tests/run_test.sh`** with known-bad input tests that assert
   the expected finding count.

5. **Run** `stages/<name>/tests/run_test.sh` locally to verify.

6. **Run** `python contracts/validate.py <output_dir>/<name>.sarif --stage <name>` to
   confirm format compliance.

7. **Open a PR** — the CI pipeline will run your stage and validate the SARIF output.

**You must NOT:**
- Touch `pipeline.yml` — it already calls your stage via the matrix
- Touch `stages/stages.json` — your stage is already registered
- Touch `contracts/` — the schemas are frozen
- Add a new top-level folder without P1 approval

## Contracts Amendment Process

If you need to change a contract (rare; discuss with the whole team first):

1. Open a PR touching only `contracts/` files
2. Add a numbered entry to `contracts/CHANGELOG.md`
3. All four members must review and approve before merge
4. Run `python contracts/validate.py contracts/samples` to confirm existing samples still pass

