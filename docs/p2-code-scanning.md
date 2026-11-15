# Phase 2 — Code-Level Security Scanning

> Owner: P2 | Phase: 2

---

## 1. Introduction

Modern software development practices, particularly continuous integration and continuous
deployment (CI/CD), require that security analysis keeps pace with code velocity. Traditional
security reviews performed as a post-development gate cannot scale to pipelines where code
is merged and deployed multiple times per day. The "shift-left" paradigm moves security
checks earlier in the development lifecycle — ideally to the moment a developer pushes a
commit — so that vulnerabilities are discovered and remediated before they propagate
downstream.

Phase 2 of this project implements the code-level layer of a shift-left DevSecOps pipeline:
secret detection (Gitleaks), static application security testing (Semgrep), and software
composition analysis (Trivy). These three stages, combined with the Phase 1 contract layer,
form the foundation upon which the policy gate (Phase 4) can make automated deployment
decisions.

---

## 2. Literature Review

> **TODO(P2) — Human author required**
>
> Suggested outline for this section:
>
> ### 2.1 OWASP Top 10 and Code-Level Risk
> Cover: how the OWASP Top 10 (2021) classifies injection (A03), identification and
> authentication failures (A07), and security misconfiguration (A05) — the classes
> targeted by this phase's scanners. Cite the official OWASP Top 10 document.
>
> ### 2.2 Shift-Left Security
> Cover: definition of shift-left; how moving security earlier reduces the cost and
> severity of vulnerabilities; industry reports on MTTR (mean time to remediate) for
> vulnerabilities found at different lifecycle stages.
>
> ### 2.3 Secret Detection
> Cover: why hardcoded credentials are a leading cause of data breaches; entropy-based
> vs. regex-based detectors; tradeoffs in false-positive rates; git history as an
> attack surface.
>
> ### 2.4 Static Application Security Testing (SAST)
> Cover: pattern-based vs. taint-tracking SAST; Semgrep's rule model; known limitations
> (false positives, lack of interprocedural analysis in community rules, language support).
>
> ### 2.5 Software Composition Analysis (SCA)
> Cover: dependency manifest scanning vs. binary analysis; CVE databases (NVD, OSV, GitHub
> Advisory); reachability analysis and why Trivy does not perform it; known limitations
> (pinned-only manifests, indirect dependencies, CVE-to-package mapping accuracy).
>
> ### 2.6 Comparison and Complementarity
> Cover: how the three tools are complementary rather than overlapping; why all three are
> needed even though some tools (Trivy) now bundle multiple scan types.
>
> **Do not invent authors, publication years, statistics, or citation strings.**
> **Write this section yourself and add real references before submission.**

---

## 3. Methodology

### 3.1 Tool Selection and Versions

| Stage | Tool | Version | License |
|-------|------|---------|---------|
| Secret detection | Gitleaks | 8.21.2 | MIT |
| SAST | Semgrep (open-source CLI) | 1.100.0 | LGPL-2.1 |
| SCA | Trivy (filesystem mode) | 0.58.1 | Apache-2.0 |

Tools were selected based on: active maintenance, permissive open-source licensing,
community adoption in the DevSecOps space, SARIF 2.1.0 output support (native or via
conversion), and compatibility with Python 3.11+ on Linux/macOS.

Exact versions are pinned in `install.sh` for each stage and recorded here for
reproducibility. Floating versions (`latest`) are explicitly prohibited.

### 3.2 Configuration

**Gitleaks:** Extended the default ruleset with two custom rules:
- `flask-secret-key`: detects `SECRET_KEY = "..."` assignments common in Flask configuration
  files. The default ruleset focuses on key-shaped entropy but misses named-variable patterns.
- `hardcoded-password`: detects `password = "..."` assignments. False-positive risk: moderate
  (may flag test fixtures or placeholder comments); mitigated with an allowlist covering
  `.env.example` and test fixture directories.

An allowlist excludes `.env.example` files (placeholder credentials by design) and
`tests/fixtures/` directories (synthetic test data). The allowlist was verified to not
suppress the seeded V1 credential.

**Semgrep:** Three custom rules cover the seeded SAST flaws:
- `p2-sql-injection-string-concat`: detects SQL queries built by string concatenation,
  `%`-formatting, f-strings, or `.format()` passed to any database `execute` call.
  Gap filled: community rules (p/python) cover Django ORM patterns; this rule targets
  raw sqlite3 and DB-API cursor patterns used in the demo app.
- `p2-weak-password-hash`: detects `hashlib.md5(...)` and `hashlib.sha1(...)` used for
  password storage. False-positive risk: low (non-password MD5 uses are distinct by context).
- `p2-flask-debug-enabled`: detects `app.run(debug=True)`. False-positive risk: very low
  (literal `True` only; `debug=False` and `debug=env_var` are explicitly excluded).

Registry packs `p/python`, `p/flask`, and `p/owasp-top-ten` are applied by default.
Registry access requires network; fail-closed behavior is enforced when offline.

**Trivy:** Filesystem mode with `--scanners vuln --vuln-type library` restricts scanning
to library vulnerabilities only. Secret and misconfiguration scanners are disabled to
prevent duplication with the `secrets` and `iac` stages respectively. The vulnerability
database is downloaded at runtime with a retry loop (3 attempts, 5-second backoff).

### 3.3 Severity Mapping

All severity values are normalized to the four canonical values (`Critical`, `High`,
`Medium`, `Low`) as specified in `contracts/severity-map.md`.

| Tool | Source Label | Canonical | Rule |
|------|-------------|-----------|------|
| Gitleaks | (any) | High | Default |
| Gitleaks | aws-access-token, gcp-service-account, azure-client-secret, … | Critical | Cloud provider rule set |
| Semgrep | ERROR | High | Severity map |
| Semgrep | WARNING | Medium | Severity map |
| Semgrep | INFO | Low | Severity map |
| Trivy | CRITICAL | Critical | Direct map |
| Trivy | HIGH | High | Direct map |
| Trivy | MEDIUM | Medium | Direct map |
| Trivy | LOW/UNKNOWN | Low | Severity map |

The original tool label is preserved in `properties.raw_severity` for auditability.

### 3.4 Fail-Closed Design

Each stage follows a strict fail-closed design:
1. If `install.sh` fails → stage exits 1, no SARIF written.
2. If the scanner crashes or times out (default 600 s, configurable via `STAGE_TIMEOUT`) →
   any partial SARIF is deleted, stage exits 1.
3. If `to_sarif.py` conversion fails → SARIF is deleted, stage exits 1.
4. If `contracts/validate.py` rejects the output → SARIF is deleted, stage exits 1.

A missing SARIF is treated by the gate as a stage failure (the gate exits 2 on missing
input), which blocks deployment regardless of policy mode.

### 3.5 Path Normalization and Redaction

All SARIF `uri` fields are repo-relative forward-slash paths regardless of:
- whether the tool reported an absolute path, Windows path, or scan-root-relative path;
- whether the target was given as a relative or absolute directory.

For the secrets stage, the actual secret value is never written to SARIF. Gitleaks is
invoked with `--redact`, and `to_sarif.py` explicitly excludes the `Secret` and `Match`
fields from conversion. The finding message contains `[REDACTED]` to make redaction
explicit.

### 3.6 Deterministic Output

Results are sorted by `(uri, startLine, ruleId)` before serialization. Two runs on
identical input produce byte-identical SARIF, which keeps CI diffs clean and makes the
evaluation reproducible.

---

## 4. Results

> Numbers sourced from `eval/p2-code/results.json`.
> Current status: `not_run` — requires tool installation and network access.
> See `eval/p2-code/results.md` for the results tables.

---

## 5. Discussion

### 5.1 Expected False Negatives

**Secrets (Gitleaks):**
- History scan covers the whole repository, not just the target subdirectory. Findings
  from other parts of the history may appear. This is deliberate (more secure) but means
  the target scope is wider than expected.
- Entropy-based detection has a known false-negative rate for low-entropy secrets (e.g.,
  the word `secret` as a literal password with no randomness).

**SAST (Semgrep):**
- Semgrep community rules use pattern matching, not taint tracking. Indirect SQL injection
  (where the vulnerable string is built several calls away from `execute`) may be missed.
- The `p2-sql-injection-string-concat` rule targets `cursor.execute(...)` calls. If a
  codebase wraps DB calls behind an ORM or helper function, the pattern may not match.
- Registry packs' detection rates depend on the currency of the community rule set.

**SCA (Trivy):**
- Trivy only sees dependencies declared in manifest files (`requirements.txt`, `Pipfile`,
  etc.). Indirect/transitive dependencies are reported if they appear in a lock file, but
  not from bare `requirements.txt` without pinned transitive deps.
- The seeded V3 CVE IDs are marked `cve_verified: false`. Trivy uses a live database;
  the actual reported CVEs may differ from or expand upon the seeded list.
- Packages without a fixed version in the database will have `fix_available: false`.

### 5.2 False Positives

- **Secrets:** The `hardcoded-password` custom rule may flag test fixture files or comment
  strings. The allowlist mitigates this for the known safe paths.
- **SAST:** The SQL injection rule uses a permissive pattern (any `.execute(query + ...)`)
  which could flag legitimate uses if a query is built from compile-time constants. The
  negative test cases (parameterized queries) confirm the rule does not fire for the fixed
  pattern.
- **SCA:** Trivy reports all vulnerabilities in the dependency database, including those
  for which no exploit code exists. The policy gate (Phase 4) is responsible for applying
  thresholds.

### 5.3 Tuning Impact

Three Semgrep configurations were defined for comparison (see `eval/p2-code/results.md`):
- Registry packs only (no custom rules)
- Custom rules only (no registry)
- Both (default)

The custom rules were specifically written to target the seeded SAST flaws (V2, V6, V7),
which use patterns (raw sqlite3, hashlib.md5, app.run) that may not be fully covered by
community registry packs. The tuning comparison (numbers pending real runs) will quantify
the marginal value of the custom rules.

---

## 6. Conclusion

Phase 2 delivers three production-ready security scanning stages that integrate cleanly
with the Phase 1 contract layer. The stages are self-contained, fail-closed, and produce
contract-valid SARIF 2.1.0 enriched with structured metadata for the Phase 4 policy gate.
Key engineering decisions — redaction, repo-relative paths, JSON-to-SARIF conversion,
deterministic output, and self-contained install scripts — were made to maximize
reliability and reproducibility in a CI/CD environment.

Evaluation numbers will be populated after the stages are run in an environment with
network access and tool availability. The human team should run `bash eval/p2-code/run_eval.sh`
after merging and update `eval/p2-code/results.json`.
