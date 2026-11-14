# Gate Interface Contract

> **⚠️ FROZEN DOCUMENT**
> This file is part of the Phase 1 contracts. It is frozen after Phase 1 sign-off.
> Do not modify without following the amendment process in `contracts/CHANGELOG.md`.
> Any change requires a numbered CHANGELOG entry and approval from all four team members.

---

## 1. Overview

The policy gate is the final arbiter of whether a build is permitted to deploy.
It reads all SARIF reports produced by the pipeline stages, normalizes the
findings, evaluates them against the security policy in `security-policy.yaml`,
applies any approved waivers, and emits a machine-readable decision.

This contract defines the gate's invocation interface, exit codes, output file
schemas, and the boundary between Phase 1 (stub) and Phase 4 (real
implementation) behavior. P4 must implement the gate so that it matches this
interface exactly; all other components (CI workflows, the orchestrator, the
demo) depend on it.

---

## 2. Universal Invocation

```bash
python gate/run_gate.py --reports <dir> --policy <file> --out <dir>
```

| Argument | Description |
|----------|-------------|
| `--reports <dir>` | Directory containing stage SARIF output files (`*.sarif`). The gate scans this directory for all `*.sarif` files. |
| `--policy <file>` | Path to the security policy YAML file (must conform to `contracts/policy.schema.json`). |
| `--out <dir>` | Directory where the gate writes its output files (`gate-result.json`, `findings.json`). Created if it does not exist. |

**Example invocations:**

```bash
# Standard pipeline invocation
python gate/run_gate.py \
  --reports /tmp/reports \
  --policy security-policy.yaml \
  --out /tmp/gate-out

# Force a failure (Phase 1 stub only — for testing CI blocking logic)
GATE_FORCE_FAIL=1 python gate/run_gate.py \
  --reports /tmp/reports \
  --policy security-policy.yaml \
  --out /tmp/gate-out
```

---

## 3. Exit Codes

| Exit Code | Meaning | Deploy Decision |
|-----------|---------|-----------------|
| `0` | Policy satisfied (all thresholds met), OR `mode: audit` | ✅ Deploy is PERMITTED |
| `1` | Policy violated (one or more thresholds exceeded) | 🚫 Deploy MUST NOT run |
| `2` | Gate or internal error (invalid SARIF, invalid policy YAML, missing arguments, unhandled exception) | 🚫 Deploy MUST NOT run |

**Key rules:**

- Exit code 1 is reserved exclusively for **policy violations**. The gate must
  not exit 1 for any other reason (use exit 2 for internal errors).
- Exit code 2 blocks deployment just as firmly as exit code 1. A gate that
  cannot validate its inputs is a gate that cannot be trusted.
- When `mode: audit`, the gate **always** exits 0 regardless of findings. It
  still writes `gate-result.json` with `decision: "fail"` if thresholds are
  exceeded, so the report reflects the true state — but it does not block.
- Both exit codes 1 and 2 must cause the CI workflow step to fail, preventing
  any subsequent deployment steps from running.

---

## 4. Output Files

The gate writes two output files to `<out>/`:

### 4.1 `<out>/gate-result.json`

Machine-readable gate decision. Consumed by CI summary steps, dashboards, and
the demo. Must contain at minimum:

```json
{
  "decision": "pass | fail | error",
  "mode": "enforce | audit",
  "counts": {
    "Critical": 0,
    "High": 0,
    "Medium": 0,
    "Low": 0
  },
  "violations": [],
  "waivers_applied": [],
  "generated_at": "<ISO 8601 datetime>"
}
```

#### Field Definitions

| Field | Type | Description |
|-------|------|-------------|
| `decision` | string | `"pass"` — policy satisfied; `"fail"` — policy violated; `"error"` — gate error |
| `mode` | string | The `mode` value from the policy file (`"enforce"` or `"audit"`) |
| `counts` | object | Total finding counts by normalized severity across all stages |
| `counts.Critical` | integer | Number of Critical findings (after waiver application) |
| `counts.High` | integer | Number of High findings (after waiver application) |
| `counts.Medium` | integer | Number of Medium findings (after waiver application) |
| `counts.Low` | integer | Number of Low findings (after waiver application) |
| `violations` | array | List of policy violation descriptions (empty if decision is `"pass"`) |
| `waivers_applied` | array | List of waiver IDs that were applied during this evaluation |
| `generated_at` | string | ISO 8601 UTC timestamp when the gate ran, e.g. `"2026-11-14T18:00:00Z"` |

#### `violations` Array Elements

Each element of `violations` is an object describing one threshold breach:

```json
{
  "category": "vulnerabilities | secrets | container",
  "severity": "Critical | High | Medium | Low | null",
  "threshold": 0,
  "actual": 3,
  "message": "Critical vulnerability threshold exceeded: 3 found, 0 allowed"
}
```

#### `waivers_applied` Array Elements

Each element identifies a waiver that matched one or more findings:

```json
{
  "waiver_id": "<waiver id from policy>",
  "findings_covered": 1,
  "expires": "2027-01-01"
}
```

#### Extended Fields (Phase 4+)

P4 may add additional fields to `gate-result.json` without breaking this
contract, provided the minimum fields above are always present. Suggested
extensions:

- `stages`: per-stage finding counts
- `by_tool`: per-tool finding counts
- `policy_version`: the policy file version
- `sarif_files_read`: list of SARIF files consumed

### 4.2 `<out>/findings.json`

The complete normalized findings array. Each element conforms to
`contracts/finding.schema.json`. This file enables downstream tools
(dashboards, ticket systems, audit logs) to consume findings without
re-parsing SARIF.

```json
[
  {
    "tool": "semgrep",
    "stage": "sast",
    "category": "sast",
    "rule_id": "python.django.security.injection.tainted-sql-string",
    "severity": "High",
    "file": "demo-app/vulnerable/app.py",
    "line": 42,
    "description": "Unsanitized user input is passed directly to a SQL query.",
    "fix": "Use parameterized queries or an ORM.",
    "id": "a3f9c2...",
    "waived": false
  }
]
```

The `waived` field is set to `true` for findings covered by an active,
non-expired waiver. The `waiver_id` field identifies the matching waiver.

---

## 5. Policy Evaluation Logic (Phase 4 Specification)

P4 must implement the following evaluation logic when replacing the stub:

### 5.1 Load and Validate

1. Load `--policy` YAML and validate against `contracts/policy.schema.json`.
   On failure, exit 2.
2. Scan `--reports` for `*.sarif` files and validate each against
   `contracts/sarif-profile.md` using `contracts/validate.py`.
   On validation failure of any SARIF file, exit 2.

### 5.2 Normalize

3. Call `extract_findings(sarif_dict)` for each SARIF file to get
   `NormalizedFinding` objects.
4. Assign the `id` fingerprint to each finding.

### 5.3 Apply Waivers

5. For each finding, check if any waiver in `policy.waivers` covers it.
   A waiver covers a finding when:
   - The waiver `id` matches the finding's `id`, `rule_id`, or `cve_id`.
   - The waiver has not expired (`expires` >= today's date).
   - If `scope` is set, the finding's `file` matches the glob.
6. Mark covered findings with `waived: true` and `waiver_id`.
7. Exclude waived findings from threshold counts.

### 5.4 Evaluate Thresholds

8. Count un-waived findings by severity.
9. Check `policy.secrets.max_allowed`: count findings where `category == "secret"`.
   If count > `max_allowed`, record a violation.
10. Check `policy.vulnerabilities.{critical,high,medium,low}`:
    For each severity where the threshold is not `null`, if count > threshold,
    record a violation.
11. Check `policy.container.must_run_as_non_root`: if true and any container
    finding indicates root execution, record a violation.
12. Check `policy.container.banned_base_tags`: if any container finding
    references a banned tag, record a violation.

### 5.5 Decide

13. If any violations were recorded:
    - Set `decision = "fail"`.
    - If `mode == "enforce"`, exit 1.
    - If `mode == "audit"`, exit 0 (but `decision` is still `"fail"` in output).
14. If no violations:
    - Set `decision = "pass"`, exit 0.

---

## 6. Phase 1 Stub Behavior

The Phase 1 stub at `gate/run_gate.py` implements a minimal version of the
interface to allow end-to-end testing before P4's real implementation is ready:

| Behavior | Stub |
|----------|------|
| Exit code (normal) | Always exits `0` |
| Exit code (forced fail) | Exits `1` when `GATE_FORCE_FAIL=1` is set |
| `gate-result.json` | Written with `decision: "pass"`, zeroed counts, empty arrays |
| `findings.json` | Written as an empty array `[]` |
| SARIF validation | Not performed by stub |
| Policy evaluation | Not performed by stub |

**Testing CI blocking logic:** Set `GATE_FORCE_FAIL=1` in the CI environment
or in `scripts/run-pipeline.sh` to verify that downstream deployment steps
are correctly skipped when the gate fails.

The stub must be replaced by P4 in Phase 4. The CI workflow does not change
between Phase 1 and Phase 4 — only the implementation of `gate/run_gate.py`
changes.

---

## 7. Environment Variables

| Variable | Used By | Description |
|----------|---------|-------------|
| `GATE_FORCE_FAIL` | Stub only | Set to `1` to force exit code 1 (for CI testing) |
| `GATE_DEBUG` | Real impl | Set to `1` to emit verbose debug output to stderr |

---

## 8. Error Handling Summary

| Scenario | Exit Code | `decision` in output |
|----------|-----------|----------------------|
| Policy satisfied, `mode: enforce` | `0` | `"pass"` |
| Policy satisfied, `mode: audit` | `0` | `"pass"` |
| Policy violated, `mode: enforce` | `1` | `"fail"` |
| Policy violated, `mode: audit` | `0` | `"fail"` |
| Invalid policy YAML | `2` | `"error"` (if writable) |
| Invalid SARIF file | `2` | `"error"` (if writable) |
| Missing `--reports` or `--policy` | `2` | Not written |
| Unhandled Python exception | `2` | `"error"` (if writable) |

When exit code 2 occurs, the gate should write `gate-result.json` with
`decision: "error"` if the output directory is known and writable. This
allows CI summary steps to report the error cause rather than showing an
empty result.

---

*Last updated: 2026-11-14 — Frozen at Phase 1 sign-off.*
