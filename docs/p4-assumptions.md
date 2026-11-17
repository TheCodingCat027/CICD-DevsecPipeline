# Phase 4 Assumptions

**Author:** P4 | **Date:** 2026-11-18

---

## A4-001: Vulnerability categories include all non-secret categories

**Decision:** The gate treats findings with `category` ∈ `{sast, sca, iac, container, dast}`
as "vulnerabilities" for the purpose of the `vulnerabilities.{critical,high,medium,low}`
thresholds. Only `category == "secret"` is counted against the `secrets.max_allowed`
threshold.

**Rationale:** The gate-interface contract specifies `category: "vulnerabilities | secrets | container"`
in the `violations` array, but the finding schema has only one `category` field per finding.
Mapping `secret` → secrets threshold, and all others → vulnerabilities threshold, is the
most natural interpretation consistent with the policy schema's structure.

---

## A4-002: Container posture rules detected by rule_id prefix

**Decision:** `must_run_as_non_root` is triggered by any finding whose `rule_id` contains
`DSP-IMG-001` or whose description contains "run as root". `banned_base_tags` is triggered
by `DSP-IMG-002` findings or by any finding whose description mentions a tag in
`banned_base_tags`.

**Rationale:** The Phase 3 container stage produces posture findings with these exact
rule IDs. This is documented in `docs/p3-handoff-to-p4.md`.

---

## A4-003: Waiver matching by id field vs rule_id vs cve_id

**Decision:** A waiver's `id` field is matched against the finding's fingerprint `id`
(sha256), `rule_id`, and `cve_id` (if present). First match wins.

**Rationale:** The gate-interface contract says "The waiver `id` matches the finding's
`id`, `rule_id`, or `cve_id`." This covers all three cases in one field.

---

## A4-004: Counts in gate-result.json reflect unwaived findings only

**Decision:** The `counts` object in `gate-result.json` reports counts of unwaived
findings only. Waived findings are still present in `findings.json` with
`waived: true`.

**Rationale:** The counts are used to report what policy is enforcing. Waived findings
should not inflate the enforced counts. The raw total is visible via `findings.json`.

---

## A4-005: GATE_FORCE_FAIL env var removed (Phase 4 behavior)

**Decision:** The Phase 4 gate does not support `GATE_FORCE_FAIL`. That was a Phase 1
stub-only mechanism. The real gate produces real decisions.

**Rationale:** `GATE_FORCE_FAIL` was explicitly marked "Stub only" in `contracts/gate-interface.md`
section 7. Keeping it in Phase 4 would mask real policy evaluation.

---

## A4-006: No cross-stage imports — gate uses only contracts/validate.py

**Decision:** `gate/run_gate.py` imports `validate` from `contracts/` only. It uses the
stable `extract_findings()` API exactly as specified. No other contract files are imported
or modified.

**Rationale:** Contracts are frozen. The gate is the only consumer of `extract_findings()`.

---

## A4-007: Violations array format extended with threshold/actual fields

**Decision:** Each element of `violations` includes `category`, `severity`, `threshold`,
`actual`, and `message`. The gate-interface contract shows only `category`, `severity`,
`threshold`, `actual`, `message` as the minimum set.

**Rationale:** Richer violation objects make it easy for dashboards and CI summaries to
render violations without string parsing.

---

## A4-008: Python 3.11 datetime.timezone.utc used instead of utcnow()

**Decision:** `datetime.datetime.now(datetime.timezone.utc)` is used for `generated_at`
timestamps, not the deprecated `datetime.datetime.utcnow()`.

**Rationale:** `utcnow()` is deprecated in Python 3.12+. Using timezone-aware datetime
is the correct modern approach.
