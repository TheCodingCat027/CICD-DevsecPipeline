# Phase 4 Contract Feedback

**Author:** P4 | **Date:** 2026-11-18

No critical contract gaps were found that prevented Phase 4 implementation.
The following observations and proposed amendments are submitted for team discussion.

---

## CF-004-001: `violations` array element schema not fully specified

**Location:** `contracts/gate-interface.md` section 4.1

**Observation:** The `violations` array element shape is shown with `category`,
`severity`, `threshold`, `actual`, `message` fields but the gate-interface contract
does not define whether additional fields are allowed, or whether these are the
minimum required. The gate implementation adds all five fields consistently.

**Proposed amendment:** Formally define the `violations` array element schema (possibly
in `policy.schema.json`) with `additionalProperties: false` and document required fields.

**Workaround used:** The gate produces all five fields in every violation object.
The contract shows this shape in the example, so it is assumed to be correct.

---

## CF-004-002: `counts` field: waived vs unwaived ambiguity

**Location:** `contracts/gate-interface.md` section 4.1

**Observation:** The contract defines `counts` as "Total finding counts by normalized
severity across all stages" but does not specify whether waived findings are included
or excluded. The Phase 4 gate excludes waived findings from counts.

**Proposed amendment:** Add a sentence: "Waived findings are excluded from counts; they
remain in `findings.json` with `waived: true`." Optionally add a `counts_total` field
that includes waived findings for completeness.

**Workaround used:** Counts exclude waived findings (align with what policy enforces).

---

## CF-004-003: `container.banned_base_tags` matching logic not specified

**Location:** `contracts/gate-interface.md` section 5.2 and `security-policy.yaml`

**Observation:** The contract says "if any container finding references a banned tag"
but does not specify how "references" is determined from the SARIF output. Phase 3's
DSP-IMG-002 posture check is the natural carrier, but no explicit link is defined.

**Proposed amendment:** Specify that the gate checks `container` findings for the
DSP-IMG-002 rule ID as the canonical indicator of an unpinned/banned base tag.
Alternatively, define a `banned_tag` field in the finding schema.

**Workaround used:** Gate checks `rule_id` for DSP-IMG-002 and description for tag names.

---

## CF-004-004: `violations[].category` enum mismatch

**Location:** `contracts/gate-interface.md` section 4.1

**Observation:** The contract defines violation `category` as
`"vulnerabilities | secrets | container"` (three values), but the finding
schema defines finding `category` as six values: `secret, sast, sca, iac, container, dast`.
This creates a mapping question: which finding categories count as "vulnerabilities" vs
other violation categories?

**Proposed amendment:** Explicitly define the mapping in `gate-interface.md`:
- `secret` → violation category `secrets`
- `sast`, `sca`, `iac`, `dast` → violation category `vulnerabilities`
- `container` → both `vulnerabilities` (for CVEs) and `container` (for posture rules)

**Workaround used:** Assumption A4-001 (documented in `docs/p4-assumptions.md`).
