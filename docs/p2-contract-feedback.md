# Phase 2 — Contract Feedback

> Owner: P2 | Phase: 2

The following items were noted during Phase 2 implementation. They require team
discussion before any amendment to `contracts/`. **P2 did not edit contracts/.**

---

## CF-1 — `help_uri` in result.properties

**Observation:** `contracts/finding.schema.json` lists `help_uri` as an optional field
in the `NormalizedFinding` schema, and `contracts/sarif-profile.md` §6 shows it in the
field mapping table. However, `contracts/validate.py` applies `additionalProperties: false`
at the result.properties level.

Trivy provides a `PrimaryURL` field (the CVE advisory URL) which maps naturally to `help_uri`.
Including it would improve traceability for SCA findings.

**Proposed Amendment CA-1:**
Add `"help_uri"` to the `result.properties` allowed fields in the JSON Schema used by
`validate.py`, with type `string`. This is a backward-compatible additive change.

**Required approvals:** All four team members per `contracts/CHANGELOG.md`.

---

## CF-2 — Gitleaks history findings: no line number for history-only commits

**Observation:** When Gitleaks detects a secret only in git history (not in the working tree),
the `StartLine` may be 0 or absent because the commit diff context doesn't always carry
the original source line. The contract requires `line >= 0` (integer), so 0 is valid and used.

**Proposed Amendment:** None needed; the contract already supports `line: 0` as a file-level
finding. Documenting here for transparency.

---

*Last updated: Phase 2 implementation — 2026-11-15*
