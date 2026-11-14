# Contracts CHANGELOG

> **NOTICE:** The files in this `contracts/` directory are FROZEN after Phase 1 sign-off.
> Any amendment requires a numbered entry below, a description of what changed and why,
> the date, and explicit acknowledgement from all four team members.
> See `docs/team-signoff.md` for the sign-off process.

---

## v1.0.0 — Frozen at end of Phase 1

**Date:** 2026-11-14

**Files frozen:**
- `finding.schema.json` — Normalized finding schema
- `policy.schema.json` — Security policy schema
- `sarif-profile.md` — SARIF 2.1.0 stage output profile
- `severity-map.md` — Tool severity normalization rules
- `stage-interface.md` — Universal stage invocation interface
- `gate-interface.md` — Gate invocation interface
- `samples/` — Reference SARIF samples (one per stage)

**Status:** Awaiting sign-off from all four members (see `docs/team-signoff.md`).

---

## Amendment Process

To amend a contract after v1.0.0 is frozen:

1. Open a PR against `contracts/` — this requires all four CODEOWNERS to approve (see `docs/branch-protection.md`).
2. Add a numbered entry to this CHANGELOG with:
   - Version number (e.g. v1.1.0)
   - Date
   - Which file(s) changed
   - What changed and why
   - Acknowledgement from all four members (GitHub username + "LGTM" or equivalent)
3. Update the affected schema/doc file.
4. Run `python contracts/validate.py contracts/samples` to confirm all existing samples still pass.
5. If the amendment breaks existing samples, update them too and document why.

---

## Planned Amendments

None at this time.
