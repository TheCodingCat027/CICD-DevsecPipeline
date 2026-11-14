# Team Sign-off — Contracts v1.0.0

> **This sign-off is the real gate for freezing the contracts.**
> Until all four members have signed below, `contracts/` is **not** frozen and can still be amended.
> Once all four sign, amendments require the process in `contracts/CHANGELOG.md`.

## Sign-off Checklist

Each team member must review **all** files in `contracts/` and confirm:
- The finding schema covers all fields they will need in their phase
- The SARIF profile is compatible with the tool(s) they will use
- The severity map correctly normalizes their tool's output
- The stage/gate interface is implementable with their tool
- The sample SARIF files are consistent with the seeded vulnerability list

---

### P1 (Foundation & Infrastructure)

- [ ] Reviewed `contracts/finding.schema.json`
- [ ] Reviewed `contracts/policy.schema.json`
- [ ] Reviewed `contracts/sarif-profile.md`
- [ ] Reviewed `contracts/severity-map.md`
- [ ] Reviewed `contracts/stage-interface.md`
- [ ] Reviewed `contracts/gate-interface.md`
- [ ] Reviewed `contracts/samples/`
- [ ] **Sign-off:** _____________________ Date: _____________

---

### P2 (Secrets, SAST, SCA)

- [ ] Reviewed `contracts/finding.schema.json` — confirmed fields for Gitleaks, Semgrep, Trivy
- [ ] Reviewed `contracts/sarif-profile.md` — confirmed SARIF subset is emittable
- [ ] Reviewed `contracts/severity-map.md` — confirmed tool severity mappings
- [ ] Reviewed `contracts/stage-interface.md` — confirmed interface is implementable
- [ ] Reviewed `contracts/samples/secrets.sarif`, `sast.sarif`, `sca.sarif`
- [ ] **Sign-off:** _____________________ Date: _____________

---

### P3 (IaC, Container, SBOM, DAST)

- [ ] Reviewed `contracts/finding.schema.json` — confirmed fields for Hadolint, Checkov, Trivy, Syft, ZAP
- [ ] Reviewed `contracts/sarif-profile.md` — confirmed SARIF subset is emittable
- [ ] Reviewed `contracts/severity-map.md` — confirmed tool severity mappings
- [ ] Reviewed `contracts/stage-interface.md` — confirmed interface is implementable
- [ ] Reviewed `contracts/samples/iac.sarif`, `container.sarif`, `sbom.sarif`, `dast.sarif`
- [ ] **Sign-off:** _____________________ Date: _____________

---

### P4 (Policy Gate, Waivers, Dashboard)

- [ ] Reviewed `contracts/finding.schema.json` — confirmed all fields needed for policy evaluation
- [ ] Reviewed `contracts/policy.schema.json` — confirmed schema is sufficient for Phase 4
- [ ] Reviewed `contracts/gate-interface.md` — confirmed interface is implementable
- [ ] Reviewed `contracts/stage-interface.md` — confirmed normalizer interface (extract_findings)
- [ ] Reviewed `contracts/samples/` — confirmed sample data is usable for stub gate testing
- [ ] **Sign-off:** _____________________ Date: _____________

---

## After All Four Sign Off

1. Update `contracts/CHANGELOG.md` with the sign-off date.
2. Apply branch protection (see `docs/branch-protection.md`) so that any future change to
   `contracts/` requires all four approvals via CODEOWNERS.
3. Tag the commit: `git tag -a contracts-v1.0.0 -m "Contracts frozen after team sign-off"`
4. Announce in the team channel that contracts are frozen and development can begin.

