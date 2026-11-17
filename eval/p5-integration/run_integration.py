#!/usr/bin/env python3
"""
eval/p5-integration/run_integration.py
Phase 5 Integration Test: runs the full gate pipeline on pre-generated
SARIF reports from all stages, verifying end-to-end behaviour.

This test bypasses the per-stage shell wrappers (which require Linux binary paths)
and feeds the same SARIF artifacts produced in Phases 2+3 eval runs directly
to the Phase 4 gate, demonstrating the full pipeline decision contract.

Usage:
    python eval/p5-integration/run_integration.py

Exit codes:
    0 - all integration tests passed
    1 - one or more tests failed
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).parent.parent.parent
GATE = str(REPO / "gate" / "run_gate.py")
POLICY = str(REPO / "security-policy.yaml")
PYTHON = sys.executable

# ── Eval SARIF directories (from P2 and P3 eval runs) ──────────────────────
VULN_SARIFS = {
    "secrets":   REPO / "contracts" / "samples" / "secrets.sarif",
    "sast":      REPO / "contracts" / "samples" / "sast.sarif",
    "sca":       REPO / "contracts" / "samples" / "sca.sarif",
    "iac":       REPO / "eval" / "p3-container" / "runs" / "iac-vulnerable" / "iac.sarif",
    "container": REPO / "eval" / "p3-container" / "runs" / "container-vulnerable" / "container.sarif",
    "sbom":      REPO / "eval" / "p3-container" / "runs" / "sbom-vulnerable" / "sbom.sarif",
}

FIXED_SARIFS = {
    "iac":       REPO / "eval" / "p3-container" / "runs" / "iac-fixed" / "iac.sarif",
    "container": REPO / "eval" / "p3-container" / "runs" / "container-fixed" / "container.sarif",
    "sbom":      REPO / "eval" / "p3-container" / "runs" / "sbom-vulnerable" / "sbom.sarif",
}


def run_gate(sarif_map: dict[str, Path], policy: str, label: str) -> tuple[int, dict]:
    """Copy SARIFs to a temp reports dir, run gate, return (exit_code, gate_result)."""
    with tempfile.TemporaryDirectory() as reports_dir:
        with tempfile.TemporaryDirectory() as out_dir:
            # Copy each SARIF into reports_dir/<stage>/<stage>.sarif
            # (matches what run-local-pipeline.sh produces)
            for stage, src in sarif_map.items():
                stage_dir = Path(reports_dir) / stage
                stage_dir.mkdir(parents=True)
                dest = stage_dir / f"{stage}.sarif"
                dest.write_bytes(src.read_bytes())

            result = subprocess.run(
                [PYTHON, GATE, "--reports", reports_dir, "--policy", policy, "--out", out_dir],
                capture_output=True,
                text=True,
            )
            exit_code = result.returncode
            stderr = result.stderr.strip()

            gate_result_path = Path(out_dir) / "gate-result.json"
            gate_result = json.loads(gate_result_path.read_text(encoding="utf-8"))

            print(f"\n--- {label} ---")
            for line in stderr.splitlines():
                print(f"  {line}")
            print(f"  → exit code: {exit_code}  decision: {gate_result['decision']}")

            return exit_code, gate_result


def main() -> int:
    print("=" * 60)
    print("  Phase 5 Integration Test")
    print("=" * 60)

    failures: list[str] = []

    # ── Test 1: Vulnerable app → must BLOCK (exit 1, decision=fail) ──────
    exit_code, result = run_gate(VULN_SARIFS, POLICY, "Test 1: Vulnerable app (enforce)")
    if exit_code != 1:
        failures.append(f"T1: Expected exit 1, got {exit_code}")
    if result["decision"] != "fail":
        failures.append(f"T1: Expected decision=fail, got {result['decision']}")
    if len(result["violations"]) == 0:
        failures.append("T1: Expected at least 1 violation")
    if not failures or all("T1" not in f for f in failures):
        total = sum(result["counts"].values())
        print(f"  ✅ BLOCKED: {len(result['violations'])} violations, {total} findings")

    # ── Test 2: Fixed app → must PASS (exit 0, decision=pass) ────────────
    exit_code, result = run_gate(FIXED_SARIFS, POLICY, "Test 2: Fixed app (enforce)")
    if exit_code != 0:
        failures.append(f"T2: Expected exit 0, got {exit_code}")
    if result["decision"] != "pass":
        failures.append(f"T2: Expected decision=pass, got {result['decision']}")
    if not failures or all("T2" not in f for f in failures):
        total = sum(result["counts"].values())
        print(f"  ✅ ALLOWED: 0 violations, {total} findings")

    # ── Test 3: Audit mode → exit 0 even with violations ─────────────────
    import yaml
    with open(POLICY, encoding="utf-8") as f:
        pol = yaml.safe_load(f)
    pol["mode"] = "audit"
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as tmp:
        yaml.dump(pol, tmp)
        audit_policy = tmp.name

    exit_code, result = run_gate(VULN_SARIFS, audit_policy, "Test 3: Vulnerable app (audit mode)")
    if exit_code != 0:
        failures.append(f"T3: audit mode should exit 0, got {exit_code}")
    if result["decision"] != "fail":
        failures.append(f"T3: audit decision should be fail, got {result['decision']}")
    if result["mode"] != "audit":
        failures.append(f"T3: mode should be audit, got {result['mode']}")
    if not failures or all("T3" not in f for f in failures):
        print(f"  ✅ AUDIT: reported fail, exit 0 (not blocked)")

    # ── Test 4: Waiver removes a violation ───────────────────────────────
    pol["mode"] = "enforce"
    pol["waivers"] = [{
        "id": "aws-access-token",
        "reason": "Integration test waiver",
        "expires": "2027-12-31",
        "approved_by": "p5-test",
    }]
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as tmp:
        yaml.dump(pol, tmp)
        waiver_policy = tmp.name

    exit_code, result_waived = run_gate(
        VULN_SARIFS, waiver_policy, "Test 4: Vulnerable app + aws-access-token waiver"
    )
    if exit_code != 1:
        failures.append(f"T4: Still blocked (other violations), expected exit 1, got {exit_code}")
    if "aws-access-token" not in result_waived.get("waivers_applied", []):
        failures.append("T4: Expected aws-access-token in waivers_applied")
    # Secrets violation should be gone
    secrets_violations = [v for v in result_waived["violations"] if v["category"] == "secrets"]
    if secrets_violations:
        failures.append(f"T4: Secrets violation should be waived, still present: {secrets_violations}")
    if not failures or all("T4" not in f for f in failures):
        wc = len(result_waived["violations"])
        print(f"  ✅ WAIVER: secrets waived, {wc} violations remain → still blocked")

    # ── Summary ───────────────────────────────────────────────────────────
    print("\n" + "=" * 60)
    if not failures:
        print("  ALL INTEGRATION TESTS PASSED ✅")
        print("=" * 60)
        return 0
    else:
        print(f"  {len(failures)} FAILURE(S):")
        for f in failures:
            print(f"    ✗ {f}")
        print("=" * 60)
        return 1


if __name__ == "__main__":
    sys.exit(main())
