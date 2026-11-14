#!/usr/bin/env python3
"""
gate/run_gate.py - Stub policy gate for the DevSecOps pipeline.

[STUB] Real policy evaluation arrives in Phase 4 (P4).
This stub:
  - Validates all SARIF inputs and the policy file (exits 2 on error)
  - Counts findings by severity
  - Always passes (exit 0) UNLESS GATE_FORCE_FAIL=1 env var is set
  - Writes gate-result.json and findings.json to --out

Usage:
    python gate/run_gate.py --reports <dir> --policy <file> --out <dir>

Exit codes:
    0 - policy satisfied (or mode: audit)
    1 - policy violated  -> deploy MUST NOT run
    2 - gate/internal error (invalid SARIF, invalid policy) -> also blocks deploy
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import sys
from pathlib import Path

# Add contracts directory to path so we can import validate
_REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_REPO_ROOT / "contracts"))

try:
    import validate as _validate
    import yaml
except ImportError as e:
    print(
        f"ERROR: Missing dependency: {e}. "
        "Run: pip install -r contracts/requirements.txt",
        file=sys.stderr,
    )
    sys.exit(2)

STUB_BANNER = """\
╔══════════════════════════════════════════════════════════╗
║  [STUB GATE] Real policy evaluation arrives in Phase 4  ║
║  P4: replace the internals of gate/run_gate.py          ║
║  Current behavior: always PASS unless GATE_FORCE_FAIL=1  ║
╚══════════════════════════════════════════════════════════╝"""


def _count_severities(findings: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        sev = f.get("severity", "Low")
        if sev in counts:
            counts[sev] += 1
    return counts


def _write_error_result(
    out_dir: Path,
    mode: str,
    findings: list[dict],
    errors: list[str],
    error_msg: str,
) -> None:
    result = {
        "decision": "error",
        "mode": mode,
        "counts": _count_severities(findings),
        "violations": errors[:20],
        "waivers_applied": [],
        "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
        "stub": True,
        "error": error_msg,
    }
    (out_dir / "gate-result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    (out_dir / "findings.json").write_text(json.dumps(findings, indent=2), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    print(STUB_BANNER, file=sys.stderr)
    print("", file=sys.stderr)

    parser = argparse.ArgumentParser(
        description="DevSecOps pipeline policy gate (Phase 1 stub)",
    )
    parser.add_argument(
        "--reports", required=True,
        help="Directory containing stage report subdirectories with *.sarif files",
    )
    parser.add_argument("--policy", required=True, help="Path to security-policy.yaml")
    parser.add_argument("--out", required=True, help="Output directory for result files")
    args = parser.parse_args(argv)

    reports_dir = Path(args.reports)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    # ── Validate policy ────────────────────────────────────────────────────────
    policy_valid, policy_errors = _validate.validate_policy_file(args.policy)
    if not policy_valid:
        print(f"[GATE ERROR] Invalid policy file: {args.policy}", file=sys.stderr)
        for e in policy_errors:
            print(f"  {e}", file=sys.stderr)
        _write_error_result(out_dir, "unknown", [], policy_errors, "policy validation failed")
        return 2

    with open(args.policy, encoding="utf-8") as f:
        policy = yaml.safe_load(f)
    mode = policy.get("mode", "enforce")
    print(f"[gate] Policy mode: {mode}", file=sys.stderr)

    # ── Collect and validate all SARIF files ───────────────────────────────────
    all_findings: list[dict] = []
    validation_errors: list[str] = []

    sarif_files = sorted(reports_dir.rglob("*.sarif"))
    print(f"[gate] Found {len(sarif_files)} SARIF file(s) in {reports_dir}", file=sys.stderr)

    for sarif_path in sarif_files:
        stage_name = sarif_path.stem
        stage = stage_name if stage_name in _validate.VALID_STAGES else None

        valid, errors = _validate.validate_sarif_file(sarif_path, stage=stage)
        if not valid:
            validation_errors.extend(errors)
            print(f"[gate] INVALID: {sarif_path}", file=sys.stderr)
            for e in errors:
                print(f"  {e}", file=sys.stderr)
        else:
            with open(sarif_path, encoding="utf-8") as f:
                sarif_data = json.load(f)
            findings = _validate.extract_findings(sarif_data)
            for finding in findings:
                finding["stage"] = stage or stage_name
            all_findings.extend(findings)
            print(f"[gate] OK: {sarif_path} ({len(findings)} finding(s))", file=sys.stderr)

    if validation_errors:
        print(
            f"\n[GATE ERROR] {len(validation_errors)} SARIF validation error(s)",
            file=sys.stderr,
        )
        _write_error_result(
            out_dir, mode, all_findings, validation_errors, "SARIF validation failed"
        )
        return 2

    counts = _count_severities(all_findings)
    total = sum(counts.values())
    print(
        f"[gate] Total findings: {total} "
        f"(Critical={counts['Critical']}, High={counts['High']}, "
        f"Medium={counts['Medium']}, Low={counts['Low']})",
        file=sys.stderr,
    )

    # ── Stub gate decision ─────────────────────────────────────────────────────
    force_fail = os.environ.get("GATE_FORCE_FAIL", "0") == "1"

    if force_fail:
        print("[STUB GATE] GATE_FORCE_FAIL=1 — simulating policy violation", file=sys.stderr)
        decision = "fail"
        violations = [
            "GATE_FORCE_FAIL=1: simulated policy violation for demo/testing",
            "Real policy evaluation arrives in Phase 4 (P4)",
        ]
    else:
        decision = "pass"
        violations = []
        print("[STUB GATE] All checks PASSED (stub always passes without GATE_FORCE_FAIL=1)", file=sys.stderr)

    # ── Write outputs ──────────────────────────────────────────────────────────
    result = {
        "decision": decision,
        "mode": mode,
        "counts": counts,
        "violations": violations,
        "waivers_applied": [],
        "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
        "stub": True,
        "note": "Phase 1 stub gate — real policy evaluation in Phase 4",
    }

    (out_dir / "gate-result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    (out_dir / "findings.json").write_text(json.dumps(all_findings, indent=2), encoding="utf-8")

    print(f"[gate] Wrote gate-result.json ({total} findings) and findings.json to {out_dir}", file=sys.stderr)
    print(f"[gate] Decision: {decision.upper()}", file=sys.stderr)

    return 1 if decision == "fail" else 0


if __name__ == "__main__":
    sys.exit(main())

