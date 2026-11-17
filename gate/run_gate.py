#!/usr/bin/env python3
"""
gate/run_gate.py - Real policy gate for the DevSecOps pipeline (Phase 4).

Implements the full gate-interface.md contract:
  - Validates all SARIF inputs and the policy file (exits 2 on error)
  - Normalizes findings via contracts/validate.extract_findings()
  - Applies waivers from policy.waivers
  - Evaluates thresholds: secrets, vulnerabilities, container rules
  - Writes gate-result.json and findings.json to --out
  - Exits 0 (pass / audit-mode), 1 (policy violated, enforce-mode), 2 (error)

Usage:
    python gate/run_gate.py --reports <dir> --policy <file> --out <dir>

Exit codes:
    0 - policy satisfied (or mode: audit)
    1 - policy violated  -> deploy MUST NOT run
    2 - gate/internal error (invalid SARIF, invalid policy, bad args)
"""
from __future__ import annotations

import argparse
import datetime
import fnmatch
import json
import os
import sys
from pathlib import Path
from typing import Any

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

_DEBUG = os.environ.get("GATE_DEBUG", "0") == "1"


def _dbg(msg: str) -> None:
    if _DEBUG:
        print(f"[gate:debug] {msg}", file=sys.stderr)


# ── Waiver matching ──────────────────────────────────────────────────────────

def _waiver_matches(waiver: dict, finding: dict) -> bool:
    """Return True if waiver covers finding (ID, rule_id, or cve_id match, not expired, scope ok)."""
    today = datetime.date.today()
    expires_str = waiver.get("expires", "")
    try:
        expires_date = datetime.date.fromisoformat(expires_str)
    except (ValueError, TypeError):
        _dbg(f"Waiver {waiver.get('id')} has bad expires date: {expires_str!r}")
        return False

    if expires_date < today:
        _dbg(f"Waiver {waiver.get('id')} expired on {expires_str}")
        return False

    waiver_id = waiver.get("id", "")
    finding_id = finding.get("id", "")
    rule_id = finding.get("rule_id", "")
    cve_id = finding.get("cve_id", "")

    # Match if waiver ID equals finding's fingerprint id, rule_id, or cve_id
    if waiver_id not in (finding_id, rule_id, cve_id):
        return False

    # Scope glob check (optional)
    scope = waiver.get("scope")
    if scope:
        file_path = finding.get("file", "")
        if not fnmatch.fnmatch(file_path, scope):
            return False

    return True


def _apply_waivers(findings: list[dict], policy_waivers: list[dict]) -> list[str]:
    """Mark waived findings in-place. Returns list of waiver IDs that were applied."""
    applied: list[str] = []
    for finding in findings:
        finding["waived"] = False
        for waiver in policy_waivers:
            if _waiver_matches(waiver, finding):
                finding["waived"] = True
                finding["waiver_id"] = waiver["id"]
                if waiver["id"] not in applied:
                    applied.append(waiver["id"])
                _dbg(
                    f"Waiver {waiver['id']} covers finding "
                    f"{finding.get('rule_id')} in {finding.get('file')}"
                )
                break
    return applied


# ── Threshold evaluation ─────────────────────────────────────────────────────

def _count_severities(findings: list[dict], *, waived_only: bool = False) -> dict[str, int]:
    counts: dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        if waived_only and not f.get("waived", False):
            continue
        if not waived_only and f.get("waived", False):
            continue
        sev = f.get("severity", "Low")
        if sev in counts:
            counts[sev] += 1
    return counts


def _count_all_severities(findings: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        sev = f.get("severity", "Low")
        if sev in counts:
            counts[sev] += 1
    return counts


def _evaluate_policy(findings: list[dict], policy: dict) -> list[dict]:
    """
    Evaluate unwaived findings against policy thresholds.
    Returns list of violation dicts (empty = pass).
    """
    violations: list[dict] = []
    unwaived = [f for f in findings if not f.get("waived", False)]

    # ── Secrets threshold ────────────────────────────────────────────────────
    secrets_policy = policy.get("secrets", {})
    max_secrets = secrets_policy.get("max_allowed", 0)
    secrets_count = sum(1 for f in unwaived if f.get("category") == "secret")
    _dbg(f"Secrets: {secrets_count} unwaived (max_allowed={max_secrets})")
    if secrets_count > max_secrets:
        violations.append({
            "category": "secrets",
            "severity": "Critical",
            "threshold": max_secrets,
            "actual": secrets_count,
            "message": (
                f"Secrets threshold exceeded: found {secrets_count} secret(s), "
                f"max_allowed={max_secrets}"
            ),
        })

    # ── Vulnerability thresholds ─────────────────────────────────────────────
    vuln_policy = policy.get("vulnerabilities", {})
    # Categories that count as general vulnerabilities (all except "secret")
    vuln_categories = {"sast", "sca", "iac", "container", "dast"}
    vuln_findings = [f for f in unwaived if f.get("category") in vuln_categories]

    sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in vuln_findings:
        sev = f.get("severity", "Low")
        if sev in sev_counts:
            sev_counts[sev] += 1

    for sev_key in ("critical", "high", "medium", "low"):
        threshold = vuln_policy.get(sev_key)
        if threshold is None:
            continue   # null = unlimited
        sev_name = sev_key.capitalize()
        actual = sev_counts[sev_name]
        _dbg(f"Vulns {sev_name}: {actual} unwaived (threshold={threshold})")
        if actual > threshold:
            violations.append({
                "category": "vulnerabilities",
                "severity": sev_name,
                "threshold": threshold,
                "actual": actual,
                "message": (
                    f"Vulnerability threshold exceeded: {actual} {sev_name} finding(s), "
                    f"max={threshold}"
                ),
            })

    # ── Container rules ──────────────────────────────────────────────────────
    container_policy = policy.get("container", {})
    container_findings = [f for f in unwaived if f.get("category") == "container"]

    # must_run_as_non_root: block if DSP-IMG-001 is present
    if container_policy.get("must_run_as_non_root", False):
        root_findings = [
            f for f in container_findings
            if "DSP-IMG-001" in f.get("rule_id", "")
            or "run as root" in f.get("description", "").lower()
            or "root" in f.get("rule_id", "").lower()
        ]
        _dbg(f"Container root findings: {len(root_findings)}")
        if root_findings:
            violations.append({
                "category": "container",
                "severity": "High",
                "threshold": 0,
                "actual": len(root_findings),
                "message": (
                    f"Container must_run_as_non_root violated: "
                    f"{len(root_findings)} finding(s) indicate root execution "
                    f"({', '.join(f['rule_id'] for f in root_findings)})"
                ),
            })

    # banned_base_tags: block if DSP-IMG-002 or banned-tag findings present
    banned_tags = container_policy.get("banned_base_tags", [])
    if banned_tags:
        def _has_banned_tag(finding: dict) -> bool:
            desc = finding.get("description", "").lower()
            rule = finding.get("rule_id", "")
            # DSP-IMG-002 means unpinned / floating tag
            if "DSP-IMG-002" in rule:
                return True
            # Check if any banned tag appears in description/message
            return any(tag.lower() in desc for tag in banned_tags)

        banned_findings = [f for f in container_findings if _has_banned_tag(f)]
        _dbg(f"Container banned-tag findings: {len(banned_findings)}")
        if banned_findings:
            violations.append({
                "category": "container",
                "severity": "Medium",
                "threshold": 0,
                "actual": len(banned_findings),
                "message": (
                    f"Container banned_base_tags violated: "
                    f"{len(banned_findings)} finding(s) reference a banned tag "
                    f"(banned: {banned_tags})"
                ),
            })

    return violations


# ── Output helpers ────────────────────────────────────────────────────────────

def _write_result(
    out_dir: Path,
    decision: str,
    mode: str,
    counts: dict[str, int],
    violations: list[dict],
    waivers_applied: list[str],
    findings: list[dict],
    extra: dict[str, Any] | None = None,
) -> None:
    result: dict[str, Any] = {
        "decision": decision,
        "mode": mode,
        "counts": counts,
        "violations": violations,
        "waivers_applied": waivers_applied,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if extra:
        result.update(extra)

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "gate-result.json").write_text(
        json.dumps(result, indent=2), encoding="utf-8"
    )
    (out_dir / "findings.json").write_text(
        json.dumps(findings, indent=2), encoding="utf-8"
    )


def _write_error_result(
    out_dir: Path,
    mode: str,
    findings: list[dict],
    errors: list[str],
    error_msg: str,
) -> None:
    counts = _count_all_severities(findings)
    _write_result(
        out_dir,
        decision="error",
        mode=mode,
        counts=counts,
        violations=[{"category": "internal", "severity": "Critical",
                     "threshold": 0, "actual": 0, "message": e} for e in errors[:20]],
        waivers_applied=[],
        findings=findings,
        extra={"error": error_msg},
    )


# ── Main ─────────────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:  # noqa: C901
    parser = argparse.ArgumentParser(
        description="DevSecOps pipeline policy gate (Phase 4)",
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

    # ── Validate policy ──────────────────────────────────────────────────────
    policy_valid, policy_errors = _validate.validate_policy_file(args.policy)
    if not policy_valid:
        print(f"[gate] ERROR: Invalid policy file: {args.policy}", file=sys.stderr)
        for e in policy_errors:
            print(f"  {e}", file=sys.stderr)
        _write_error_result(out_dir, "unknown", [], policy_errors, "policy validation failed")
        return 2

    with open(args.policy, encoding="utf-8") as f:
        policy = yaml.safe_load(f)
    mode = policy.get("mode", "enforce")
    print(f"[gate] Policy mode: {mode}", file=sys.stderr)

    # ── Collect and validate all SARIF files ─────────────────────────────────
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
            print(
                f"[gate] OK: {sarif_path.name} ({len(findings)} finding(s))",
                file=sys.stderr,
            )

    if validation_errors:
        print(
            f"\n[gate] ERROR: {len(validation_errors)} SARIF validation error(s)",
            file=sys.stderr,
        )
        _write_error_result(
            out_dir, mode, all_findings, validation_errors, "SARIF validation failed"
        )
        return 2

    # ── Apply waivers ────────────────────────────────────────────────────────
    policy_waivers = policy.get("waivers", [])
    waivers_applied = _apply_waivers(all_findings, policy_waivers)
    if waivers_applied:
        print(f"[gate] Waivers applied: {waivers_applied}", file=sys.stderr)
    else:
        print("[gate] No waivers applied", file=sys.stderr)

    # ── Count findings ───────────────────────────────────────────────────────
    counts_all = _count_all_severities(all_findings)
    counts_unwaived = _count_severities(all_findings)   # excludes waived
    total_all = sum(counts_all.values())
    total_unwaived = sum(counts_unwaived.values())
    total_waived = total_all - total_unwaived

    print(
        f"[gate] Total findings: {total_all} "
        f"(Critical={counts_all['Critical']}, High={counts_all['High']}, "
        f"Medium={counts_all['Medium']}, Low={counts_all['Low']})",
        file=sys.stderr,
    )
    print(
        f"[gate] After waivers : {total_unwaived} unwaived, {total_waived} waived",
        file=sys.stderr,
    )

    # ── Evaluate policy ──────────────────────────────────────────────────────
    violations = _evaluate_policy(all_findings, policy)

    # decision uses the unwaived counts for the output
    decision = "fail" if violations else "pass"

    if violations:
        print(f"\n[gate] Policy VIOLATED — {len(violations)} violation(s):", file=sys.stderr)
        for v in violations:
            print(f"  [{v['category'].upper()}] {v['message']}", file=sys.stderr)
    else:
        print("[gate] All policy thresholds SATISFIED", file=sys.stderr)

    # In audit mode, never block even on violations
    if mode == "audit" and decision == "fail":
        print(
            "[gate] mode=audit — reporting failure but NOT blocking deployment",
            file=sys.stderr,
        )

    # ── Write outputs ────────────────────────────────────────────────────────
    _write_result(
        out_dir,
        decision=decision,
        mode=mode,
        counts=counts_unwaived,
        violations=violations,
        waivers_applied=waivers_applied,
        findings=all_findings,
    )

    print(
        f"[gate] Wrote gate-result.json ({total_all} findings) "
        f"and findings.json to {out_dir}",
        file=sys.stderr,
    )
    print(f"[gate] Decision: {decision.upper()}", file=sys.stderr)

    # Exit 1 only in enforce mode with violations
    if decision == "fail" and mode == "enforce":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
