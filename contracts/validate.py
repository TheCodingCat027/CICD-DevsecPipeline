#!/usr/bin/env python3
"""
contracts/validate.py - SARIF and policy validator for the DevSecOps pipeline.

Usage:
    python contracts/validate.py <file-or-directory> [--stage NAME] [--json]
    python contracts/validate.py --policy <file>

Exit codes:
    0 - valid
    1 - invalid (prints errors with JSON-pointer-like paths)
    2 - usage error
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

try:
    import jsonschema
    import yaml
except ImportError as e:
    print(
        f"ERROR: Missing dependency: {e}. "
        "Run: pip install -r contracts/requirements.txt",
        file=sys.stderr,
    )
    sys.exit(2)

# ── Paths ─────────────────────────────────────────────────────────────────────
_HERE = Path(__file__).parent
_FINDING_SCHEMA_PATH = _HERE / "finding.schema.json"
_POLICY_SCHEMA_PATH = _HERE / "policy.schema.json"

# ── Schema loading ─────────────────────────────────────────────────────────────
def _load_json(path: Path) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _get_finding_schema() -> dict:
    return _load_json(_FINDING_SCHEMA_PATH)


def _get_policy_schema() -> dict:
    return _load_json(_POLICY_SCHEMA_PATH)


# ── Constants ──────────────────────────────────────────────────────────────────
VALID_SEVERITIES = {"Critical", "High", "Medium", "Low"}
VALID_CATEGORIES = {"secret", "sast", "sca", "iac", "container", "dast"}
VALID_STAGES = {"secrets", "sast", "sca", "iac", "container", "sbom", "dast"}

# categories allowed per stage
STAGE_CATEGORIES: dict[str, set[str]] = {
    "secrets":   {"secret"},
    "sast":      {"sast"},
    "sca":       {"sca"},
    "iac":       {"iac"},
    "container": {"container", "sca"},
    "sbom":      set(),   # SBOM emits no findings; any result is unexpected
    "dast":      {"dast"},
}

# ── SARIF structural validation ────────────────────────────────────────────────
def _validate_sarif_structure(data: dict, path_prefix: str = "") -> list[str]:
    """Validate SARIF 2.1.0 structure per the stage-interface contract.

    Returns a list of error strings (empty list = valid).
    """
    errors: list[str] = []

    def err(pointer: str, msg: str) -> None:
        errors.append(f"{path_prefix}{pointer}: {msg}")

    # Top-level version
    if data.get("version") != "2.1.0":
        err("/version", f"must be '2.1.0', got {data.get('version')!r}")

    # runs array
    runs = data.get("runs")
    if not isinstance(runs, list) or len(runs) != 1:
        err("/runs", "must be an array with exactly one run")
        return errors  # can't validate further without a valid run

    run = runs[0]

    # tool.driver
    tool = run.get("tool", {})
    driver = tool.get("driver", {})
    if not isinstance(driver.get("name"), str) or not driver["name"]:
        err("/runs/0/tool/driver/name", "must be a non-empty string")
    if not isinstance(driver.get("version"), str) or not driver["version"]:
        err(
            "/runs/0/tool/driver/version",
            "must be a non-empty string (pin your tool version!)",
        )

    # results
    results = run.get("results", [])
    if not isinstance(results, list):
        err("/runs/0/results", "must be an array")
        return errors

    for i, result in enumerate(results):
        rp = f"/runs/0/results/{i}"

        if not isinstance(result.get("ruleId"), str) or not result["ruleId"]:
            err(f"{rp}/ruleId", "must be a non-empty string")

        if result.get("level") not in {"error", "warning", "note"}:
            err(
                f"{rp}/level",
                f"must be one of error/warning/note, got {result.get('level')!r}",
            )

        msg = result.get("message", {})
        if not isinstance(msg.get("text"), str) or not msg["text"]:
            err(f"{rp}/message/text", "must be a non-empty string")

        locations = result.get("locations", [])
        if not isinstance(locations, list) or len(locations) == 0:
            err(
                f"{rp}/locations",
                "must be a non-empty array with at least one location",
            )
        else:
            loc = locations[0]
            pl = loc.get("physicalLocation", {})
            al = pl.get("artifactLocation", {})
            if not isinstance(al.get("uri"), str) or not al["uri"]:
                err(
                    f"{rp}/locations/0/physicalLocation/artifactLocation/uri",
                    "must be a non-empty string",
                )

        props = result.get("properties", {})
        if props.get("severity") not in VALID_SEVERITIES:
            err(
                f"{rp}/properties/severity",
                f"must be one of {sorted(VALID_SEVERITIES)}, got {props.get('severity')!r}",
            )

        if props.get("category") not in VALID_CATEGORIES:
            err(
                f"{rp}/properties/category",
                f"must be one of {sorted(VALID_CATEGORIES)}, got {props.get('category')!r}",
            )

    return errors


# ── Finding extraction ─────────────────────────────────────────────────────────
def extract_findings(sarif_dict: dict) -> list[dict]:
    """Extract normalized findings from a SARIF dict.

    **Stable public API** — P4's normalizer imports and calls this function.
    Signature: ``extract_findings(sarif_dict: dict) -> list[dict]``

    Each returned dict is a normalized finding per finding.schema.json.
    Optional fields are included only when present in the SARIF result properties.
    The ``stage`` field is left as an empty string; callers fill it from context.
    """
    findings: list[dict] = []
    runs = sarif_dict.get("runs", [])
    if not runs:
        return findings

    run = runs[0]
    tool_name = run.get("tool", {}).get("driver", {}).get("name", "unknown")

    for result in run.get("results", []):
        props = result.get("properties", {})
        locations = result.get("locations", [{}])
        loc = locations[0] if locations else {}
        pl = loc.get("physicalLocation", {})
        al = pl.get("artifactLocation", {})
        region = pl.get("region", {})

        file_uri = al.get("uri", "")
        line = region.get("startLine", 0)
        rule_id = result.get("ruleId", "")
        severity = props.get("severity", "Low")

        # Stable fingerprint: sha256(tool|rule_id|file|line)
        fingerprint_input = f"{tool_name}|{rule_id}|{file_uri}|{line}"
        finding_id = hashlib.sha256(fingerprint_input.encode()).hexdigest()

        finding: dict[str, Any] = {
            "id": finding_id,
            "tool": tool_name,
            "stage": "",   # caller fills in from context
            "category": props.get("category", ""),
            "rule_id": rule_id,
            "severity": severity,
            "file": file_uri,
            "line": line,
            "description": result.get("message", {}).get("text", ""),
            "fix": props.get("fix"),
        }

        # Optional fields — include only when present in SARIF properties
        for opt_field in (
            "cve_id", "cwe", "package", "installed_version",
            "fixed_version", "fix_available", "confidence",
            "help_uri", "raw_severity",
        ):
            if opt_field in props:
                finding[opt_field] = props[opt_field]

        findings.append(finding)

    return findings


# ── Finding validation ─────────────────────────────────────────────────────────
def _validate_findings(findings: list[dict], stage: str | None = None) -> list[str]:
    """Validate extracted findings against finding.schema.json."""
    errors: list[str] = []
    schema = _get_finding_schema()
    validator_cls = jsonschema.Draft202012Validator

    for i, finding in enumerate(findings):
        # Fill in stage for schema validation purposes
        f = {**finding, "stage": stage or finding.get("stage", "secrets")}
        for ve in validator_cls(schema).iter_errors(f):
            path = "".join(f"/{p}" for p in ve.absolute_path)
            errors.append(f"/findings/{i}{path}: {ve.message}")

    return errors


# ── Stage-category check ───────────────────────────────────────────────────────
def _check_stage_categories(findings: list[dict], stage: str) -> list[str]:
    """Check that each finding's category is valid for the given stage."""
    errors: list[str] = []
    allowed = STAGE_CATEGORIES.get(stage, set())

    for i, finding in enumerate(findings):
        cat = finding.get("category", "")
        if cat and cat not in allowed:
            errors.append(
                f"/findings/{i}/category: category '{cat}' is not valid for "
                f"stage '{stage}'. "
                f"Allowed: {sorted(allowed) if allowed else '(none)'}"
            )
    return errors


# ── SARIF file validation ──────────────────────────────────────────────────────
def validate_sarif_file(
    filepath: str | Path,
    stage: str | None = None,
) -> tuple[bool, list[str]]:
    """Validate a SARIF file. Returns ``(is_valid, errors)``."""
    filepath = Path(filepath)
    errors: list[str] = []
    prefix = str(filepath) + ":"

    # Parse JSON
    try:
        with open(filepath, encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        return False, [f"{prefix} not valid JSON: {e}"]
    except OSError as e:
        return False, [f"{prefix} cannot read file: {e}"]

    # Validate SARIF structure
    struct_errors = _validate_sarif_structure(data, prefix)
    errors.extend(struct_errors)

    # Stage filename check
    if stage and filepath.stem != stage:
        errors.append(
            f"{prefix} filename must be '{stage}.sarif', got '{filepath.name}'"
        )

    if not struct_errors:
        findings = extract_findings(data)
        find_errors = _validate_findings(findings, stage)
        errors.extend(find_errors)

        if stage:
            cat_errors = _check_stage_categories(findings, stage)
            errors.extend(cat_errors)

    return len(errors) == 0, errors


# ── Policy validation ───────────────────────────────────────────────────────────
def validate_policy_file(filepath: str | Path) -> tuple[bool, list[str]]:
    """Validate a security-policy.yaml against policy.schema.json."""
    filepath = Path(filepath)
    errors: list[str] = []

    try:
        with open(filepath, encoding="utf-8") as f:
            policy_data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        return False, [f"{filepath}: YAML parse error: {e}"]
    except OSError as e:
        return False, [f"{filepath}: cannot read file: {e}"]

    if not isinstance(policy_data, dict):
        return False, [f"{filepath}: policy must be a YAML mapping"]

    schema = _get_policy_schema()
    validator_cls = jsonschema.Draft202012Validator
    for ve in validator_cls(schema).iter_errors(policy_data):
        path = "".join(f"/{p}" for p in ve.absolute_path)
        errors.append(f"{filepath}:{path}: {ve.message}")

    return len(errors) == 0, errors


# ── Directory validation ────────────────────────────────────────────────────────
def validate_directory(dirpath: str | Path) -> tuple[bool, dict[str, list[str]]]:
    """Validate all *.sarif files directly inside *dirpath* (not recursing into invalid/)."""
    dirpath = Path(dirpath)
    all_errors: dict[str, list[str]] = {}

    sarif_files = sorted(dirpath.glob("*.sarif"))
    for f in sarif_files:
        stage_name = f.stem
        stage = stage_name if stage_name in VALID_STAGES else None
        valid, errs = validate_sarif_file(f, stage=stage)
        if not valid:
            all_errors[str(f)] = errs

    return len(all_errors) == 0, all_errors


# ── CLI ─────────────────────────────────────────────────────────────────────────
def main(argv: list[str] | None = None) -> int:  # noqa: C901
    parser = argparse.ArgumentParser(
        description="Validate SARIF files and security policy for the DevSecOps pipeline",
    )
    parser.add_argument(
        "target",
        nargs="?",
        help="SARIF file or directory containing *.sarif files",
    )
    parser.add_argument("--stage", help="Stage name (must match filename stem)")
    parser.add_argument(
        "--json", dest="json_out", action="store_true",
        help="Output machine-readable JSON result",
    )
    parser.add_argument("--policy", help="Validate a security-policy.yaml instead")

    args = parser.parse_args(argv)

    # ── Policy mode ────────────────────────────────────────────────────────────
    if args.policy:
        valid, errors = validate_policy_file(args.policy)
        if args.json_out:
            print(json.dumps({"valid": valid, "errors": errors, "file": args.policy}, indent=2))
        elif valid:
            print(f"[OK] Policy file is valid: {args.policy}")
        else:
            print(f"[INVALID] Policy file: {args.policy}", file=sys.stderr)
            for e in errors:
                print(f"  {e}", file=sys.stderr)
        return 0 if valid else 1

    if not args.target:
        parser.print_help(sys.stderr)
        return 2

    target = Path(args.target)

    # ── Directory mode ─────────────────────────────────────────────────────────
    if target.is_dir():
        all_valid, all_errors = validate_directory(target)
        total_files = len(list(target.glob("*.sarif")))
        invalid_count = len(all_errors)
        if args.json_out:
            print(json.dumps(
                {
                    "valid": all_valid,
                    "total_files": total_files,
                    "invalid_files": invalid_count,
                    "errors": all_errors,
                },
                indent=2,
            ))
        elif all_valid:
            print(f"[OK] All {total_files} SARIF file(s) in {target} are valid.")
        else:
            print(
                f"[INVALID] {invalid_count}/{total_files} file(s) have errors:",
                file=sys.stderr,
            )
            for filepath, errs in all_errors.items():
                print(f"\n  {filepath}:", file=sys.stderr)
                for e in errs:
                    print(f"    {e}", file=sys.stderr)
        return 0 if all_valid else 1

    # ── Single file mode ───────────────────────────────────────────────────────
    if target.is_file():
        valid, errors = validate_sarif_file(target, stage=args.stage)
        if args.json_out:
            print(json.dumps(
                {"valid": valid, "file": str(target), "stage": args.stage, "errors": errors},
                indent=2,
            ))
        elif valid:
            print(f"[OK] {target} is valid.")
        else:
            print(f"[INVALID] {target}:", file=sys.stderr)
            for e in errors:
                print(f"  {e}", file=sys.stderr)
        return 0 if valid else 1

    print(f"ERROR: {target} is not a file or directory", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())

