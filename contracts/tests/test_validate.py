"""
Tests for contracts/validate.py

Covers:
- All valid samples pass
- All invalid samples fail with expected error fragments
- Baseline policy passes; broken policy fails
- Stage-category check
- CLI exit codes and --json flag
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

# Allow importing validate from the contracts/ directory
REPO_ROOT = Path(__file__).parent.parent.parent
CONTRACTS_DIR = REPO_ROOT / "contracts"
SAMPLES_DIR = CONTRACTS_DIR / "samples"
INVALID_DIR = SAMPLES_DIR / "invalid"
POLICY_FILE = REPO_ROOT / "security-policy.yaml"
VALIDATE_PY = CONTRACTS_DIR / "validate.py"

sys.path.insert(0, str(CONTRACTS_DIR))
import validate  # noqa: E402


# ── Valid samples ──────────────────────────────────────────────────────────────
VALID_STAGES = ["secrets", "sast", "sca", "iac", "container", "sbom", "dast"]


@pytest.mark.parametrize("stage", VALID_STAGES)
def test_valid_sample_passes(stage):
    """Each valid sample in contracts/samples/ must pass validation."""
    sarif_file = SAMPLES_DIR / f"{stage}.sarif"
    assert sarif_file.exists(), f"{sarif_file} does not exist"
    valid, errors = validate.validate_sarif_file(sarif_file, stage=stage)
    assert valid, (
        f"Sample {stage}.sarif should be valid, but got errors:\n"
        + "\n".join(errors)
    )


@pytest.mark.parametrize("stage", VALID_STAGES)
def test_extract_findings_returns_list(stage):
    """extract_findings always returns a list (may be empty for sbom/dast)."""
    sarif_file = SAMPLES_DIR / f"{stage}.sarif"
    with open(sarif_file, encoding="utf-8") as f:
        data = json.load(f)
    findings = validate.extract_findings(data)
    assert isinstance(findings, list)
    # sbom and dast may legitimately have zero findings
    if stage not in ("sbom", "dast"):
        assert len(findings) > 0, (
            f"Stage {stage} should have at least one finding in its sample"
        )


# ── Invalid samples ────────────────────────────────────────────────────────────
INVALID_SAMPLES = {
    "missing-driver-version.sarif": "version",
    "bad-severity-value.sarif": "severity",
    "missing-rule-id.sarif": "ruleId",
    "wrong-sarif-version.sarif": "2.1.0",
    "not-json-at-all.sarif": "JSON",
    "missing-location.sarif": "locations",
}


@pytest.mark.parametrize("filename,expected_fragment", INVALID_SAMPLES.items())
def test_invalid_sample_fails(filename, expected_fragment):
    """Every file in contracts/samples/invalid/ must be rejected."""
    sarif_file = INVALID_DIR / filename
    assert sarif_file.exists(), f"{sarif_file} does not exist"
    valid, errors = validate.validate_sarif_file(sarif_file)
    assert not valid, f"{filename} should be invalid but was accepted"
    all_errors_text = " ".join(errors).lower()
    assert expected_fragment.lower() in all_errors_text, (
        f"{filename}: expected error containing '{expected_fragment}', got:\n"
        + "\n".join(errors)
    )


# ── Policy validation ──────────────────────────────────────────────────────────
def test_baseline_policy_valid():
    """The baseline security-policy.yaml must pass validation."""
    assert POLICY_FILE.exists(), f"Policy file not found: {POLICY_FILE}"
    valid, errors = validate.validate_policy_file(POLICY_FILE)
    assert valid, "Baseline policy should be valid, got:\n" + "\n".join(errors)


def test_broken_policy_fails(tmp_path):
    """A malformed policy must fail validation."""
    import yaml

    broken = {"version": 99, "mode": "invalid-mode"}
    p = tmp_path / "bad-policy.yaml"
    p.write_text(yaml.dump(broken), encoding="utf-8")
    valid, errors = validate.validate_policy_file(str(p))
    assert not valid, "Broken policy should fail validation"
    assert len(errors) > 0


# ── Stage-category check ───────────────────────────────────────────────────────
def test_stage_category_correct():
    """secrets.sarif with stage='secrets' passes category check."""
    sarif_file = SAMPLES_DIR / "secrets.sarif"
    valid, errors = validate.validate_sarif_file(sarif_file, stage="secrets")
    assert valid, f"secrets.sarif with stage=secrets should pass: {errors}"


def test_stage_category_wrong(tmp_path):
    """A SARIF with sast category for the secrets stage must fail."""
    sarif_data = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "semgrep", "version": "1.0.0"}},
                "results": [
                    {
                        "ruleId": "test-rule",
                        "level": "error",
                        "message": {"text": "test finding"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "app.py"},
                                    "region": {"startLine": 1},
                                }
                            }
                        ],
                        "properties": {"severity": "High", "category": "sast"},
                    }
                ],
            }
        ],
    }
    # Must be named secrets.sarif for stage check
    sarif_path = tmp_path / "secrets.sarif"
    sarif_path.write_text(json.dumps(sarif_data), encoding="utf-8")
    valid, errors = validate.validate_sarif_file(sarif_path, stage="secrets")
    assert not valid, "Should fail: sast category not allowed in secrets stage"
    assert any("category" in e for e in errors)


# ── CLI exit codes ─────────────────────────────────────────────────────────────
def _run(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(VALIDATE_PY)] + args,
        capture_output=True,
        text=True,
    )


def test_cli_exit_0_valid_file(tmp_path):
    """CLI exits 0 on a valid file."""
    import shutil

    dst = tmp_path / "sast.sarif"
    shutil.copy(SAMPLES_DIR / "sast.sarif", dst)
    result = _run([str(dst), "--stage", "sast"])
    assert result.returncode == 0, f"Expected 0, got {result.returncode}:\n{result.stderr}"


def test_cli_exit_1_invalid_file(tmp_path):
    """CLI exits 1 on an invalid file."""
    import shutil

    dst = tmp_path / "bad.sarif"
    shutil.copy(INVALID_DIR / "missing-driver-version.sarif", dst)
    result = _run([str(dst)])
    assert result.returncode == 1, f"Expected 1, got {result.returncode}"


def test_cli_exit_2_no_args():
    """CLI exits 2 when given no arguments."""
    result = _run([])
    assert result.returncode == 2, f"Expected 2, got {result.returncode}"


def test_cli_json_output(tmp_path):
    """--json flag produces valid JSON with 'valid' and 'errors' keys."""
    import shutil

    dst = tmp_path / "sast.sarif"
    shutil.copy(SAMPLES_DIR / "sast.sarif", dst)
    result = _run([str(dst), "--json"])
    output = json.loads(result.stdout)
    assert "valid" in output
    assert "errors" in output


def test_cli_directory_valid():
    """CLI validates all SARIF files in contracts/samples/ and exits 0."""
    result = _run([str(SAMPLES_DIR)])
    assert result.returncode == 0, (
        f"Expected exit 0 for valid samples dir:\n{result.stderr}"
    )


def test_cli_policy_valid():
    """CLI --policy validates the baseline policy and exits 0."""
    result = _run(["--policy", str(POLICY_FILE)])
    assert result.returncode == 0, (
        f"Expected exit 0 for valid policy:\n{result.stderr}"
    )

