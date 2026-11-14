"""
Drift-protection test: verifies that every entry in seeded-vulnerabilities.json
points to a file that exists and contains the expected planted pattern.

If a seeded vulnerability drifts (file moved, pattern changed), this test fails,
alerting the team before Phase 5 evaluation is affected.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent.parent
SEEDED_FILE = REPO_ROOT / "demo-app" / "seeded-vulnerabilities.json"

# Pattern that must exist somewhere in the stated file for each vulnerability ID.
# These match the actual planted strings in demo-app/vulnerable/.
PATTERNS: dict[str, str] = {
    "V1":  "AKIAIOSFODNN7EXAMPLE",
    "V2":  "username = '",           # SQL concat pattern
    "V3a": "Flask==1.0.2",
    "V3b": "Jinja2==2.10",
    "V3c": "PyYAML==5.1",
    "V4":  "FROM python:3.11-slim",
    "V5":  "FROM python:3.11-slim",
    "V6":  "hashlib.md5",
    "V7":  "debug=True",
    "V8":  "FROM python:",
}


def _load_seeded() -> dict:
    with open(SEEDED_FILE, encoding="utf-8") as f:
        return json.load(f)


def test_seeded_file_exists() -> None:
    """The seeded-vulnerabilities.json file must exist."""
    assert SEEDED_FILE.exists(), f"seeded-vulnerabilities.json not found at {SEEDED_FILE}"


def test_all_files_exist() -> None:
    """Every file listed in the seeded vulnerability list must exist."""
    data = _load_seeded()
    missing = []
    for vuln in data["vulnerabilities"]:
        filepath = REPO_ROOT / vuln["file"]
        if not filepath.exists():
            missing.append(vuln["file"])
    assert not missing, (
        "The following files listed in seeded-vulnerabilities.json do not exist:\n"
        + "\n".join(f"  {f}" for f in missing)
    )


@pytest.mark.parametrize(
    "vid,pattern",
    [(vid, pat) for vid, pat in PATTERNS.items()],
)
def test_pattern_in_file(vid: str, pattern: str) -> None:
    """Check that the planted pattern exists in the stated file."""
    data = _load_seeded()
    # Find matching entry
    matching = [v for v in data["vulnerabilities"] if v["id"] == vid]
    assert matching, f"No vulnerability with id '{vid}' found in seeded-vulnerabilities.json"
    vuln = matching[0]

    filepath = REPO_ROOT / vuln["file"]
    if not filepath.exists():
        pytest.skip(f"File {vuln['file']} does not exist — covered by test_all_files_exist")

    content = filepath.read_text(encoding="utf-8")
    assert pattern in content, (
        f"{vid}: pattern '{pattern}' not found in {vuln['file']}\n"
        f"This means the seeded vulnerability list has drifted from the actual code.\n"
        f"Update either the code or seeded-vulnerabilities.json."
    )

