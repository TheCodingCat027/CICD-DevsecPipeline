#!/usr/bin/env python3
"""
stages/container/run_posture.py
Run posture checks on a Dockerfile and write findings to a JSON file.

Usage:
    python3 run_posture.py <dockerfile_path> <output_json_file>

Checks:
    DSP-IMG-001: No non-root USER instruction (runs as root)
    DSP-IMG-002: Base image uses 'latest' or no version tag
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any


def run_posture_checks(dockerfile_path: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    path = Path(dockerfile_path)
    if not path.is_file():
        return findings

    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines(keepends=True)
    except Exception:
        return findings

    has_nonroot_user = any(
        re.match(r"^\s*USER\s+(?!root\s*$)", line, re.IGNORECASE)
        for line in lines
    )

    has_healthcheck = any(
        re.match(r"^\s*HEALTHCHECK\s+", line, re.IGNORECASE)
        for line in lines
    )

    # Find FROM line number
    from_line_num = 1
    for i, line in enumerate(lines, 1):
        if re.match(r"^\s*FROM\s+", line, re.IGNORECASE):
            from_line_num = i
            break

    # Detect untagged, :latest, or non-digest-pinned base image
    # Catches: FROM ubuntu (no tag), FROM python:latest, FROM python:3.11-slim (no digest/patch)
    def _is_unpinned(from_line: str) -> bool:
        line_clean = re.sub(r'\s+AS\s+\S+\s*$', '', from_line.strip(), flags=re.IGNORECASE)
        m = re.match(r'^\s*FROM\s+(\S+)', line_clean, re.IGNORECASE)
        if not m:
            return False
        image_ref = m.group(1)
        if '@sha256:' in image_ref:
            return False  # digest-pinned
        if ':' not in image_ref:
            return True   # no tag at all
        tag = image_ref.split(':', 1)[1]
        if tag.lower() == 'latest':
            return True
        # Unpinned if numeric version has fewer than 3 segments (e.g. 3.11, 3.11-slim)
        numeric_part = re.match(r'^(\d[\d.]*)', tag)
        if numeric_part:
            version_segments = numeric_part.group(1).split('.')
            if len(version_segments) < 3:
                return True  # e.g. 3.11-slim: missing patch version
        return False

    uses_untagged = any(
        _is_unpinned(line)
        for line in lines
        if re.match(r"^\s*FROM\s+", line, re.IGNORECASE)
    )

    # DSP-IMG-001: running as root
    if not has_nonroot_user:
        findings.append({
            "ruleId": "DSP-IMG-001",
            "severity": "High",
            "raw_severity": "HIGH",
            "message": "Container image runs as root: no non-root USER instruction found in Dockerfile",
            "fix": "Add 'RUN useradd -m appuser && USER appuser' before the CMD instruction",
            "line": from_line_num,
        })

    # DSP-IMG-002: untagged or :latest base image
    if uses_untagged:
        findings.append({
            "ruleId": "DSP-IMG-002",
            "severity": "Medium",
            "raw_severity": "MEDIUM",
            "message": "Base image uses 'latest' or no version tag: image is not pinned to a specific version",
            "fix": "Pin the base image to an exact version e.g. 'python:3.11.11-slim-bookworm'",
            "line": from_line_num,
        })

    return findings


def main() -> int:
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <dockerfile_path> <output_json_file>", file=sys.stderr)
        return 2

    dockerfile_path = sys.argv[1]
    output_file = sys.argv[2]

    findings = run_posture_checks(dockerfile_path)

    Path(output_file).parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2)

    print(f"[posture] {len(findings)} finding(s) for {dockerfile_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
