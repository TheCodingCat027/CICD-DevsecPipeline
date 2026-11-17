#!/usr/bin/env python3
"""
stages/iac/run_checkov.py
Helper script to run Checkov and capture JSON output reliably.

Usage:
    python3 run_checkov.py <target_dir> <output_json_file>
"""
from __future__ import annotations
import json
import os
import subprocess
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <target_dir> <output_json_file>", file=sys.stderr)
        return 2

    target_dir = sys.argv[1]
    output_file = sys.argv[2]

    # Find the checkov executable in the same Python environment
    python_bin = sys.executable
    python_dir = Path(python_bin).parent

    # Try to find checkov script
    checkov_candidates = [
        python_dir / "checkov",
        python_dir / "checkov.exe",
        python_dir / "checkov.cmd",
    ]
    checkov_script = None
    for c in checkov_candidates:
        if c.exists():
            checkov_script = str(c)
            break

    # Run checkov as a subprocess using the same Python interpreter
    # This avoids sys.exit() issues with direct import
    cmd = [
        python_bin, "-c",
        (
            "import sys, json; "
            "sys.argv = ['checkov', '--directory', sys.argv[1], '--framework', 'dockerfile', "
            "'--output', 'json', '--quiet', '--compact']; "
            "from checkov.main import Checkov; c = Checkov(); c.run()"
        ),
        target_dir,
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )
    except subprocess.TimeoutExpired:
        print("ERROR: Checkov timed out", file=sys.stderr)
        Path(output_file).write_text("[]", encoding="utf-8")
        return 1
    except Exception as e:
        print(f"ERROR: Failed to run Checkov: {e}", file=sys.stderr)
        Path(output_file).write_text("[]", encoding="utf-8")
        return 1

    stdout = result.stdout.strip()

    # Checkov exits 1 when checks fail (normal), 0 when all pass, >1 on error
    if result.returncode > 1:
        print(f"ERROR: Checkov exited {result.returncode}", file=sys.stderr)
        if result.stderr:
            print(result.stderr[:1000], file=sys.stderr)
        Path(output_file).write_text("[]", encoding="utf-8")
        return result.returncode

    if result.stderr:
        print(result.stderr[:500], file=sys.stderr)

    # Validate it's JSON
    if stdout:
        try:
            json.loads(stdout)
            Path(output_file).write_text(stdout, encoding="utf-8")
        except json.JSONDecodeError:
            # Try to find JSON portion
            for line in stdout.split("\n"):
                line = line.strip()
                if line.startswith("{") or line.startswith("["):
                    try:
                        json.loads(line)
                        Path(output_file).write_text(line, encoding="utf-8")
                        break
                    except json.JSONDecodeError:
                        continue
            else:
                print(f"WARNING: Checkov output not valid JSON, writing empty", file=sys.stderr)
                Path(output_file).write_text("[]", encoding="utf-8")
    else:
        print("WARNING: Checkov produced no stdout output", file=sys.stderr)
        Path(output_file).write_text("[]", encoding="utf-8")

    # Read and report finding count
    try:
        data = json.loads(Path(output_file).read_text(encoding="utf-8"))
        if isinstance(data, dict) and "results" in data:
            failed = data["results"].get("failed_checks", [])
            print(f"[checkov] {len(failed)} failed check(s)", file=sys.stderr)
        elif isinstance(data, list):
            total = sum(
                len(item.get("results", {}).get("failed_checks", []))
                for item in data
                if isinstance(item, dict)
            )
            print(f"[checkov] {total} failed check(s) total", file=sys.stderr)
    except Exception:
        pass

    return 0


if __name__ == "__main__":
    sys.exit(main())
