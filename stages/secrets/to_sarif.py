#!/usr/bin/env python3
"""Convert Gitleaks JSON report to SARIF 2.1.0 for the DevSecOps pipeline.

Usage:
    python3 to_sarif.py <gitleaks_json_file> <target_rel> <repo_root> <tool_version> <output_sarif_file>
"""
from __future__ import annotations

import json
import os
import sys
from typing import Any

CLOUD_PROVIDER_RULES = {
    "aws-access-token",
    "aws-secret-access-key",
    "gcp-service-account",
    "gcp-service-account-credentials",
    "azure-client-secret",
    "azure-service-principal",
    "github-pat",
    "github-fine-grained-pat",
    "github-oauth",
}


def normalize_repo_rel_path(raw_file: str, target_rel: str, repo_root: str) -> str:
    """Normalize file path to repo-relative path with forward slashes."""
    if not raw_file:
        return ""

    norm_file = raw_file.replace("\\", "/")
    norm_target = target_rel.replace("\\", "/").strip("./")

    # If raw_file is absolute or has Windows drive letter
    if os.path.isabs(raw_file) or (len(raw_file) > 1 and raw_file[1] == ":"):
        try:
            rel = os.path.relpath(raw_file, repo_root)
            return rel.replace("\\", "/").lstrip("/")
        except Exception:
            return norm_file.lstrip("/")

    # Strip leading ./ or /
    while norm_file.startswith("./") or norm_file.startswith("/"):
        if norm_file.startswith("./"):
            norm_file = norm_file[2:]
        elif norm_file.startswith("/"):
            norm_file = norm_file[1:]

    if not norm_target or norm_target == ".":
        return norm_file

    if norm_file == norm_target or norm_file.startswith(norm_target + "/"):
        return norm_file

    return f"{norm_target}/{norm_file}"


def convert_gitleaks_to_sarif(
    input_file: str,
    target_rel: str,
    repo_root: str,
    tool_version: str,
) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    if os.path.exists(input_file):
        try:
            with open(input_file, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if content:
                    parsed = json.loads(content)
                    if isinstance(parsed, list):
                        findings = parsed
        except Exception:
            findings = []

    results: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int]] = set()

    for item in findings:
        if not isinstance(item, dict):
            continue

        rule_id = str(item.get("RuleID") or item.get("rule_id") or "generic-secret").strip()
        description = str(item.get("Description") or item.get("description") or f"Secret matching rule {rule_id}").strip()
        raw_file = str(item.get("File") or item.get("file") or "").strip()

        repo_rel_path = normalize_repo_rel_path(raw_file, target_rel, repo_root)
        if not repo_rel_path:
            repo_rel_path = "UNKNOWN"

        raw_line = item.get("StartLine") or item.get("start_line") or item.get("Line") or 1
        try:
            start_line = int(raw_line)
        except (ValueError, TypeError):
            start_line = 1
        if start_line < 1:
            start_line = 1

        dedup_key = (rule_id, repo_rel_path, start_line)
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        # Cloud provider rule IDs -> Critical, all others -> High
        if rule_id.lower() in CLOUD_PROVIDER_RULES:
            severity = "Critical"
        else:
            severity = "High"

        # Redact: NEVER include Secret or Match values in output
        message_text = f"{description} detected at {repo_rel_path}:{start_line} [REDACTED]"

        result = {
            "ruleId": rule_id,
            "level": "error",
            "message": {
                "text": message_text
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": repo_rel_path
                        },
                        "region": {
                            "startLine": start_line
                        }
                    }
                }
            ],
            "properties": {
                "severity": severity,
                "category": "secret",
                "raw_severity": "HIGH",
                "fix": "Rotate this credential immediately. Remove from git history (use git filter-repo or BFG Repo-Cleaner). Load secrets from environment variables or a secrets manager.",
                "confidence": "high"
            }
        }
        results.append(result)

    # Sort results by (uri, startLine, ruleId)
    results.sort(
        key=lambda r: (
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            r["locations"][0]["physicalLocation"]["region"]["startLine"],
            r["ruleId"],
        )
    )

    driver: dict[str, Any] = {
        "name": "gitleaks",
        "version": tool_version,
        "informationUri": "https://github.com/gitleaks/gitleaks",
    }

    rules: list[dict[str, Any]] = []
    seen_rules: set[str] = set()
    for r in results:
        rid = r["ruleId"]
        if rid not in seen_rules:
            seen_rules.add(rid)
            rules.append({
                "id": rid,
                "name": rid,
                "shortDescription": {"text": f"Gitleaks rule {rid}"}
            })
    rules.sort(key=lambda x: str(x["id"]))
    if rules:
        driver["rules"] = rules

    sarif: dict[str, Any] = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": driver
                },
                "results": results
            }
        ]
    }
    return sarif


def main() -> int:
    if len(sys.argv) != 6:
        print(
            "Usage: python3 to_sarif.py <gitleaks_json_file> <target_rel> <repo_root> <tool_version> <output_sarif_file>",
            file=sys.stderr,
        )
        return 2

    input_file = sys.argv[1]
    target_rel = sys.argv[2]
    repo_root = sys.argv[3]
    tool_version = sys.argv[4]
    output_sarif = sys.argv[5]

    try:
        sarif = convert_gitleaks_to_sarif(input_file, target_rel, repo_root, tool_version)
        os.makedirs(os.path.dirname(os.path.abspath(output_sarif)), exist_ok=True)
        with open(output_sarif, "w", encoding="utf-8") as f:
            json.dump(sarif, f, indent=2)
            f.write("\n")
        return 0
    except Exception as exc:
        print(f"ERROR: Failed to convert Gitleaks report to SARIF: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
