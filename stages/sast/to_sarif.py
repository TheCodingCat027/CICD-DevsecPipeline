#!/usr/bin/env python3
"""
Convert Semgrep JSON output to SARIF 2.1.0 format conforming to
contracts/sarif-profile.md and contracts/finding.schema.json.
"""
from __future__ import annotations

import json
import os
import sys
from typing import Any

SEVERITY_MAP: dict[str, tuple[str, str]] = {
    "ERROR": ("High", "error"),
    "WARNING": ("Medium", "warning"),
    "INFO": ("Low", "note"),
}


def normalize_path(raw_path: str, target_rel: str, repo_root: str) -> str:
    """Normalize file path to repo-relative forward-slash path."""
    raw_path_str = str(raw_path).replace("\\", "/")
    repo_root_str = str(repo_root).replace("\\", "/")

    if os.path.isabs(raw_path_str):
        try:
            rel = os.path.relpath(raw_path_str, repo_root_str)
            return rel.replace("\\", "/").lstrip("./")
        except ValueError:
            return raw_path_str

    # If raw_path already exists directly under repo_root
    if os.path.exists(os.path.join(repo_root, raw_path_str)):
        return os.path.normpath(raw_path_str).replace("\\", "/").lstrip("./")

    # If target_rel is provided, check if joining resolves to existing file
    if target_rel:
        clean_target = target_rel.replace("\\", "/").strip("./")
        combined = os.path.join(clean_target, raw_path_str)
        if os.path.exists(os.path.join(repo_root, combined)):
            return os.path.normpath(combined).replace("\\", "/").lstrip("./")
        if not raw_path_str.startswith(clean_target):
            return os.path.normpath(combined).replace("\\", "/").lstrip("./")

    return os.path.normpath(raw_path_str).replace("\\", "/").lstrip("./")


def convert_semgrep_to_sarif(
    semgrep_json_path: str,
    target_rel: str,
    repo_root: str,
    tool_version: str,
    output_sarif_path: str,
) -> None:
    with open(semgrep_json_path, encoding="utf-8") as f:
        data = json.load(f)

    results = data.get("results", [])
    parsed_results: list[dict[str, Any]] = []

    for item in results:
        check_id = item.get("check_id") or "unknown-rule"
        path = item.get("path", "")
        norm_uri = normalize_path(path, target_rel, repo_root)

        start_line = item.get("start", {}).get("line", 1)
        if not isinstance(start_line, int) or start_line < 0:
            start_line = 1

        extra = item.get("extra", {})
        message_text = extra.get("message") or "Semgrep finding"

        raw_severity = extra.get("severity") or "UNKNOWN"
        raw_sev_str = str(raw_severity).strip().upper()
        canonical_sev, sarif_level = SEVERITY_MAP.get(raw_sev_str, ("Low", "note"))

        metadata = extra.get("metadata", {})

        # Properties conform strictly to finding.schema.json
        props: dict[str, Any] = {
            "severity": canonical_sev,
            "category": "sast",
            "raw_severity": raw_severity,
        }

        # CWE
        cwe_val = metadata.get("cwe")
        if isinstance(cwe_val, list) and cwe_val:
            props["cwe"] = str(cwe_val[0])
        elif isinstance(cwe_val, str) and cwe_val:
            props["cwe"] = cwe_val

        # Confidence (must be "high", "medium", or "low")
        conf_val = metadata.get("confidence")
        if isinstance(conf_val, str):
            conf_clean = conf_val.strip().lower()
            if conf_clean in {"high", "medium", "low"}:
                props["confidence"] = conf_clean

        # Fix / Remediation
        remediation = metadata.get("remediation") or extra.get("fix")
        if remediation and isinstance(remediation, str):
            props["fix"] = remediation
            props["fix_available"] = True
        else:
            props["fix"] = None
            props["fix_available"] = False

        # CVE if present in metadata
        cve_val = metadata.get("cve")
        if isinstance(cve_val, list) and cve_val:
            props["cve_id"] = str(cve_val[0])
        elif isinstance(cve_val, str) and cve_val:
            props["cve_id"] = cve_val

        sarif_result: dict[str, Any] = {
            "ruleId": check_id,
            "level": sarif_level,
            "message": {
                "text": message_text,
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": norm_uri,
                        },
                        "region": {
                            "startLine": start_line,
                        },
                    },
                },
            ],
            "properties": props,
        }
        parsed_results.append(sarif_result)

    # Dedup: same (check_id, normalized_path, start_line) -> keep one
    seen: set[tuple[str, str, int]] = set()
    deduped_results: list[dict[str, Any]] = []

    for res in parsed_results:
        uri = res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        line = res["locations"][0]["physicalLocation"]["region"]["startLine"]
        rule = res["ruleId"]
        key = (rule, uri, line)
        if key in seen:
            continue
        seen.add(key)
        deduped_results.append(res)

    # Sort: (uri, startLine, ruleId)
    deduped_results.sort(
        key=lambda r: (
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            r["locations"][0]["physicalLocation"]["region"]["startLine"],
            r["ruleId"],
        )
    )

    sarif_doc = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "semgrep",
                        "version": tool_version,
                    },
                },
                "results": deduped_results,
            },
        ],
    }

    out_dir = os.path.dirname(output_sarif_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    with open(output_sarif_path, "w", encoding="utf-8") as f:
        json.dump(sarif_doc, f, indent=2)


def main() -> int:
    if len(sys.argv) != 6:
        print(
            f"Usage: {sys.argv[0]} <semgrep_json_file> <target_rel> <repo_root> <tool_version> <output_sarif_file>",
            file=sys.stderr,
        )
        return 2

    semgrep_json_file = sys.argv[1]
    target_rel = sys.argv[2]
    repo_root = sys.argv[3]
    tool_version = sys.argv[4]
    output_sarif_file = sys.argv[5]

    try:
        convert_semgrep_to_sarif(
            semgrep_json_file,
            target_rel,
            repo_root,
            tool_version,
            output_sarif_file,
        )
        return 0
    except Exception as e:
        print(f"ERROR converting Semgrep JSON to SARIF: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
