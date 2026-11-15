#!/usr/bin/env python3
"""
stages/sca/to_sarif.py
Convert Trivy filesystem JSON output to SARIF 2.1.0 conforming to contracts/sarif-profile.md.

Usage:
    python3 to_sarif.py <trivy_json_file> <target_rel> <repo_root> <tool_version> <output_sarif_file>
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Any

SEVERITY_MAP: dict[str, str] = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "UNKNOWN": "Low",
}


def compute_uri(target_rel: str, result_target: str) -> str:
    """Normalize and combine target_rel and Trivy Result Target into a repo-relative URI."""
    t_rel = target_rel.replace("\\", "/").strip("/.")
    r_tgt = result_target.replace("\\", "/").strip("/.")

    if not t_rel:
        return r_tgt
    if not r_tgt:
        return t_rel
    if r_tgt.startswith(t_rel + "/"):
        return r_tgt
    if r_tgt == t_rel:
        return t_rel
    return f"{t_rel}/{r_tgt}"


def find_manifest_line(file_path: Path, pkg_name: str) -> int:
    """Search for the 1-based line number where pkg_name is declared in the manifest file."""
    if not file_path.is_file():
        return 0
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for idx, line in enumerate(f, start=1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                # Match package name at beginning of line (e.g. Flask==1.0.2, flask >= 1.0)
                pattern = rf"^{re.escape(pkg_name)}([=<>!~;@\s]|$)"
                if re.match(pattern, stripped, re.IGNORECASE):
                    return idx
    except Exception:
        return 0
    return 0


def main() -> int:
    if len(sys.argv) != 6:
        print(
            f"Usage: {sys.argv[0]} <trivy_json_file> <target_rel> <repo_root> <tool_version> <output_sarif_file>",
            file=sys.stderr,
        )
        return 2

    trivy_json_path = Path(sys.argv[1])
    target_rel = sys.argv[2]
    repo_root = Path(sys.argv[3]).resolve()
    tool_version = sys.argv[4]
    output_sarif_path = Path(sys.argv[5])

    if not trivy_json_path.is_file():
        print(f"ERROR: Trivy JSON file not found: {trivy_json_path}", file=sys.stderr)
        return 1

    try:
        with open(trivy_json_path, "r", encoding="utf-8") as f:
            trivy_data = json.load(f)
    except Exception as e:
        print(f"ERROR: Failed to parse Trivy JSON: {e}", file=sys.stderr)
        return 1

    results: list[dict[str, Any]] = []
    rules_map: dict[str, dict[str, Any]] = {}
    seen_vulns: set[tuple[str, str]] = set()

    trivy_results = trivy_data.get("Results") or []
    for res in trivy_results:
        raw_target = res.get("Target", "")
        uri = compute_uri(target_rel, raw_target)
        manifest_path = repo_root / uri

        vulnerabilities = res.get("Vulnerabilities") or []
        for vuln in vulnerabilities:
            vuln_id = vuln.get("VulnerabilityID", "")
            if not vuln_id:
                continue

            # Dedup: same (VulnerabilityID + Target file path) -> keep one result
            dedup_key = (vuln_id, uri)
            if dedup_key in seen_vulns:
                continue
            seen_vulns.add(dedup_key)

            pkg_name = vuln.get("PkgName", "")
            installed_version = vuln.get("InstalledVersion", "")
            fixed_version = vuln.get("FixedVersion") or ""
            fix_available = bool(fixed_version)

            raw_severity = vuln.get("Severity", "UNKNOWN")
            severity = SEVERITY_MAP.get(str(raw_severity).upper(), "Low")

            # SARIF level: error for Critical/High, warning for Medium, note for Low
            if severity in ("Critical", "High"):
                level = "error"
            elif severity == "Medium":
                level = "warning"
            else:
                level = "note"

            title = vuln.get("Title", "")
            description = vuln.get("Description", "")
            desc_snippet = f" {description[:300]}" if description else ""
            msg_text = f"{title or vuln_id}: {pkg_name} {installed_version} is affected.{desc_snippet}".strip()

            start_line = find_manifest_line(manifest_path, pkg_name)

            # Properties conforming strictly to contracts/finding.schema.json
            properties: dict[str, Any] = {
                "severity": severity,
                "category": "sca",
                "raw_severity": str(raw_severity),
                "cve_id": vuln_id,
                "package": pkg_name,
                "installed_version": installed_version,
                "fixed_version": fixed_version,
                "fix_available": fix_available,
                "fix": (
                    f"Upgrade {pkg_name} from {installed_version} to {fixed_version}"
                    if fix_available
                    else "No fixed version available yet"
                ),
            }

            cwe_ids = vuln.get("CweIDs")
            if cwe_ids and isinstance(cwe_ids, list) and len(cwe_ids) > 0:
                properties["cwe"] = str(cwe_ids[0])

            physical_location: dict[str, Any] = {
                "artifactLocation": {
                    "uri": uri,
                }
            }
            if start_line > 0:
                physical_location["region"] = {
                    "startLine": start_line,
                }

            result_entry: dict[str, Any] = {
                "ruleId": vuln_id,
                "level": level,
                "message": {
                    "text": msg_text,
                },
                "locations": [
                    {
                        "physicalLocation": physical_location,
                    }
                ],
                "properties": properties,
            }
            results.append(result_entry)

            if vuln_id not in rules_map:
                rules_map[vuln_id] = {
                    "id": vuln_id,
                    "name": title or vuln_id,
                    "shortDescription": {
                        "text": description[:300] if description else (title or vuln_id),
                    },
                }

    # Sort results deterministically by: (uri, ruleId, package)
    results.sort(
        key=lambda r: (
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            r["ruleId"],
            r["properties"].get("package", ""),
        )
    )

    driver_obj: dict[str, Any] = {
        "name": "trivy",
        "version": tool_version,
    }
    if rules_map:
        driver_obj["rules"] = list(rules_map.values())

    sarif_output: dict[str, Any] = {
        "version": "2.1.0",
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
        "runs": [
            {
                "tool": {
                    "driver": driver_obj,
                },
                "results": results,
            }
        ],
    }

    output_sarif_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_sarif_path, "w", encoding="utf-8") as f:
        json.dump(sarif_output, f, indent=2)

    return 0


if __name__ == "__main__":
    sys.exit(main())
