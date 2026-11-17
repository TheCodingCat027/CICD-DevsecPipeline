#!/usr/bin/env python3
"""
stages/container/to_sarif.py
Convert Trivy image JSON + posture checks to SARIF 2.1.0.

Usage:
    python3 to_sarif.py <trivy_json> <posture_json> <dockerfile_rel> <repo_root> <tool_version> <output_sarif>

posture_json: JSON file with posture findings list [{ruleId, severity, message, fix, line}]
dockerfile_rel: repo-relative path to the Dockerfile (e.g. "demo-app/vulnerable/Dockerfile")
"""
from __future__ import annotations

import json
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


def _sarif_level(severity: str) -> str:
    if severity in ("Critical", "High"):
        return "error"
    if severity == "Medium":
        return "warning"
    return "note"


def main() -> int:
    if len(sys.argv) != 7:
        print(
            f"Usage: {sys.argv[0]} <trivy_json> <posture_json> <dockerfile_rel> <repo_root> <tool_version> <output_sarif>",
            file=sys.stderr,
        )
        return 2

    trivy_json_path = Path(sys.argv[1])
    posture_json_path = Path(sys.argv[2])
    dockerfile_rel = sys.argv[3].replace("\\", "/")
    _repo_root = Path(sys.argv[4]).resolve()
    tool_version = sys.argv[5]
    output_sarif_path = Path(sys.argv[6])

    # Load Trivy JSON
    if not trivy_json_path.is_file():
        print(f"ERROR: Trivy JSON not found: {trivy_json_path}", file=sys.stderr)
        return 1
    try:
        with open(trivy_json_path, "r", encoding="utf-8") as f:
            trivy_data = json.load(f)
    except Exception as e:
        print(f"ERROR: Failed to parse Trivy JSON: {e}", file=sys.stderr)
        return 1

    # Load posture JSON
    posture_findings: list[dict] = []
    if posture_json_path.is_file():
        try:
            with open(posture_json_path, "r", encoding="utf-8") as f:
                posture_findings = json.load(f)
        except Exception as e:
            print(f"WARNING: Failed to parse posture JSON: {e}", file=sys.stderr)

    results: list[dict[str, Any]] = []
    rules_map: dict[str, dict[str, Any]] = {}
    seen_vulns: set[tuple[str, str]] = set()

    # Parse Trivy results
    trivy_results = trivy_data.get("Results") or []
    for res in trivy_results:
        vulnerabilities = res.get("Vulnerabilities") or []
        for vuln in vulnerabilities:
            vuln_id = vuln.get("VulnerabilityID", "")
            if not vuln_id:
                continue

            pkg_name = vuln.get("PkgName", "")
            installed_version = vuln.get("InstalledVersion", "")
            fixed_version = vuln.get("FixedVersion") or ""
            fix_available = bool(fixed_version)

            dedup_key = (vuln_id, pkg_name)
            if dedup_key in seen_vulns:
                continue
            seen_vulns.add(dedup_key)

            raw_severity = vuln.get("Severity", "UNKNOWN")
            severity = SEVERITY_MAP.get(str(raw_severity).upper(), "Low")
            level = _sarif_level(severity)

            title = vuln.get("Title", "")
            description = vuln.get("Description", "")
            desc_snippet = f" {description[:300]}" if description else ""
            msg_text = (
                f"{title or vuln_id}: {pkg_name} {installed_version} in container image is affected.{desc_snippet}".strip()
            )

            props: dict[str, Any] = {
                "severity": severity,
                "category": "container",
                "raw_severity": str(raw_severity),
                "cve_id": vuln_id,
                "package": pkg_name,
                "installed_version": installed_version,
                "fixed_version": fixed_version,
                "fix_available": fix_available,
                "fix": (
                    f"Update base image to get patched {pkg_name} version {fixed_version}"
                    if fix_available
                    else f"No fixed version available for {pkg_name} {installed_version}"
                ),
            }

            cwe_ids = vuln.get("CweIDs")
            if cwe_ids and isinstance(cwe_ids, list) and len(cwe_ids) > 0:
                props["cwe"] = str(cwe_ids[0])

            result_entry: dict[str, Any] = {
                "ruleId": vuln_id,
                "level": level,
                "message": {"text": msg_text},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": dockerfile_rel},
                            "region": {"startLine": 1},
                        }
                    }
                ],
                "properties": props,
            }
            results.append(result_entry)

            if vuln_id not in rules_map:
                rules_map[vuln_id] = {
                    "id": vuln_id,
                    "name": title or vuln_id,
                    "shortDescription": {"text": description[:300] if description else (title or vuln_id)},
                }

    # Add posture findings
    for pf in posture_findings:
        rule_id = pf.get("ruleId", "DSP-UNKNOWN")
        severity = pf.get("severity", "Medium")
        level = _sarif_level(severity)
        message_text = pf.get("message", f"Posture check {rule_id} failed")
        fix_text = pf.get("fix", None)
        raw_sev = pf.get("raw_severity", severity.upper())
        line = int(pf.get("line", 1)) or 1

        props_p: dict[str, Any] = {
            "severity": severity,
            "category": "container",
            "raw_severity": raw_sev,
            "fix": fix_text,
        }

        result_entry_p: dict[str, Any] = {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": message_text},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": dockerfile_rel},
                        "region": {"startLine": line},
                    }
                }
            ],
            "properties": props_p,
        }
        results.append(result_entry_p)

        if rule_id not in rules_map:
            rules_map[rule_id] = {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": message_text},
            }

    # Sort deterministically
    results.sort(
        key=lambda r: (
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            r["locations"][0]["physicalLocation"].get("region", {}).get("startLine", 0),
            r["ruleId"],
        )
    )

    driver_obj: dict[str, Any] = {
        "name": "trivy",
        "version": tool_version,
        "informationUri": "https://github.com/aquasecurity/trivy",
    }
    if rules_map:
        driver_obj["rules"] = list(rules_map.values())

    sarif_output: dict[str, Any] = {
        "version": "2.1.0",
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
        "runs": [
            {
                "tool": {"driver": driver_obj},
                "results": results,
            }
        ],
    }

    output_sarif_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_sarif_path, "w", encoding="utf-8") as f:
        json.dump(sarif_output, f, indent=2)

    print(
        f"[container/to_sarif] Wrote {len(results)} results to {output_sarif_path}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
