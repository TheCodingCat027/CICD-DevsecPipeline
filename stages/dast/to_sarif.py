#!/usr/bin/env python3
"""
stages/dast/to_sarif.py
Convert OWASP ZAP JSON report to SARIF 2.1.0.

Usage:
    python3 to_sarif.py <zap_json> <target_path> <repo_root> <zap_image> <output_sarif>
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ZAP_SEVERITY_MAP: dict[str, str] = {
    "High": "High",
    "Medium": "Medium",
    "Low": "Low",
    "Informational": "Low",
}


def _sarif_level(severity: str) -> str:
    if severity in ("Critical", "High"):
        return "error"
    if severity == "Medium":
        return "warning"
    return "note"


def main() -> int:
    if len(sys.argv) != 6:
        print(
            f"Usage: {sys.argv[0]} <zap_json> <target_path> <repo_root> <zap_image> <output_sarif>",
            file=sys.stderr,
        )
        return 2

    zap_json_path = Path(sys.argv[1])
    target_path = sys.argv[2]
    repo_root = Path(sys.argv[3]).resolve()
    zap_image = sys.argv[4]
    output_sarif_path = Path(sys.argv[5])

    if not zap_json_path.is_file():
        print(f"ERROR: ZAP JSON not found: {zap_json_path}", file=sys.stderr)
        return 1

    try:
        with open(zap_json_path, "r", encoding="utf-8") as f:
            zap_data = json.load(f)
    except Exception as e:
        print(f"ERROR: Failed to parse ZAP JSON: {e}", file=sys.stderr)
        return 1

    # Compute tool version from image tag
    tool_version = zap_image.split(":")[-1] if ":" in zap_image else "latest"

    results: list[dict[str, Any]] = []
    rules_map: dict[str, dict[str, Any]] = {}

    # ZAP JSON structure: {"site": [{"alerts": [...]}]}
    sites = zap_data.get("site") or []
    for site in sites:
        alerts = site.get("alerts") or []
        for alert in alerts:
            rule_id = alert.get("pluginid", "ZAP-UNKNOWN")
            name = alert.get("name", rule_id)
            risk_code = alert.get("riskcode", "1")
            risk_desc = alert.get("riskdesc", "Low")
            # Extract risk level word
            risk_level = risk_desc.split(" ")[0] if risk_desc else "Low"
            severity = ZAP_SEVERITY_MAP.get(risk_level, "Low")
            level = _sarif_level(severity)
            description = alert.get("desc", name)
            solution = alert.get("solution", "")
            instances = alert.get("instances") or [{}]
            reference = alert.get("reference", "")

            for instance in instances:
                uri_raw = instance.get("uri", target_path)
                # Try to make it repo-relative
                uri = str(uri_raw)

                props: dict[str, Any] = {
                    "severity": severity,
                    "category": "dast",
                    "raw_severity": risk_level,
                    "fix": solution[:500] if solution else None,
                }

                result_entry: dict[str, Any] = {
                    "ruleId": f"ZAP-{rule_id}",
                    "level": level,
                    "message": {"text": f"{name}: {description[:300]}"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": uri},
                                "region": {"startLine": 1},
                            }
                        }
                    ],
                    "properties": props,
                }
                results.append(result_entry)

            rule_key = f"ZAP-{rule_id}"
            if rule_key not in rules_map:
                rules_map[rule_key] = {
                    "id": rule_key,
                    "name": name,
                    "shortDescription": {"text": description[:300]},
                    "helpUri": reference[:200] if reference else f"https://www.zaproxy.org/docs/alerts/{rule_id}/",
                }

    results.sort(
        key=lambda r: (
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            r["ruleId"],
        )
    )

    driver_obj: dict[str, Any] = {
        "name": "zap",
        "version": tool_version,
        "informationUri": "https://www.zaproxy.org",
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

    print(f"[dast/to_sarif] Wrote {len(results)} results to {output_sarif_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
