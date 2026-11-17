#!/usr/bin/env python3
"""
eval/p3-container/evaluate.py
Evaluate Phase 3 results: IAC, container, SBOM stages.

Usage:
    python3 evaluate.py <iac_vuln_sarif> <iac_fixed_sarif>
                        <container_vuln_sarif> <container_fixed_sarif>
                        <sbom_sarif>
                        <output_json> <output_md>
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def load_sarif(path: str) -> dict[str, Any]:
    p = Path(path)
    if not p.exists():
        return {"runs": [{"results": []}]}
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def get_results(sarif: dict) -> list[dict]:
    results = []
    for run in sarif.get("runs", []):
        results.extend(run.get("results", []))
    return results


def count_by_severity(results: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for r in results:
        sev = r.get("properties", {}).get("severity", "Low")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def main() -> int:
    if len(sys.argv) != 8:
        print(
            f"Usage: {sys.argv[0]} <iac_vuln> <iac_fixed> <cont_vuln> <cont_fixed> <sbom> <out_json> <out_md>",
            file=sys.stderr,
        )
        return 2

    iac_vuln_path, iac_fixed_path = sys.argv[1], sys.argv[2]
    cont_vuln_path, cont_fixed_path = sys.argv[3], sys.argv[4]
    sbom_path = sys.argv[5]
    out_json_path, out_md_path = sys.argv[6], sys.argv[7]

    # Load SARIFs
    iac_vuln  = load_sarif(iac_vuln_path)
    iac_fixed = load_sarif(iac_fixed_path)
    cont_vuln  = load_sarif(cont_vuln_path)
    cont_fixed = load_sarif(cont_fixed_path)
    sbom_sarif = load_sarif(sbom_path)

    iac_vuln_results  = get_results(iac_vuln)
    iac_fixed_results = get_results(iac_fixed)
    cont_vuln_results  = get_results(cont_vuln)
    cont_fixed_results = get_results(cont_fixed)
    sbom_results = get_results(sbom_sarif)

    # Detection analysis — seeded vulnerabilities
    seeded = {
        "V4": {"desc": "Runs as root (no USER)", "rules": ["CKV_DOCKER_3", "CKV_DOCKER_8", "DL3002", "DSP-IMG-001"]},
        "V5": {"desc": "Unpinned base image", "rules": ["CKV_DOCKER_7", "DL3007", "DSP-IMG-002"]},
        "V8": {"desc": "No HEALTHCHECK", "rules": ["CKV_DOCKER_2", "CKV_DOCKER_28", "DL3057"]},
    }

    def detected(results: list[dict], rules: list[str]) -> bool:
        found_ids = {r.get("ruleId", "") for r in results}
        return any(rule in found_ids for rule in rules)

    detection = {}
    for vid, info in seeded.items():
        det_vuln = detected(iac_vuln_results + cont_vuln_results, info["rules"])
        det_fixed = detected(iac_fixed_results + cont_fixed_results, info["rules"])
        detection[vid] = {
            "description": info["desc"],
            "detected_in_vulnerable": det_vuln,
            "detected_in_fixed": det_fixed,
            "correct": det_vuln and not det_fixed,
        }

    # Severity breakdown
    iac_vuln_sev  = count_by_severity(iac_vuln_results)
    iac_fixed_sev = count_by_severity(iac_fixed_results)
    cont_vuln_sev  = count_by_severity(cont_vuln_results)
    cont_fixed_sev = count_by_severity(cont_fixed_results)

    # SBOM info
    sbom_cdx_path = Path(out_json_path).parent / "sbom.cdx.json"
    sbom_component_count = 0
    if sbom_cdx_path.exists():
        try:
            cdx = json.loads(sbom_cdx_path.read_text(encoding="utf-8"))
            sbom_component_count = len(cdx.get("components", []))
        except Exception:
            pass

    # Detection rate
    total_seeded = len(seeded)
    detected_count = sum(1 for v in detection.values() if v["detected_in_vulnerable"])
    detection_rate = detected_count / total_seeded * 100 if total_seeded else 0

    # Build results dict
    results_data: dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "phase": "P3 (Container & IaC)",
        "detection_rate_pct": round(detection_rate, 1),
        "seeded_vulnerabilities": detection,
        "iac_stage": {
            "vulnerable_findings": len(iac_vuln_results),
            "fixed_findings": len(iac_fixed_results),
            "severity_vulnerable": iac_vuln_sev,
            "severity_fixed": iac_fixed_sev,
        },
        "container_stage": {
            "vulnerable_findings": len(cont_vuln_results),
            "fixed_findings": len(cont_fixed_results),
            "severity_vulnerable": cont_vuln_sev,
            "severity_fixed": cont_fixed_sev,
        },
        "sbom_stage": {
            "findings": len(sbom_results),
            "cdx_component_count": sbom_component_count,
        },
    }

    # Write JSON
    Path(out_json_path).write_text(json.dumps(results_data, indent=2), encoding="utf-8")

    # Build Markdown report
    def ck(val: bool) -> str:
        return "✅" if val else "❌"

    md_lines = [
        "# Phase 3 Evaluation Results",
        "",
        f"**Generated:** {results_data['generated_at']}",
        "",
        f"## Detection Rate: {detection_rate:.0f}% ({detected_count}/{total_seeded} seeded vulnerabilities found)",
        "",
        "## Seeded Vulnerability Detection",
        "",
        "| ID | Description | Detected (Vulnerable) | Fixed (Hardened) | Correct |",
        "|----|-------------|----------------------|------------------|---------|",
    ]
    for vid, info in detection.items():
        md_lines.append(
            f"| {vid} | {info['description']} | {ck(info['detected_in_vulnerable'])} | "
            f"{ck(not info['detected_in_fixed'])} | {ck(info['correct'])} |"
        )

    md_lines += [
        "",
        "## IAC Stage Results",
        "",
        f"| Metric | Vulnerable | Fixed |",
        f"|--------|-----------|-------|",
        f"| Total Findings | {len(iac_vuln_results)} | {len(iac_fixed_results)} |",
        f"| Critical | {iac_vuln_sev.get('Critical',0)} | {iac_fixed_sev.get('Critical',0)} |",
        f"| High | {iac_vuln_sev.get('High',0)} | {iac_fixed_sev.get('High',0)} |",
        f"| Medium | {iac_vuln_sev.get('Medium',0)} | {iac_fixed_sev.get('Medium',0)} |",
        f"| Low | {iac_vuln_sev.get('Low',0)} | {iac_fixed_sev.get('Low',0)} |",
        "",
        "## Container Stage Results",
        "",
        f"| Metric | Vulnerable | Fixed |",
        f"|--------|-----------|-------|",
        f"| Total Findings | {len(cont_vuln_results)} | {len(cont_fixed_results)} |",
        f"| Critical | {cont_vuln_sev.get('Critical',0)} | {cont_fixed_sev.get('Critical',0)} |",
        f"| High | {cont_vuln_sev.get('High',0)} | {cont_fixed_sev.get('High',0)} |",
        f"| Medium | {cont_vuln_sev.get('Medium',0)} | {cont_fixed_sev.get('Medium',0)} |",
        f"| Low | {cont_vuln_sev.get('Low',0)} | {cont_fixed_sev.get('Low',0)} |",
        "",
        "## SBOM Stage Results",
        "",
        f"- SARIF findings: {len(sbom_results)} (inventory tool — zero is correct)",
        f"- CycloneDX components: {sbom_component_count}",
        "",
        "## Notes",
        "",
        "> [!NOTE] V5 (unpinned base `python:3.11-slim`) is not detected by DSP-IMG-002 because",
        "> the image has a named tag (not `:latest`). DL3007 (Hadolint) also does not fire for named",
        "> tags. Checkov CKV_DOCKER_7 may detect this depending on version.",
        "> In CI where Docker image scanning runs in image mode, Trivy would surface OS-level CVEs",
        "> from the actual unpinned base image.",
        "",
        "> [!NOTE] Container stage ran in **filesystem fallback mode** (no Docker available locally).",
        "> CVEs shown are from application dependencies (`requirements.txt`), not OS-layer CVEs.",
        "> In CI with `IMAGE_REF` set, OS-layer vulnerabilities would also be reported.",
    ]

    Path(out_md_path).write_text("\n".join(md_lines), encoding="utf-8")

    print(f"[eval] Detection rate: {detection_rate:.0f}%", file=sys.stderr)
    for vid, info in detection.items():
        status = "DETECTED" if info["detected_in_vulnerable"] else "MISSED"
        print(f"  {vid}: {status} - {info['description']}", file=sys.stderr)
    print(f"[eval] IAC:       {len(iac_vuln_results)} findings (vuln) / {len(iac_fixed_results)} (fixed)", file=sys.stderr)
    print(f"[eval] Container: {len(cont_vuln_results)} findings (vuln) / {len(cont_fixed_results)} (fixed)", file=sys.stderr)
    print(f"[eval] SBOM:      {sbom_component_count} components", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
