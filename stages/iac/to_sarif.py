#!/usr/bin/env python3
"""
stages/iac/to_sarif.py
Convert Hadolint JSON + Checkov JSON output to SARIF 2.1.0 conforming to contracts/sarif-profile.md.

Usage:
    python3 to_sarif.py <hadolint_json> <checkov_json> <target_rel> <repo_root> <tool_versions> <output_sarif>

tool_versions: "hadolint X.Y.Z; checkov A.B.C"
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Severity mappings per contracts/severity-map.md
# ---------------------------------------------------------------------------
HADOLINT_SEVERITY_MAP: dict[str, tuple[str, str]] = {
    "error":   ("High",   "error"),
    "warning": ("Medium", "warning"),
    "info":    ("Low",    "note"),
    "style":   ("Low",    "note"),
}

CHECKOV_SEVERITY_MAP: dict[str, tuple[str, str]] = {
    "CRITICAL": ("Critical", "error"),
    "HIGH":     ("High",     "error"),
    "MEDIUM":   ("Medium",   "warning"),
    "LOW":      ("Low",      "note"),
}

# ---------------------------------------------------------------------------
# Fix text table for common rules
# ---------------------------------------------------------------------------
FIX_TABLE: dict[str, str] = {
    # Hadolint rules
    "DL3002": "Add a non-root USER instruction before CMD: 'RUN useradd -m appuser && USER appuser'",
    "DL3003": "Use WORKDIR instead of 'cd' and 'RUN cd'",
    "DL3006": "Always tag the version of an image explicitly",
    "DL3007": "Pin the base image tag to a specific version e.g. 'python:3.11.11-slim-bookworm'",
    "DL3008": "Pin apt-get package versions: e.g. 'apt-get install -y curl=7.x.x'",
    "DL3009": "Delete the apt-get lists after installing packages",
    "DL3010": "Use ADD for extracting archives; use COPY for plain files",
    "DL3013": "Pin pip install versions: e.g. 'pip install flask==2.x.x'",
    "DL3014": "Use the -y switch with apt-get: 'apt-get install -y ...'",
    "DL3015": "Avoid additional packages by specifying --no-install-recommends",
    "DL3016": "Pin npm package versions",
    "DL3017": "Do not use apk upgrade",
    "DL3018": "Pin apk package versions",
    "DL3020": "Use COPY instead of ADD for files and folders",
    "DL3025": "Use arguments JSON notation for CMD and ENTRYPOINT",
    "DL3026": "Use only an allowed registry in the FROM image",
    "DL3027": "Do not use apt as it is meant to be an end-user tool",
    "DL3028": "Pin gem install versions",
    "DL3029": "Do not use --platform flag with FROM",
    "DL3030": "Use the -y switch with yum install",
    "DL3032": "yum clean all missing after yum command",
    "DL3033": "Pin yum package versions",
    "DL3034": "Non-interactive switch missing from zypper command",
    "DL3035": "Do not use zypper dist-upgrade",
    "DL3036": "Pin zypper install versions",
    "DL3037": "Specify version flag for pip3",
    "DL3038": "Use the -y switch with dnf install",
    "DL3040": "dnf clean all missing after dnf command",
    "DL3041": "Pin dnf package versions",
    "DL3042": "Avoid use of cache directory with pip",
    "DL3043": "ONBUILD, FROM or MAINTAINER triggered from ONBUILD instruction",
    "DL3044": "Do not refer to an environment variable within the same ENV statement",
    "DL3045": "COPY to a relative destination without WORKDIR set",
    "DL3046": "useradd without flag -l and high UID will fill up the lastlog and faillog files",
    "DL3047": "wget without certificate validation",
    "DL3048": "Invalid label key",
    "DL3049": "Label schema requires a specific format",
    "DL3050": "Superfluous label(s) present",
    "DL3051": "Label value is empty",
    "DL3052": "Label is not a valid URL",
    "DL3053": "Label is not a valid SPDX license identifier",
    "DL3054": "Label is not a valid git hash",
    "DL3055": "Label is not a valid git ref",
    "DL3056": "Label is not a valid RFC3339 date",
    "DL3057": "HEALTHCHECK instruction missing",
    "DL3058": "Label is not a valid email format",
    "DL3059": "Multiple consecutive RUN instructions - consider merging into a single RUN",
    "DL3060": "yarn cache clean missing after yarn install",
    "DL3061": "Invalid instruction order - FROM must be the first instruction",
    "DL4000": "MAINTAINER is deprecated",
    "DL4001": "Either use Wget or Curl but not both",
    "DL4003": "Multiple CMD instructions found",
    "DL4004": "Multiple ENTRYPOINT instructions found",
    "DL4005": "Use SHELL to change the default shell",
    "DL4006": "Set the SHELL option -o pipefail before RUN with a pipe",
    # Checkov rules
    "CKV_DOCKER_1":  "Ensure port 22 is not exposed",
    "CKV_DOCKER_2":  "Ensure that HEALTHCHECK instructions have been added to the container image",
    "CKV_DOCKER_3":  "Ensure that a user for the container has been created",
    "CKV_DOCKER_4":  "Ensure that COPY is used instead of ADD in Dockerfiles",
    "CKV_DOCKER_5":  "Ensure update instructions are not used alone in the Dockerfile",
    "CKV_DOCKER_6":  "Ensure that LABEL instructions are used in Dockerfiles",
    "CKV_DOCKER_7":  "Ensure the base image uses a non-latest version tag",
    "CKV_DOCKER_8":  "Ensure the last USER is not root",
    "CKV_DOCKER_9":  "Ensure that Apt commands do not use untrusted packages",
    "CKV_DOCKER_10": "Ensure secrets are not stored in Dockerfiles",
    "CKV_DOCKER_11": "Ensure From alias are unique for multistage builds",
    "CKV_DOCKER_12": "Ensure that you do not run commands with the sudo command in the Dockerfile",
    "CKV_DOCKER_13": "Ensure that the Dockerfile's base image is locked to a specific version and not 'latest'",
    "CKV_DOCKER_14": "Ensure that the base image is not deprecated",
    "CKV_DOCKER_17": "Ensure ADD is not used in the Dockerfile",
    "CKV_DOCKER_18": "Ensure that run commands are not run as root",
    "CKV_DOCKER_20": "Ensure that the base image uses a digest",
    "CKV_DOCKER_21": "Ensure that labels are used for identifying the base image",
    "CKV_DOCKER_22": "Ensure the last USER is not root (non-root is better practice)",
    "CKV_DOCKER_23": "Ensure that apt-get is used instead of apt",
    "CKV_DOCKER_24": "Ensure that the Docker socket is not mounted",
    "CKV_DOCKER_25": "Ensure that only trusted base images are used",
    "CKV_DOCKER_26": "Ensure that there is at most one ENV instruction",
    "CKV_DOCKER_27": "Ensure WORKDIR is set",
    "CKV_DOCKER_28": "Add a HEALTHCHECK instruction to verify the container is running correctly",
    "CKV_DOCKER_29": "Ensure only one process is running per container",
    "CKV_DOCKER_30": "Ensure that sensitive data is not stored in the Dockerfile",
    "CKV_DOCKER_31": "Ensure that docker socket is not mounted in the dockerfile",
}


def _hadolint_severity(level: str) -> tuple[str, str]:
    """Return (canonical_severity, sarif_level) for a Hadolint level."""
    return HADOLINT_SEVERITY_MAP.get(level.lower(), ("Low", "note"))


def _checkov_severity(sev: str | None) -> tuple[str, str]:
    """Return (canonical_severity, sarif_level) for a Checkov severity."""
    if sev is None:
        return ("Medium", "warning")  # fallback per severity-map.md
    return CHECKOV_SEVERITY_MAP.get(str(sev).upper(), ("Medium", "warning"))


def _normalize_uri(path: str) -> str:
    """Normalize a file path to a repo-relative forward-slash URI."""
    return path.replace("\\", "/").lstrip("/")


def _fix_for_rule(rule_id: str) -> str:
    """Return curated fix advice for rule_id, or a URL-based fallback."""
    if rule_id in FIX_TABLE:
        return FIX_TABLE[rule_id]
    if rule_id.startswith("DL"):
        return f"See https://github.com/hadolint/hadolint/wiki/{rule_id}"
    if rule_id.startswith("CKV"):
        return f"See https://docs.bridgecrew.io/docs/{rule_id.lower().replace('_', '-')}"
    return f"Review rule {rule_id} documentation"


def _parse_hadolint(hadolint_data: list[dict], target_rel: str) -> tuple[list[dict], dict]:
    """Parse Hadolint JSON array into SARIF results and rules_map."""
    results: list[dict[str, Any]] = []
    rules_map: dict[str, dict[str, Any]] = {}

    for item in hadolint_data:
        rule_id = item.get("code", "")
        if not rule_id:
            continue

        raw_level = item.get("level", "warning")
        severity, sarif_level = _hadolint_severity(raw_level)

        # Build URI: Hadolint reports the filename; combine with target_rel
        file_name = item.get("file", "Dockerfile")
        # Normalize file path
        file_norm = file_name.replace("\\", "/")
        # If file_norm is absolute or contains the full path, extract relative part
        # Try to make it relative to target_rel
        t_rel = target_rel.replace("\\", "/").strip("/")
        if file_norm.startswith("/"):
            # absolute path - try to strip repo root prefix
            if t_rel and t_rel in file_norm:
                # Find where target_rel appears and take from there
                idx = file_norm.find(t_rel)
                uri = file_norm[idx:]
            else:
                # just use the basename
                uri = "Dockerfile" if not t_rel else f"{t_rel}/Dockerfile"
        else:
            if t_rel and not file_norm.startswith(t_rel):
                uri = f"{t_rel}/{file_norm}" if file_norm else t_rel
            else:
                uri = file_norm if file_norm else (t_rel or "Dockerfile")

        # Normalize slashes
        uri = uri.replace("\\", "/")

        line = item.get("line", 1) or 1
        col = item.get("column", 1) or 1

        message_text = item.get("message", f"Hadolint rule {rule_id}")
        fix_text = _fix_for_rule(rule_id)

        props: dict[str, Any] = {
            "severity": severity,
            "category": "iac",
            "raw_severity": raw_level,
            "fix": fix_text,
        }

        result_entry: dict[str, Any] = {
            "ruleId": rule_id,
            "level": sarif_level,
            "message": {"text": f"[Hadolint {rule_id}] {message_text}"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri},
                        "region": {"startLine": line, "startColumn": col},
                    }
                }
            ],
            "properties": props,
        }
        results.append(result_entry)

        if rule_id not in rules_map:
            rules_map[rule_id] = {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": message_text},
                "helpUri": (
                    f"https://github.com/hadolint/hadolint/wiki/{rule_id}"
                    if rule_id.startswith("DL") or rule_id.startswith("SC")
                    else f"https://docs.bridgecrew.io/docs/{rule_id.lower().replace('_', '-')}"
                ),
            }

    return results, rules_map


def _parse_checkov(checkov_data: dict | list, target_rel: str) -> tuple[list[dict], dict]:
    """Parse Checkov JSON output into SARIF results and rules_map."""
    results: list[dict[str, Any]] = []
    rules_map: dict[str, dict[str, Any]] = {}

    # Checkov can output a single check result dict or a list of them
    # With --check and single Dockerfile it outputs a dict with 'results' key
    # or a list of result dicts when multiple files
    checks: list[dict] = []

    def _extract_checks(data: Any) -> None:
        if isinstance(data, list):
            for item in data:
                _extract_checks(item)
        elif isinstance(data, dict):
            # Might be a top-level result object with 'results' or 'failed_checks'
            if "results" in data:
                r = data["results"]
                if "failed_checks" in r:
                    for c in r["failed_checks"]:
                        checks.append(c)
                if "passed_checks" in r:
                    pass  # we only care about failed
            elif "failed_checks" in data:
                for c in data["failed_checks"]:
                    checks.append(c)
            elif "check_id" in data:
                # It's already a single check result
                checks.append(data)

    _extract_checks(checkov_data)

    t_rel = target_rel.replace("\\", "/").strip("/")

    for check in checks:
        rule_id = check.get("check_id", "")
        check_name = check.get("check", {})
        if isinstance(check_name, dict):
            check_name_str = check_name.get("name", rule_id)
        else:
            check_name_str = str(check_name) if check_name else rule_id

        # Checkov severity
        raw_sev = check.get("severity") or check.get("check", {}).get("severity") if isinstance(check.get("check"), dict) else None
        severity, sarif_level = _checkov_severity(raw_sev)

        # File path
        file_abs = check.get("repo_file_path") or check.get("file_path") or ""
        file_norm = file_abs.replace("\\", "/").lstrip("/")
        # Try to build repo-relative URI
        if t_rel and t_rel in file_norm:
            idx = file_norm.find(t_rel)
            uri = file_norm[idx:]
        elif file_norm:
            # It might be an absolute Linux path or a relative path
            # Strip leading slash if any
            if "/" in file_norm:
                # Use the last meaningful part
                parts = [p for p in file_norm.split("/") if p]
                # Look for target_rel tail
                if t_rel:
                    t_parts = [p for p in t_rel.split("/") if p]
                    # Try to find t_parts sequence in parts
                    for i in range(len(parts)):
                        if parts[i:i+len(t_parts)] == t_parts:
                            uri = "/".join(parts[i:])
                            break
                    else:
                        uri = f"{t_rel}/{'/'.join(parts[-1:])}" if t_rel else "/".join(parts[-2:])
                else:
                    uri = "/".join(parts[-2:]) if len(parts) >= 2 else file_norm
            else:
                uri = f"{t_rel}/{file_norm}" if t_rel else file_norm
        else:
            uri = f"{t_rel}/Dockerfile" if t_rel else "Dockerfile"

        uri = uri.replace("\\", "/")

        # Line numbers
        file_line_range = check.get("file_line_range") or []
        if isinstance(file_line_range, list) and len(file_line_range) >= 1:
            start_line = int(file_line_range[0]) or 1
        else:
            start_line = 1

        fix_text = _fix_for_rule(rule_id)
        message_text = f"[Checkov {rule_id}] {check_name_str}"

        props: dict[str, Any] = {
            "severity": severity,
            "category": "iac",
            "raw_severity": str(raw_sev) if raw_sev else "MEDIUM",
            "fix": fix_text,
        }

        result_entry: dict[str, Any] = {
            "ruleId": rule_id,
            "level": sarif_level,
            "message": {"text": message_text},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri},
                        "region": {"startLine": start_line},
                    }
                }
            ],
            "properties": props,
        }
        results.append(result_entry)

        if rule_id not in rules_map:
            rules_map[rule_id] = {
                "id": rule_id,
                "name": check_name_str,
                "shortDescription": {"text": check_name_str},
                "helpUri": f"https://docs.bridgecrew.io/docs/{rule_id.lower().replace('_', '-')}",
            }

    return results, rules_map


def main() -> int:
    if len(sys.argv) != 7:
        print(
            f"Usage: {sys.argv[0]} <hadolint_json> <checkov_json> <target_rel> <repo_root> <tool_versions> <output_sarif>",
            file=sys.stderr,
        )
        return 2

    hadolint_json_path = Path(sys.argv[1])
    checkov_json_path = Path(sys.argv[2])
    target_rel = sys.argv[3]
    _repo_root = Path(sys.argv[4]).resolve()
    tool_versions = sys.argv[5]  # "hadolint X.Y.Z; checkov A.B.C"
    output_sarif_path = Path(sys.argv[6])

    # Load Hadolint JSON
    if not hadolint_json_path.is_file():
        print(f"ERROR: Hadolint JSON not found: {hadolint_json_path}", file=sys.stderr)
        return 1
    try:
        with open(hadolint_json_path, "r", encoding="utf-8") as f:
            hadolint_data = json.load(f)
    except Exception as e:
        print(f"ERROR: Failed to parse Hadolint JSON: {e}", file=sys.stderr)
        return 1

    if not isinstance(hadolint_data, list):
        print("ERROR: Hadolint JSON must be a list", file=sys.stderr)
        return 1

    # Load Checkov JSON
    if not checkov_json_path.is_file():
        print(f"ERROR: Checkov JSON not found: {checkov_json_path}", file=sys.stderr)
        return 1
    try:
        with open(checkov_json_path, "r", encoding="utf-8") as f:
            checkov_data = json.load(f)
    except Exception as e:
        print(f"ERROR: Failed to parse Checkov JSON: {e}", file=sys.stderr)
        return 1

    # Parse both
    h_results, h_rules = _parse_hadolint(hadolint_data, target_rel)
    c_results, c_rules = _parse_checkov(checkov_data, target_rel)

    # Merge
    all_results = h_results + c_results
    all_rules = {**h_rules, **c_rules}

    # Sort deterministically: (uri, startLine, ruleId)
    all_results.sort(
        key=lambda r: (
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            r["locations"][0]["physicalLocation"].get("region", {}).get("startLine", 0),
            r["ruleId"],
        )
    )

    # Build driver — combined name per contracts/p3-contract-feedback.md decision
    driver_obj: dict[str, Any] = {
        "name": "hadolint+checkov",
        "version": tool_versions,
        "informationUri": "https://github.com/hadolint/hadolint",
    }
    if all_rules:
        driver_obj["rules"] = list(all_rules.values())

    sarif_output: dict[str, Any] = {
        "version": "2.1.0",
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
        "runs": [
            {
                "tool": {"driver": driver_obj},
                "results": all_results,
            }
        ],
    }

    output_sarif_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_sarif_path, "w", encoding="utf-8") as f:
        json.dump(sarif_output, f, indent=2)

    print(
        f"[iac/to_sarif] Wrote {len(all_results)} results "
        f"({len(h_results)} hadolint + {len(c_results)} checkov) to {output_sarif_path}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
