#!/usr/bin/env python3
"""
stages/sbom/to_sarif.py
Generate a zero-result SARIF 2.1.0 for the SBOM stage.

Usage:
    python3 to_sarif.py <tool_version> <output_sarif>

The SBOM stage uses Syft which is an inventory tool only - it emits no findings.
Per contracts/severity-map.md §3.7, Syft SARIF has an empty results array.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


def main() -> int:
    if len(sys.argv) != 3:
        print(
            f"Usage: {sys.argv[0]} <tool_version> <output_sarif>",
            file=sys.stderr,
        )
        return 2

    tool_version = sys.argv[1]
    output_sarif_path = Path(sys.argv[2])

    sarif_output: dict[str, Any] = {
        "version": "2.1.0",
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "syft",
                        "version": tool_version,
                        "informationUri": "https://github.com/anchore/syft",
                    }
                },
                "results": [],
            }
        ],
    }

    output_sarif_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_sarif_path, "w", encoding="utf-8") as f:
        json.dump(sarif_output, f, indent=2)

    print(f"[sbom/to_sarif] Wrote zero-result SARIF to {output_sarif_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
