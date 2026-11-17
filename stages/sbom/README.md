# SBOM Stage — Syft

**Owner:** P3 | **Phase:** 3

Generates a Software Bill of Materials (SBOM) using Syft and emits a zero-result SARIF.

## Interface

```bash
stages/sbom/run.sh <target_path> <output_dir>
```

Optionally set `IMAGE_REF` to scan a container image instead of the directory.

## Outputs

| File | Description |
|------|-------------|
| `<output_dir>/sbom.sarif` | Zero-result SARIF 2.1.0 (Syft is inventory-only) |
| `<output_dir>/artifacts/sbom/sbom.cdx.json` | CycloneDX 1.6 SBOM |
| `<output_dir>/artifacts/sbom/sbom-summary.json` | Summary with package count |

## Tool Version

| Tool | Version | Cache |
|------|---------|-------|
| Syft | 1.18.1 | `~/.cache/devsecops/syft-1.18.1/syft` |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Scanner crash / install failure |
| 2 | Usage error |

## Notes

Per `contracts/severity-map.md §3.7`, Syft is an inventory tool and emits no
findings. The SARIF `results` array is always empty. The gate ignores this stage
for policy decisions but uses the CycloneDX artifact for downstream processing (P4).
