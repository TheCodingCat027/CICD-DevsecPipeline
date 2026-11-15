#!/usr/bin/env python3
"""Quick validation test for all three stage to_sarif.py scripts."""
import json, tempfile, os, subprocess, sys

repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
python = sys.executable
validate = os.path.join(repo_root, "contracts", "validate.py")

PASS = 0
FAIL = 0

def check(label, cond, msg=""):
    global PASS, FAIL
    if cond:
        print(f"  PASS: {label}")
        PASS += 1
    else:
        print(f"  FAIL: {label} {msg}")
        FAIL += 1

# ── Test secrets/to_sarif.py ─────────────────────────────────────────────────
print("\n=== secrets/to_sarif.py ===")
sample_secrets = [
    {"RuleID": "aws-access-token", "Description": "AWS Access Key", "File": "demo-app/vulnerable/config.py",
     "StartLine": 10, "Secret": "FAKESECRET123", "Match": "FAKEMATCH", "Commit": "", "Author": ""}
]
with tempfile.TemporaryDirectory() as tmp:
    inp = os.path.join(tmp, "findings.json")
    out = os.path.join(tmp, "secrets.sarif")
    with open(inp, "w") as f:
        json.dump(sample_secrets, f)
    r = subprocess.run([python, "stages/secrets/to_sarif.py", inp, "demo-app/vulnerable", repo_root, "8.21.2", out],
                       capture_output=True, text=True, cwd=repo_root)
    check("exit 0", r.returncode == 0, r.stderr[:200])
    if r.returncode == 0:
        sarif = json.load(open(out))
        sarif_text = open(out).read()
        res = sarif["runs"][0]["results"][0]
        check("no secret leaked", "FAKESECRET123" not in sarif_text)
        check("severity=Critical for aws-access-token", res["properties"]["severity"] == "Critical")
        check("category=secret", res["properties"]["category"] == "secret")
        check("uri is repo-relative", res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "demo-app/vulnerable/config.py")
        # validate
        v = subprocess.run([python, validate, out, "--stage", "secrets"], capture_output=True, text=True, cwd=repo_root)
        check("passes validate.py", v.returncode == 0, v.stdout + v.stderr)

# test empty input
with tempfile.TemporaryDirectory() as tmp:
    inp = os.path.join(tmp, "empty.json")
    out = os.path.join(tmp, "secrets.sarif")
    with open(inp, "w") as f:
        json.dump([], f)
    r = subprocess.run([python, "stages/secrets/to_sarif.py", inp, "demo-app/vulnerable", repo_root, "8.21.2", out],
                       capture_output=True, text=True, cwd=repo_root)
    if r.returncode == 0:
        sarif = json.load(open(out))
        check("empty findings = 0 results", len(sarif["runs"][0]["results"]) == 0)
        v = subprocess.run([python, validate, out, "--stage", "secrets"], capture_output=True, text=True, cwd=repo_root)
        check("empty SARIF passes validate.py", v.returncode == 0, v.stdout + v.stderr)

# ── Test sast/to_sarif.py ─────────────────────────────────────────────────────
print("\n=== sast/to_sarif.py ===")
sample_sast = {
    "results": [
        {"check_id": "p2-sql-injection-string-concat",
         "path": "demo-app/vulnerable/app.py",
         "start": {"line": 51}, "end": {"line": 51},
         "extra": {"message": "SQL injection via string concat", "severity": "ERROR",
                   "metadata": {"cwe": "CWE-89", "confidence": "high",
                                "remediation": "Use parameterized queries"}}}
    ],
    "errors": []
}
with tempfile.TemporaryDirectory() as tmp:
    inp = os.path.join(tmp, "semgrep.json")
    out = os.path.join(tmp, "sast.sarif")
    with open(inp, "w") as f:
        json.dump(sample_sast, f)
    r = subprocess.run([python, "stages/sast/to_sarif.py", inp, "demo-app/vulnerable", repo_root, "1.100.0", out],
                       capture_output=True, text=True, cwd=repo_root)
    check("exit 0", r.returncode == 0, r.stderr[:200])
    if r.returncode == 0:
        sarif = json.load(open(out))
        res = sarif["runs"][0]["results"][0]
        check("severity=High for ERROR", res["properties"]["severity"] == "High")
        check("category=sast", res["properties"]["category"] == "sast")
        check("cwe populated", res["properties"].get("cwe") == "CWE-89")
        check("fix populated", res["properties"].get("fix") is not None)
        check("uri correct", "app.py" in res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"])
        v = subprocess.run([python, validate, out, "--stage", "sast"], capture_output=True, text=True, cwd=repo_root)
        check("passes validate.py", v.returncode == 0, v.stdout + v.stderr)

# ── Test sca/to_sarif.py ─────────────────────────────────────────────────────
print("\n=== sca/to_sarif.py ===")
sample_sca = {
    "SchemaVersion": 2,
    "Results": [
        {"Target": "requirements.txt", "Class": "lang-pkgs", "Type": "pip",
         "Vulnerabilities": [
             {"VulnerabilityID": "CVE-2019-10906", "PkgName": "Jinja2",
              "InstalledVersion": "2.10", "FixedVersion": "2.10.1",
              "Severity": "HIGH", "Title": "SSTI in Jinja2",
              "Description": "Server-side template injection in Jinja2.",
              "PrimaryURL": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-10906",
              "CweIDs": ["CWE-94"]}
         ]}
    ]
}
with tempfile.TemporaryDirectory() as tmp:
    inp = os.path.join(tmp, "trivy.json")
    out = os.path.join(tmp, "sca.sarif")
    with open(inp, "w") as f:
        json.dump(sample_sca, f)
    r = subprocess.run([python, "stages/sca/to_sarif.py", inp, "demo-app/vulnerable", repo_root, "0.58.1", out],
                       capture_output=True, text=True, cwd=repo_root)
    check("exit 0", r.returncode == 0, r.stderr[:200])
    if r.returncode == 0:
        sarif = json.load(open(out))
        res = sarif["runs"][0]["results"][0]
        check("ruleId=CVE", res["ruleId"] == "CVE-2019-10906")
        check("severity=High for HIGH", res["properties"]["severity"] == "High")
        check("category=sca", res["properties"]["category"] == "sca")
        check("package populated", res["properties"].get("package") == "Jinja2")
        check("fix_available=True", res["properties"].get("fix_available") is True)
        check("uri has requirements.txt", "requirements.txt" in res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"])
        v = subprocess.run([python, validate, out, "--stage", "sca"], capture_output=True, text=True, cwd=repo_root)
        check("passes validate.py", v.returncode == 0, v.stdout + v.stderr)

print(f"\n{'='*40}")
print(f"Results: {PASS} PASS, {FAIL} FAIL")
sys.exit(0 if FAIL == 0 else 1)
