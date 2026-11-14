# Demo Application

This directory contains two versions of a simple Flask "user notes" service used to
demonstrate the DevSecOps pipeline's ability to detect and report security vulnerabilities.

## ⚠️ SECURITY WARNING

> **`demo-app/vulnerable/` contains INTENTIONAL security vulnerabilities.**
>
> - Do **NOT** deploy it to any real environment
> - Do **NOT** use it as a basis for real code
> - Do **NOT** expose it to any network
> - It exists solely to test the pipeline's detection capabilities

## Fake AWS Credentials Notice

`demo-app/vulnerable/config.py` contains a fake AWS access key (`AKIAIOSFODNN7EXAMPLE`)
and secret key. These are:
- **Completely fabricated** — they match the AKIA pattern but are AWS's own example values
- **Non-functional** — they cannot access any AWS account
- **Intentionally planted** to test Gitleaks detection (V1 in the seeded vulnerability list)

### Handling Secret Scanner Warnings

GitHub push protection or other secret scanners may flag these values. To handle this:

1. GitHub push protection: when prompted, click **"It's used in tests"** or select
   **"Allow secret"** with the reason "Test credential - known fake value".
2. If the push is blocked, follow the bypass link GitHub provides and document the bypass
   in `contracts/CHANGELOG.md` as a known test value.
3. Do **not** try to disguise or encode the key — it must remain detectable for testing.

## Dependabot Note

The `demo-app/vulnerable/` folder is intentionally excluded from automated dependency
updates. Its outdated dependencies are deliberate (V3 in the seeded vulnerability list).
Do not add Dependabot configuration that would auto-update them.

## Running the Applications

### Prerequisites

```bash
pip install flask
# For the fixed app only:
pip install flask==3.1.0
```

### Vulnerable App

```bash
cd demo-app/vulnerable
python app.py
# App runs on http://localhost:5000
```

### Fixed App

```bash
cd demo-app/fixed
cp .env.example .env  # then fill in real values
python app.py
# App runs on http://localhost:5000
```

### Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/users?name=<name>` | GET | Search users by name |
| `/login` | POST | Authenticate (JSON body: `username`, `password`) |
| `/register` | POST | Register new user (JSON body: `username`, `password`, `notes`) |

### Docker Build

```bash
# Vulnerable app (intentionally flawed - for testing only)
docker build -t demo-app-vulnerable demo-app/vulnerable/

# Fixed app
docker build -t demo-app-fixed demo-app/fixed/
```

> **Note:** Docker builds were not verified in the Phase 1 CI environment (no Docker daemon
> available). The Dockerfiles are syntactically correct and follow standard Flask patterns.

## Seeded Vulnerabilities

See [seeded-vulnerabilities.md](seeded-vulnerabilities.md) for the full list of planted
flaws and the expected detection tool for each.

## Tests

```bash
# Run functional tests for the vulnerable app
pytest demo-app/vulnerable/tests/ -v

# Run functional tests for the fixed app
pytest demo-app/fixed/tests/ -v

# Run the drift-protection test (checks seeded list matches actual code)
pytest demo-app/tests/test_seeded_list.py -v
```

